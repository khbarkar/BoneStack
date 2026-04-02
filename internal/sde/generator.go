package sde

import (
	"fmt"
	"sort"
	"strings"

	"github.com/docker/docker/api/types"
)

// ProjectProfile captures a best-effort application/runtime profile.
type ProjectProfile struct {
	BaseImage     string
	Runtime       string
	Workdir       string
	ExposedPorts  []string
	HasEntrypoint bool
}

// Scaffold contains generated SDE output.
type Scaffold struct {
	Profile        ProjectProfile
	Dockerfile     string
	PolicyChecklist []string
}

// Generator produces starter Dockerfiles and policy scaffolding.
type Generator struct{}

// NewGenerator creates a new scaffold generator.
func NewGenerator() *Generator {
	return &Generator{}
}

// InferProfile derives a simple runtime profile from image metadata.
func (g *Generator) InferProfile(imageName string, inspect types.ImageInspect) ProjectProfile {
	profile := ProjectProfile{
		BaseImage: imageName,
		Runtime:   inferRuntime(imageName, inspect),
		Workdir:   firstWorkdir(inspect),
	}

	for port := range inspect.Config.ExposedPorts {
		profile.ExposedPorts = append(profile.ExposedPorts, string(port))
	}
	sort.Strings(profile.ExposedPorts)
	profile.HasEntrypoint = len(inspect.Config.Entrypoint) > 0 || len(inspect.Config.Cmd) > 0
	return profile
}

// Generate builds a starter scaffold from image metadata.
func (g *Generator) Generate(imageName string, inspect types.ImageInspect) Scaffold {
	profile := g.InferProfile(imageName, inspect)
	return Scaffold{
		Profile:        profile,
		Dockerfile:     renderDockerfile(profile, inspect),
		PolicyChecklist: buildPolicyChecklist(profile),
	}
}

func inferRuntime(imageName string, inspect types.ImageInspect) string {
	candidates := []string{
		imageName,
		strings.Join(inspect.Config.Entrypoint, " "),
		strings.Join(inspect.Config.Cmd, " "),
	}
	joined := strings.ToLower(strings.Join(candidates, " "))

	switch {
	case strings.Contains(joined, "node"):
		return "node"
	case strings.Contains(joined, "python") || strings.Contains(joined, "pip"):
		return "python"
	case strings.Contains(joined, "java") || strings.Contains(joined, "jar"):
		return "java"
	case strings.Contains(joined, "nginx"):
		return "nginx"
	case strings.Contains(joined, "go"):
		return "go"
	default:
		return "generic"
	}
}

func firstWorkdir(inspect types.ImageInspect) string {
	if inspect.Config.WorkingDir != "" {
		return inspect.Config.WorkingDir
	}
	return "/app"
}

func renderDockerfile(profile ProjectProfile, inspect types.ImageInspect) string {
	switch profile.Runtime {
	case "node":
		return fmt.Sprintf(`FROM node:20-alpine AS build
WORKDIR %s
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine
WORKDIR %s
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build %s ./
USER node
%s
CMD ["npm", "start"]`, profile.Workdir, profile.Workdir, profile.Workdir, renderExposeLines(profile.ExposedPorts))
	case "python":
		return fmt.Sprintf(`FROM python:3.12-slim
WORKDIR %s
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
COPY requirements*.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -r -u 10001 appuser && chown -R appuser:appuser %s
USER appuser
%s
CMD ["python", "app.py"]`, profile.Workdir, profile.Workdir, renderExposeLines(profile.ExposedPorts))
	case "java":
		return fmt.Sprintf(`FROM eclipse-temurin:21-jdk AS build
WORKDIR %s
COPY . .
RUN ./mvnw -q -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR %s
COPY --from=build %s/target/*.jar app.jar
RUN useradd -r -u 10001 appuser && chown appuser:appuser app.jar
USER appuser
%s
CMD ["java", "-jar", "app.jar"]`, profile.Workdir, profile.Workdir, profile.Workdir, renderExposeLines(profile.ExposedPorts))
	case "nginx":
		return fmt.Sprintf(`FROM nginx:stable-alpine
WORKDIR %s
COPY . /usr/share/nginx/html
%s
CMD ["nginx", "-g", "daemon off;"]`, profile.Workdir, renderExposeLines(profile.ExposedPorts))
	case "go":
		return fmt.Sprintf(`FROM golang:1.25 AS build
WORKDIR %s
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o app ./...

FROM gcr.io/distroless/static-debian12
WORKDIR %s
COPY --from=build %s/app ./app
USER nonroot:nonroot
%s
ENTRYPOINT ["./app"]`, profile.Workdir, profile.Workdir, profile.Workdir, renderExposeLines(profile.ExposedPorts))
	default:
		return fmt.Sprintf(`FROM %s
WORKDIR %s
COPY . .
%s
CMD ["sh"]`, fallbackBase(profile.BaseImage), profile.Workdir, renderExposeLines(profile.ExposedPorts))
	}
}

func buildPolicyChecklist(profile ProjectProfile) []string {
	items := []string{
		"Pin the base image to a specific version or digest",
		"Use a non-root user in the final stage",
		"Keep secrets out of the Dockerfile and build args",
		"Add a .dockerignore to reduce build context size",
	}

	switch profile.Runtime {
	case "node":
		items = append(items,
			"Prefer npm ci over npm install for reproducible builds",
			"Exclude dev dependencies from the final stage")
	case "python":
		items = append(items,
			"Use pip --no-cache-dir to avoid shipping dependency caches",
			"Pin Python dependencies in requirements files")
	case "java":
		items = append(items,
			"Copy only the built jar into the runtime stage",
			"Run tests in the build stage, not the runtime stage")
	case "go":
		items = append(items,
			"Use static builds with a minimal runtime image",
			"Keep the final image free of build toolchains")
	}

	return items
}

func fallbackBase(base string) string {
	if base == "" || strings.HasPrefix(base, "sha256:") {
		return "alpine:3.20"
	}
	return base
}

func renderExposeLines(ports []string) string {
	if len(ports) == 0 {
		return "# EXPOSE 8080"
	}

	lines := make([]string, 0, len(ports))
	for _, port := range ports {
		lines = append(lines, "EXPOSE "+port)
	}
	return strings.Join(lines, "\n")
}
