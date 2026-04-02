package sde

import (
	"fmt"
	"sort"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/kristinb/bonestack/internal/layers"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
)

// ProjectProfile captures a best-effort application/runtime profile.
type ProjectProfile struct {
	BaseImage         string
	Runtime           string
	Workdir           string
	ExposedPorts      []string
	HasEntrypoint     bool
	DetectedLanguages []string
	PackageManagers   []string
}

// GeneratedArtifact is an additional generated file/template.
type GeneratedArtifact struct {
	Name    string
	Content string
}

// Scaffold contains generated SDE output.
type Scaffold struct {
	Profile          ProjectProfile
	Dockerfile       string
	PolicyChecklist  []string
	SecurityArtifacts []GeneratedArtifact
}

// Generator produces starter Dockerfiles and policy scaffolding.
type Generator struct{}

// NewGenerator creates a new scaffold generator.
func NewGenerator() *Generator {
	return &Generator{}
}

// InferProfile derives a runtime profile from image metadata and optional tar analysis.
func (g *Generator) InferProfile(imageName string, inspect types.ImageInspect, analyses []layers.FileAnalysisResult) ProjectProfile {
	profile := ProjectProfile{
		BaseImage:         imageName,
		Runtime:           inferRuntime(imageName, inspect, analyses),
		Workdir:           firstWorkdir(inspect),
		DetectedLanguages: collectLanguages(analyses),
		PackageManagers:   collectPackageManagers(analyses),
	}

	for port := range imageConfig(inspect).ExposedPorts {
		profile.ExposedPorts = append(profile.ExposedPorts, port)
	}
	sort.Strings(profile.ExposedPorts)
	profile.HasEntrypoint = len(imageConfig(inspect).Entrypoint) > 0 || len(imageConfig(inspect).Cmd) > 0
	return profile
}

// Generate builds a starter scaffold from image metadata.
func (g *Generator) Generate(imageName string, inspect types.ImageInspect) Scaffold {
	return g.GenerateWithAnalysis(imageName, inspect, nil)
}

// GenerateWithAnalysis builds a scaffold enriched by tar-analysis findings when available.
func (g *Generator) GenerateWithAnalysis(imageName string, inspect types.ImageInspect, analyses []layers.FileAnalysisResult) Scaffold {
	profile := g.InferProfile(imageName, inspect, analyses)
	return Scaffold{
		Profile:           profile,
		Dockerfile:        renderDockerfile(profile),
		PolicyChecklist:   buildPolicyChecklist(profile, analyses),
		SecurityArtifacts: buildSecurityArtifacts(profile),
	}
}

func inferRuntime(imageName string, inspect types.ImageInspect, analyses []layers.FileAnalysisResult) string {
	languages := collectLanguages(analyses)
	for _, lang := range languages {
		switch lang {
		case "JavaScript":
			return "node"
		case "Python":
			return "python"
		case "Java":
			return "java"
		case "Go":
			return "go"
		case "Ruby":
			return "ruby"
		case "Rust":
			return "rust"
		case "PHP":
			return "php"
		}
	}

	for _, pm := range collectPackageManagers(analyses) {
		switch pm {
		case "cargo":
			return "rust"
		case "gem":
			return "ruby"
		}
	}

	candidates := []string{
		imageName,
		strings.Join(imageConfig(inspect).Entrypoint, " "),
		strings.Join(imageConfig(inspect).Cmd, " "),
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
	if imageConfig(inspect).WorkingDir != "" {
		return imageConfig(inspect).WorkingDir
	}
	return "/app"
}

func imageConfig(inspect types.ImageInspect) *dockerspec.DockerOCIImageConfig {
	if inspect.Config != nil {
		return inspect.Config
	}
	return &dockerspec.DockerOCIImageConfig{}
}

func renderDockerfile(profile ProjectProfile) string {
	hints := dependencyHintComments(profile)
	switch profile.Runtime {
	case "node":
		return fmt.Sprintf(`FROM node:20-alpine AS build
WORKDIR %s
%s
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
CMD ["npm", "start"]`, profile.Workdir, hints, profile.Workdir, profile.Workdir, renderExposeLines(profile.ExposedPorts))
	case "python":
		return fmt.Sprintf(`FROM python:3.12-slim
WORKDIR %s
%s
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
COPY requirements*.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -r -u 10001 appuser && chown -R appuser:appuser %s
USER appuser
%s
CMD ["python", "app.py"]`, profile.Workdir, hints, profile.Workdir, renderExposeLines(profile.ExposedPorts))
	case "java":
		return fmt.Sprintf(`FROM eclipse-temurin:21-jdk AS build
WORKDIR %s
%s
COPY . .
RUN ./mvnw -q -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR %s
COPY --from=build %s/target/*.jar app.jar
RUN useradd -r -u 10001 appuser && chown appuser:appuser app.jar
USER appuser
%s
CMD ["java", "-jar", "app.jar"]`, profile.Workdir, hints, profile.Workdir, profile.Workdir, renderExposeLines(profile.ExposedPorts))
	case "go":
		return fmt.Sprintf(`FROM golang:1.25 AS build
WORKDIR %s
%s
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o app ./...

FROM gcr.io/distroless/static-debian12
WORKDIR %s
COPY --from=build %s/app ./app
USER nonroot:nonroot
%s
ENTRYPOINT ["./app"]`, profile.Workdir, hints, profile.Workdir, profile.Workdir, renderExposeLines(profile.ExposedPorts))
	case "ruby":
		return fmt.Sprintf(`FROM ruby:3.3-alpine
WORKDIR %s
%s
COPY Gemfile* ./
RUN bundle config set without 'development test' && bundle install
COPY . .
RUN adduser -D -u 10001 appuser && chown -R appuser:appuser %s
USER appuser
%s
CMD ["bundle", "exec", "ruby", "app.rb"]`, profile.Workdir, hints, profile.Workdir, renderExposeLines(profile.ExposedPorts))
	case "rust":
		return fmt.Sprintf(`FROM rust:1.86 AS build
WORKDIR %s
%s
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR %s
COPY --from=build %s/target/release/app ./app
RUN useradd -r -u 10001 appuser && chown appuser:appuser app
USER appuser
%s
ENTRYPOINT ["./app"]`, profile.Workdir, hints, profile.Workdir, profile.Workdir, renderExposeLines(profile.ExposedPorts))
	case "php":
		return fmt.Sprintf(`FROM php:8.3-cli-alpine
WORKDIR %s
%s
COPY composer.* ./
RUN composer install --no-dev --optimize-autoloader || true
COPY . .
RUN adduser -D -u 10001 appuser && chown -R appuser:appuser %s
USER appuser
%s
CMD ["php", "index.php"]`, profile.Workdir, hints, profile.Workdir, renderExposeLines(profile.ExposedPorts))
	case "nginx":
		return fmt.Sprintf(`FROM nginx:stable-alpine
WORKDIR %s
%s
COPY . /usr/share/nginx/html
%s
CMD ["nginx", "-g", "daemon off;"]`, profile.Workdir, hints, renderExposeLines(profile.ExposedPorts))
	default:
		return fmt.Sprintf(`FROM %s
WORKDIR %s
%s
COPY . .
%s
CMD ["sh"]`, fallbackBase(profile.BaseImage), profile.Workdir, hints, renderExposeLines(profile.ExposedPorts))
	}
}

func dependencyHintComments(profile ProjectProfile) string {
	hints := []string{"# Dependency optimization hints:"}
	for _, pm := range profile.PackageManagers {
		switch pm {
		case "npm":
			hints = append(hints, "# - copy package-lock.json and use npm ci for reproducible installs")
		case "pip":
			hints = append(hints, "# - pin requirements and keep pip --no-cache-dir enabled")
		case "apt":
			hints = append(hints, "# - combine apt-get install with cache cleanup in the same RUN step")
		case "apk":
			hints = append(hints, "# - prefer apk add --no-cache to avoid package cache layers")
		case "cargo":
			hints = append(hints, "# - copy Cargo.lock early to maximize dependency layer reuse")
		case "gem":
			hints = append(hints, "# - exclude development/test gems from the final image")
		}
	}
	if len(hints) == 1 {
		hints = append(hints, "# - keep dependency manifests in an early copy step to improve layer reuse")
	}
	return strings.Join(hints, "\n")
}

func buildPolicyChecklist(profile ProjectProfile, analyses []layers.FileAnalysisResult) []string {
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

	if hasLargeBloatFootprint(analyses) {
		items = append(items,
			"Review tar-analysis bloat findings before copying the full project tree into the image")
	}

	return items
}

func buildSecurityArtifacts(profile ProjectProfile) []GeneratedArtifact {
	artifacts := []GeneratedArtifact{
		{
			Name: ".dockerignore",
			Content: strings.Join([]string{
				".git",
				".env",
				"node_modules",
				"__pycache__",
				"dist",
				"build",
			}, "\n"),
		},
		{
			Name: "policy/kubernetes-security-context.yaml",
			Content: strings.Join([]string{
				"securityContext:",
				"  runAsNonRoot: true",
				"  allowPrivilegeEscalation: false",
				"  readOnlyRootFilesystem: true",
				"  capabilities:",
				"    drop: [\"ALL\"]",
			}, "\n"),
		},
	}

	if profile.Runtime == "nginx" || profile.Runtime == "node" || profile.Runtime == "python" {
		artifacts = append(artifacts, GeneratedArtifact{
			Name: "policy/container-hardening.md",
			Content: strings.Join([]string{
				"# Container Hardening",
				"",
				"- set CPU/memory limits at deploy time",
				"- mount secrets read-only",
				"- enable image scanning in CI",
				"- avoid shell access in production containers",
			}, "\n"),
		})
	}

	switch profile.Runtime {
	case "node":
		artifacts = append(artifacts, GeneratedArtifact{
			Name: "policy/node-runtime.md",
			Content: strings.Join([]string{
				"# Node Runtime Policy",
				"",
				"- set NODE_ENV=production",
				"- fail builds if package-lock.json changes unexpectedly",
				"- run npm audit in CI before release",
			}, "\n"),
		})
	case "python":
		artifacts = append(artifacts, GeneratedArtifact{
			Name: "policy/python-runtime.md",
			Content: strings.Join([]string{
				"# Python Runtime Policy",
				"",
				"- require pinned dependencies",
				"- block images that contain pip cache directories",
				"- prefer slim base images unless native build deps are required",
			}, "\n"),
		})
	case "rust":
		artifacts = append(artifacts, GeneratedArtifact{
			Name: "policy/rust-runtime.md",
			Content: strings.Join([]string{
				"# Rust Runtime Policy",
				"",
				"- build in a dedicated toolchain stage",
				"- copy only the release binary into the runtime image",
				"- prefer distroless or slim runtime images when glibc requirements allow",
			}, "\n"),
		})
	case "go":
		artifacts = append(artifacts, GeneratedArtifact{
			Name: "policy/go-runtime.md",
			Content: strings.Join([]string{
				"# Go Runtime Policy",
				"",
				"- enforce static builds for simple services",
				"- use minimal runtime images for final delivery",
				"- fail CI when debug toolchains leak into final images",
			}, "\n"),
		})
	}

	return artifacts
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

func collectLanguages(analyses []layers.FileAnalysisResult) []string {
	set := make(map[string]bool)
	for _, analysis := range analyses {
		for _, lang := range analysis.LanguageDetected {
			set[lang] = true
		}
	}
	return sortedKeys(set)
}

func collectPackageManagers(analyses []layers.FileAnalysisResult) []string {
	set := make(map[string]bool)
	for _, analysis := range analyses {
		for _, pm := range analysis.PackageManagers {
			set[pm] = true
		}
	}
	return sortedKeys(set)
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func hasLargeBloatFootprint(analyses []layers.FileAnalysisResult) bool {
	var total int64
	for _, analysis := range analyses {
		for _, finding := range analysis.PotentialBloat {
			total += finding.Size
		}
	}
	return total > 50*1024*1024
}
