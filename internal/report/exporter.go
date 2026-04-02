package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kristinb/bonestack/internal/layers"
)

// ExportBundle describes the optimization report written to disk.
type ExportBundle struct {
	ImageName           string                    `json:"image_name"`
	OptimizationReport  layers.OptimizationReport `json:"optimization_report"`
	LayerFindingSummary []LayerFindingRow         `json:"layer_finding_summary"`
	TarAnalysisFindings []TarFindingRow           `json:"tar_analysis_findings"`
}

// ContainerForensicsBundle captures container threat-hunt and diff output.
type ContainerForensicsBundle struct {
	ContainerName   string             `json:"container_name"`
	ThreatSummary   map[string]int     `json:"threat_summary"`
	ThreatFindings  []ForensicsFinding `json:"threat_findings"`
	DiffSummary     map[string]int     `json:"diff_summary"`
	DiffChanges     []ContainerDiffRow `json:"diff_changes"`
	TimelineSummary map[string]int     `json:"timeline_summary"`
	TimelineEvents  []TimelineRow      `json:"timeline_events"`
}

// LayerFindingRow captures per-layer optimization findings.
type LayerFindingRow struct {
	LayerIndex int    `json:"layer_index"`
	Size       string `json:"size"`
	Command    string `json:"command"`
	Findings   int    `json:"findings"`
}

// TarFindingRow captures one tar-analysis bloat item.
type TarFindingRow struct {
	Path      string `json:"path"`
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	SizeBytes int64  `json:"size_bytes"`
	Removable bool   `json:"removable"`
}

// ForensicsFinding captures one exported threat-hunt result.
type ForensicsFinding struct {
	Category string `json:"category"`
	Path     string `json:"path"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

// ContainerDiffRow captures one exported docker diff row.
type ContainerDiffRow struct {
	Path       string `json:"path"`
	Kind       string `json:"kind"`
	Suspicious bool   `json:"suspicious"`
	Detail     string `json:"detail"`
}

// TimelineRow captures one exported docker event row.
type TimelineRow struct {
	Time    string `json:"time"`
	Action  string `json:"action"`
	Type    string `json:"type"`
	Actor   string `json:"actor"`
	Details string `json:"details"`
}

// ExportOptimizationReport writes JSON, CSV, and HTML variants of the optimization report.
func ExportOptimizationReport(baseDir, imageName string, optimizationReport layers.OptimizationReport, imageLayers *layers.ImageLayers, bloat map[int][]layers.BloatItem, analyses []layers.FileAnalysisResult) (string, error) {
	exportDir := filepath.Join(baseDir, ".bonestack", "reports", sanitizeFilename(imageName))
	if err := os.MkdirAll(exportDir, 0755); err != nil {
		return "", err
	}

	bundle := ExportBundle{
		ImageName:           imageName,
		OptimizationReport:  optimizationReport,
		LayerFindingSummary: layerFindingRows(imageLayers, bloat),
		TarAnalysisFindings: tarFindingRows(analyses),
	}

	if err := writeJSON(filepath.Join(exportDir, "optimization.json"), bundle); err != nil {
		return "", err
	}
	if err := writeCSV(filepath.Join(exportDir, "optimization.csv"), bundle); err != nil {
		return "", err
	}
	if err := writeHTML(filepath.Join(exportDir, "optimization.html"), bundle); err != nil {
		return "", err
	}

	return exportDir, nil
}

// ExportContainerForensicsReport writes JSON, CSV, and HTML variants of container forensic findings.
func ExportContainerForensicsReport(baseDir, containerName string, threatFindings []map[string]string, threatSummary map[string]int, diffChanges []map[string]string, diffSummary map[string]int, timelineEvents []map[string]string, timelineSummary map[string]int) (string, error) {
	exportDir := filepath.Join(baseDir, ".bonestack", "reports", sanitizeFilename(containerName))
	if err := os.MkdirAll(exportDir, 0755); err != nil {
		return "", err
	}

	bundle := ContainerForensicsBundle{
		ContainerName:   containerName,
		ThreatSummary:   threatSummary,
		ThreatFindings:  threatFindingRows(threatFindings),
		DiffSummary:     diffSummary,
		DiffChanges:     diffChangeRows(diffChanges),
		TimelineSummary: timelineSummary,
		TimelineEvents:  timelineRows(timelineEvents),
	}

	if err := writeJSON(filepath.Join(exportDir, "forensics.json"), bundle); err != nil {
		return "", err
	}
	if err := writeContainerCSV(filepath.Join(exportDir, "forensics.csv"), bundle); err != nil {
		return "", err
	}
	if err := writeContainerHTML(filepath.Join(exportDir, "forensics.html"), bundle); err != nil {
		return "", err
	}

	return exportDir, nil
}

func writeJSON(path string, value interface{}) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func writeCSV(path string, bundle ExportBundle) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"section", "field", "value", "details"}); err != nil {
		return err
	}
	if err := writer.Write([]string{"summary", "image_name", bundle.ImageName, ""}); err != nil {
		return err
	}
	if err := writer.Write([]string{"summary", "layer_count", fmt.Sprintf("%d", bundle.OptimizationReport.LayerCount), ""}); err != nil {
		return err
	}
	if err := writer.Write([]string{"summary", "bloat_item_count", fmt.Sprintf("%d", bundle.OptimizationReport.BloatItemCount), ""}); err != nil {
		return err
	}
	if err := writer.Write([]string{"summary", "estimated_savings_bytes", fmt.Sprintf("%d", bundle.OptimizationReport.EstimatedSavings), ""}); err != nil {
		return err
	}
	for _, rec := range bundle.OptimizationReport.Recommendations {
		if err := writer.Write([]string{"recommendation", "item", rec, ""}); err != nil {
			return err
		}
	}
	for _, row := range bundle.LayerFindingSummary {
		if err := writer.Write([]string{
			"layer",
			fmt.Sprintf("%d", row.LayerIndex),
			row.Size,
			fmt.Sprintf("%d findings | %s", row.Findings, row.Command),
		}); err != nil {
			return err
		}
	}
	for _, finding := range bundle.TarAnalysisFindings {
		if err := writer.Write([]string{
			"tar_finding",
			finding.Path,
			finding.Type,
			fmt.Sprintf("%s | %d bytes | removable=%t", finding.Severity, finding.SizeBytes, finding.Removable),
		}); err != nil {
			return err
		}
	}

	return writer.Error()
}

func writeContainerCSV(path string, bundle ContainerForensicsBundle) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"section", "field", "value", "details"}); err != nil {
		return err
	}
	if err := writer.Write([]string{"summary", "container_name", bundle.ContainerName, ""}); err != nil {
		return err
	}
	for key, value := range bundle.ThreatSummary {
		if err := writer.Write([]string{"threat_summary", key, fmt.Sprintf("%d", value), ""}); err != nil {
			return err
		}
	}
	for key, value := range bundle.DiffSummary {
		if err := writer.Write([]string{"diff_summary", key, fmt.Sprintf("%d", value), ""}); err != nil {
			return err
		}
	}
	for key, value := range bundle.TimelineSummary {
		if err := writer.Write([]string{"timeline_summary", key, fmt.Sprintf("%d", value), ""}); err != nil {
			return err
		}
	}
	for _, finding := range bundle.ThreatFindings {
		if err := writer.Write([]string{"threat_finding", finding.Category, finding.Path, fmt.Sprintf("%s | %s", finding.Severity, finding.Detail)}); err != nil {
			return err
		}
	}
	for _, change := range bundle.DiffChanges {
		if err := writer.Write([]string{"container_diff", change.Kind, change.Path, fmt.Sprintf("suspicious=%t | %s", change.Suspicious, change.Detail)}); err != nil {
			return err
		}
	}
	for _, event := range bundle.TimelineEvents {
		if err := writer.Write([]string{"timeline_event", event.Action, event.Time, fmt.Sprintf("%s | %s | %s", event.Actor, event.Type, event.Details)}); err != nil {
			return err
		}
	}

	return writer.Error()
}

func writeHTML(path string, bundle ExportBundle) error {
	var body strings.Builder

	body.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>BoneStack Optimization Report</title>")
	body.WriteString("<style>body{font-family:Georgia,serif;background:#f7f4ed;color:#1d1d1d;margin:2rem;}h1,h2{color:#113b5c;}table{border-collapse:collapse;width:100%;margin:1rem 0;}th,td{border:1px solid #c8c1b8;padding:.5rem;text-align:left;}code{background:#ece7de;padding:.1rem .3rem;}ul{padding-left:1.2rem;}</style>")
	body.WriteString("</head><body>")
	body.WriteString("<h1>BoneStack Optimization Report</h1>")
	body.WriteString("<p><strong>Image:</strong> <code>" + html.EscapeString(bundle.ImageName) + "</code></p>")
	body.WriteString("<h2>Summary</h2><table>")
	body.WriteString("<tr><th>Metric</th><th>Value</th></tr>")
	body.WriteString("<tr><td>Layers</td><td>" + fmt.Sprintf("%d", bundle.OptimizationReport.LayerCount) + "</td></tr>")
	body.WriteString("<tr><td>Bloat Findings</td><td>" + fmt.Sprintf("%d", bundle.OptimizationReport.BloatItemCount) + "</td></tr>")
	body.WriteString("<tr><td>Estimated Savings</td><td>" + layers.SizeFormatter(bundle.OptimizationReport.EstimatedSavings) + "</td></tr>")
	body.WriteString("</table>")

	body.WriteString("<h2>Recommendations</h2><ul>")
	if len(bundle.OptimizationReport.Recommendations) == 0 {
		body.WriteString("<li>No recommendations generated.</li>")
	} else {
		for _, rec := range bundle.OptimizationReport.Recommendations {
			body.WriteString("<li>" + html.EscapeString(rec) + "</li>")
		}
	}
	body.WriteString("</ul>")

	body.WriteString("<h2>Layer Findings</h2><table><tr><th>Layer</th><th>Size</th><th>Findings</th><th>Command</th></tr>")
	if len(bundle.LayerFindingSummary) == 0 {
		body.WriteString("<tr><td colspan=\"4\">No layer findings.</td></tr>")
	} else {
		for _, row := range bundle.LayerFindingSummary {
			body.WriteString("<tr><td>" + fmt.Sprintf("%d", row.LayerIndex) + "</td><td>" + html.EscapeString(row.Size) + "</td><td>" + fmt.Sprintf("%d", row.Findings) + "</td><td>" + html.EscapeString(row.Command) + "</td></tr>")
		}
	}
	body.WriteString("</table>")

	body.WriteString("<h2>Tar Analysis Findings</h2><table><tr><th>Path</th><th>Type</th><th>Severity</th><th>Size</th><th>Removable</th></tr>")
	if len(bundle.TarAnalysisFindings) == 0 {
		body.WriteString("<tr><td colspan=\"5\">No tar-analysis findings.</td></tr>")
	} else {
		for _, finding := range bundle.TarAnalysisFindings {
			body.WriteString("<tr><td>" + html.EscapeString(finding.Path) + "</td><td>" + html.EscapeString(finding.Type) + "</td><td>" + html.EscapeString(finding.Severity) + "</td><td>" + layers.SizeFormatter(finding.SizeBytes) + "</td><td>" + fmt.Sprintf("%t", finding.Removable) + "</td></tr>")
		}
	}
	body.WriteString("</table></body></html>")

	return os.WriteFile(path, []byte(body.String()), 0644)
}

func writeContainerHTML(path string, bundle ContainerForensicsBundle) error {
	var body strings.Builder

	body.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>BoneStack Container Forensics Report</title>")
	body.WriteString("<style>body{font-family:Georgia,serif;background:#f7f4ed;color:#1d1d1d;margin:2rem;}h1,h2{color:#113b5c;}table{border-collapse:collapse;width:100%;margin:1rem 0;}th,td{border:1px solid #c8c1b8;padding:.5rem;text-align:left;}code{background:#ece7de;padding:.1rem .3rem;}</style>")
	body.WriteString("</head><body>")
	body.WriteString("<h1>BoneStack Container Forensics Report</h1>")
	body.WriteString("<p><strong>Container:</strong> <code>" + html.EscapeString(bundle.ContainerName) + "</code></p>")

	body.WriteString("<h2>Threat Summary</h2><table><tr><th>Category</th><th>Count</th></tr>")
	if len(bundle.ThreatSummary) == 0 {
		body.WriteString("<tr><td colspan=\"2\">No threat-hunt summary available.</td></tr>")
	} else {
		for _, key := range sortedSummaryKeys(bundle.ThreatSummary) {
			body.WriteString("<tr><td>" + html.EscapeString(key) + "</td><td>" + fmt.Sprintf("%d", bundle.ThreatSummary[key]) + "</td></tr>")
		}
	}
	body.WriteString("</table>")

	body.WriteString("<h2>Threat Findings</h2><table><tr><th>Severity</th><th>Category</th><th>Path</th><th>Detail</th></tr>")
	if len(bundle.ThreatFindings) == 0 {
		body.WriteString("<tr><td colspan=\"4\">No threat findings.</td></tr>")
	} else {
		for _, finding := range bundle.ThreatFindings {
			body.WriteString("<tr><td>" + html.EscapeString(finding.Severity) + "</td><td>" + html.EscapeString(finding.Category) + "</td><td>" + html.EscapeString(finding.Path) + "</td><td>" + html.EscapeString(finding.Detail) + "</td></tr>")
		}
	}
	body.WriteString("</table>")

	body.WriteString("<h2>Container Diff Summary</h2><table><tr><th>Kind</th><th>Count</th></tr>")
	if len(bundle.DiffSummary) == 0 {
		body.WriteString("<tr><td colspan=\"2\">No container diff summary available.</td></tr>")
	} else {
		for _, key := range sortedSummaryKeys(bundle.DiffSummary) {
			body.WriteString("<tr><td>" + html.EscapeString(key) + "</td><td>" + fmt.Sprintf("%d", bundle.DiffSummary[key]) + "</td></tr>")
		}
	}
	body.WriteString("</table>")

	body.WriteString("<h2>Container Diff Changes</h2><table><tr><th>Kind</th><th>Suspicious</th><th>Path</th><th>Detail</th></tr>")
	if len(bundle.DiffChanges) == 0 {
		body.WriteString("<tr><td colspan=\"4\">No container diff changes.</td></tr>")
	} else {
		for _, change := range bundle.DiffChanges {
			body.WriteString("<tr><td>" + html.EscapeString(change.Kind) + "</td><td>" + fmt.Sprintf("%t", change.Suspicious) + "</td><td>" + html.EscapeString(change.Path) + "</td><td>" + html.EscapeString(change.Detail) + "</td></tr>")
		}
	}
	body.WriteString("</table>")

	body.WriteString("<h2>Timeline Summary</h2><table><tr><th>Action</th><th>Count</th></tr>")
	if len(bundle.TimelineSummary) == 0 {
		body.WriteString("<tr><td colspan=\"2\">No timeline summary available.</td></tr>")
	} else {
		for _, key := range sortedSummaryKeys(bundle.TimelineSummary) {
			body.WriteString("<tr><td>" + html.EscapeString(key) + "</td><td>" + fmt.Sprintf("%d", bundle.TimelineSummary[key]) + "</td></tr>")
		}
	}
	body.WriteString("</table>")

	body.WriteString("<h2>Timeline Events</h2><table><tr><th>Time</th><th>Action</th><th>Actor</th><th>Details</th></tr>")
	if len(bundle.TimelineEvents) == 0 {
		body.WriteString("<tr><td colspan=\"4\">No timeline events.</td></tr>")
	} else {
		for _, event := range bundle.TimelineEvents {
			body.WriteString("<tr><td>" + html.EscapeString(event.Time) + "</td><td>" + html.EscapeString(event.Action) + "</td><td>" + html.EscapeString(event.Actor) + "</td><td>" + html.EscapeString(event.Details) + "</td></tr>")
		}
	}
	body.WriteString("</table></body></html>")

	return os.WriteFile(path, []byte(body.String()), 0644)
}

func layerFindingRows(imageLayers *layers.ImageLayers, bloat map[int][]layers.BloatItem) []LayerFindingRow {
	if imageLayers == nil {
		return nil
	}

	rows := make([]LayerFindingRow, 0, len(bloat))
	for idx, items := range bloat {
		if idx >= len(imageLayers.Layers) || len(items) == 0 {
			continue
		}
		layer := imageLayers.Layers[idx]
		rows = append(rows, LayerFindingRow{
			LayerIndex: idx,
			Size:       layers.SizeFormatter(layer.Size),
			Command:    layer.Command,
			Findings:   len(items),
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].LayerIndex < rows[j].LayerIndex })
	return rows
}

func tarFindingRows(analyses []layers.FileAnalysisResult) []TarFindingRow {
	rows := []TarFindingRow{}
	for _, analysis := range analyses {
		for _, finding := range analysis.PotentialBloat {
			rows = append(rows, TarFindingRow{
				Path:      finding.Path,
				Type:      finding.Type,
				Severity:  finding.Severity,
				SizeBytes: finding.Size,
				Removable: finding.Removable,
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Severity == rows[j].Severity {
			return rows[i].Path < rows[j].Path
		}
		return rows[i].Severity < rows[j].Severity
	})
	return rows
}

func threatFindingRows(findings []map[string]string) []ForensicsFinding {
	rows := make([]ForensicsFinding, 0, len(findings))
	for _, finding := range findings {
		rows = append(rows, ForensicsFinding{
			Category: finding["category"],
			Path:     finding["path"],
			Severity: finding["severity"],
			Detail:   finding["detail"],
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Severity == rows[j].Severity {
			return rows[i].Path < rows[j].Path
		}
		return rows[i].Severity < rows[j].Severity
	})
	return rows
}

func diffChangeRows(changes []map[string]string) []ContainerDiffRow {
	rows := make([]ContainerDiffRow, 0, len(changes))
	for _, change := range changes {
		rows = append(rows, ContainerDiffRow{
			Path:       change["path"],
			Kind:       change["kind"],
			Suspicious: change["suspicious"] == "true",
			Detail:     change["detail"],
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Suspicious == rows[j].Suspicious {
			return rows[i].Path < rows[j].Path
		}
		return rows[i].Suspicious
	})
	return rows
}

func timelineRows(events []map[string]string) []TimelineRow {
	rows := make([]TimelineRow, 0, len(events))
	for _, event := range events {
		rows = append(rows, TimelineRow{
			Time:    event["time"],
			Action:  event["action"],
			Type:    event["type"],
			Actor:   event["actor"],
			Details: event["details"],
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Time > rows[j].Time
	})
	return rows
}

func sortedSummaryKeys(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sanitizeFilename(name string) string {
	replacer := strings.NewReplacer("/", "_", ":", "_", "@", "_", " ", "_")
	return replacer.Replace(name)
}
