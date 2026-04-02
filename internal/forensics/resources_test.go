package forensics

import (
	"math"
	"testing"
)

func TestParseMemInfo(t *testing.T) {
	stats := &ResourceStats{}
	parseMemInfo("MemTotal: 2048000 kB\nMemAvailable: 512000 kB\n", stats)

	if got, want := stats.MemoryLimitMB, 2000.0; math.Abs(got-want) > 0.01 {
		t.Fatalf("MemoryLimitMB got %.2f want %.2f", got, want)
	}
	if got, want := stats.MemoryUsageMB, 1500.0; math.Abs(got-want) > 0.01 {
		t.Fatalf("MemoryUsageMB got %.2f want %.2f", got, want)
	}
	if got, want := stats.MemoryPercent, 75.0; math.Abs(got-want) > 0.01 {
		t.Fatalf("MemoryPercent got %.2f want %.2f", got, want)
	}
}

func TestParseMemInfoWithoutTotal(t *testing.T) {
	stats := &ResourceStats{}
	parseMemInfo("MemAvailable: 512000 kB\n", stats)

	if stats.MemoryLimitMB != 0 || stats.MemoryUsageMB != 0 || stats.MemoryPercent != 0 {
		t.Fatalf("expected zero-value stats when MemTotal is missing, got %+v", stats)
	}
}
