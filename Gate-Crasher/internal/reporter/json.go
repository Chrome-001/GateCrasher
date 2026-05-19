package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/gate-crasher/gate-crasher/internal/analyzer"
)

// ScanMeta holds top-level metadata for a scan report.
type ScanMeta struct {
	ScanTime      string             `json:"scan_time"`
	Target        string             `json:"target"`
	TotalFindings int                `json:"total_findings"`
	BySeverity    map[string]int     `json:"by_severity"`
	Findings      []analyzer.Finding `json:"findings"`
}

// WriteJSON serialises all findings plus metadata to a JSON file.
func WriteJSON(path string, target string, findings []analyzer.Finding) error {
	meta := buildMeta(target, findings)

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json report: %w", err)
	}

	if path == "" || path == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create json report file %q: %w", path, err)
	}
	defer f.Close()

	_, err = f.Write(data)
	return err
}

func buildMeta(target string, findings []analyzer.Finding) ScanMeta {
	bySev := map[string]int{
		string(analyzer.SeverityCritical): 0,
		string(analyzer.SeverityHigh):     0,
		string(analyzer.SeverityMedium):   0,
		string(analyzer.SeverityLow):      0,
		string(analyzer.SeverityInfo):     0,
	}
	for _, f := range findings {
		bySev[string(f.Severity)]++
	}
	return ScanMeta{
		ScanTime:      time.Now().UTC().Format(time.RFC3339),
		Target:        target,
		TotalFindings: len(findings),
		BySeverity:    bySev,
		Findings:      findings,
	}
}
