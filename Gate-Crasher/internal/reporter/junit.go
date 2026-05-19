package reporter

import (
	"encoding/xml"
	"fmt"
	"os"
	"time"

	"github.com/gate-crasher/gate-crasher/internal/analyzer"
)

// JUnit XML structures

type jUnitTestSuites struct {
	XMLName    xml.Name         `xml:"testsuites"`
	Name       string           `xml:"name,attr"`
	Tests      int              `xml:"tests,attr"`
	Failures   int              `xml:"failures,attr"`
	Time       string           `xml:"time,attr"`
	TestSuites []jUnitTestSuite `xml:"testsuite"`
}

type jUnitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Timestamp string          `xml:"timestamp,attr"`
	TestCases []jUnitTestCase `xml:"testcase"`
}

type jUnitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Name      string        `xml:"name,attr"`
	Classname string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *jUnitFailure `xml:"failure,omitempty"`
}

type jUnitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

// WriteJUnit serialises findings as JUnit XML suitable for CI/CD pipelines.
// Each finding becomes a test-case failure; clean runs produce passing test cases.
func WriteJUnit(path string, target string, findings []analyzer.Finding) error {
	now := time.Now().UTC()

	// Group findings by module
	byModule := make(map[string][]analyzer.Finding)
	for _, f := range findings {
		byModule[f.Module] = append(byModule[f.Module], f)
	}

	// Add a "clean" suite entry for modules with no findings
	allModules := []string{"idor", "privilege", "method_tamper", "mass_assign", "jwt", "path_traversal"}
	for _, m := range allModules {
		if _, exists := byModule[m]; !exists {
			byModule[m] = nil // empty slice signals no findings
		}
	}

	var suites []jUnitTestSuite
	totalTests, totalFail := 0, 0

	for _, module := range allModules {
		modFindings := byModule[module]
		cases := make([]jUnitTestCase, 0, max(1, len(modFindings)))

		if len(modFindings) == 0 {
			cases = append(cases, jUnitTestCase{
				Name:      "no_findings",
				Classname: "gatecrasher." + module,
				Time:      "0",
			})
		} else {
			for _, f := range modFindings {
				failure := &jUnitFailure{
					Message: f.Description,
					Type:    string(f.Severity),
					Text: fmt.Sprintf(
						"Finding ID: %s\nModule: %s\nSeverity: %s\nURL: %s\nMethod: %s\nTimestamp: %s\n\nRequest:\n%s\n\nResponse:\n%s",
						f.ID, f.Module, f.Severity, f.URL, f.Method, f.Timestamp,
						f.Request, f.ResponseSnippet,
					),
				}
				cases = append(cases, jUnitTestCase{
					Name:      sanitizeName(f.Description),
					Classname: "gatecrasher." + module,
					Time:      "0",
					Failure:   failure,
				})
			}
		}

		totalTests += len(cases)
		totalFail += len(modFindings)

		suites = append(suites, jUnitTestSuite{
			Name:      "gatecrasher." + module,
			Tests:     len(cases),
			Failures:  len(modFindings),
			Timestamp: now.Format(time.RFC3339),
			TestCases: cases,
		})
	}

	root := jUnitTestSuites{
		Name:       "GateCrasher BAC Scan: " + target,
		Tests:      totalTests,
		Failures:   totalFail,
		Time:       "0",
		TestSuites: suites,
	}

	data, err := xml.MarshalIndent(root, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal junit xml: %w", err)
	}
	output := []byte(xml.Header + string(data))

	if path == "" || path == "-" {
		_, err = os.Stdout.Write(output)
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create junit file %q: %w", path, err)
	}
	defer f.Close()
	_, err = f.Write(output)
	return err
}

// sanitizeName truncates and cleans a finding description for use as a JUnit
// test name.
func sanitizeName(s string) string {
	const maxLen = 80
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
