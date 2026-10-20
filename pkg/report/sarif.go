package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/cawalch/go-yara-supplychain/pkg/analyzer"
)

const (
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	sarifVersion = "2.1.0"
	toolName     = "go-yara-supplychain"
	toolVersion  = "0.1.0"
	toolURL      = "https://github.com/cawalch/go-yara-supplychain"
)

// SARIFReport represents the root of a SARIF 2.1.0 document.
type SARIFReport struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver ToolComponent `json:"driver"`
}

type ToolComponent struct {
	Name            string                `json:"name"`
	SemanticVersion string                `json:"semanticVersion"`
	InformationURI  string                `json:"informationUri"`
	Rules           []ReportingDescriptor `json:"rules"`
}

type ReportingDescriptor struct {
	ID                   string                 `json:"id"`
	ShortDescription     MultiformatMessage     `json:"shortDescription"`
	FullDescription      MultiformatMessage     `json:"fullDescription"`
	DefaultConfiguration ReportingConfiguration `json:"defaultConfiguration"`
}

type ReportingConfiguration struct {
	Level string `json:"level"`
}

type MultiformatMessage struct {
	Text string `json:"text"`
}

type Result struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    MultiformatMessage     `json:"message"`
	Locations  []Location             `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine int `json:"startLine"`
}

// GenerateSARIF converts a slice of package analysis verdicts into a SARIF 2.1.0 report.
func GenerateSARIF(verdicts []*analyzer.Verdict) (*SARIFReport, error) {
	ruleMap := make(map[string]ReportingDescriptor)
	results := make([]Result, 0)

	for _, v := range verdicts {
		for _, ev := range v.Evidence {
			// Register rule descriptor if not seen
			sarifLevel := mapSeverityToSARIFLevel(ev.Severity)
			if _, exists := ruleMap[ev.RuleID]; !exists {
				ruleMap[ev.RuleID] = ReportingDescriptor{
					ID: ev.RuleID,
					ShortDescription: MultiformatMessage{
						Text: ev.Description,
					},
					FullDescription: MultiformatMessage{
						Text: fmt.Sprintf("[%s] %s (Category: %s)", ev.Severity, ev.Description, ev.Category),
					},
					DefaultConfiguration: ReportingConfiguration{
						Level: sarifLevel,
					},
				}
			}

			// Construct result
			msg := fmt.Sprintf("[%s] Package '%s': %s", ev.Severity, v.PackageName, ev.Description)
			if ev.Snippet != "" {
				msg += "\nSnippet: " + ev.Snippet
			}

			locURI := ev.FilePath
			if locURI == "" {
				locURI = "package.json"
			}

			results = append(results, Result{
				RuleID: ev.RuleID,
				Level:  sarifLevel,
				Message: MultiformatMessage{
					Text: msg,
				},
				Locations: []Location{
					{
						PhysicalLocation: PhysicalLocation{
							ArtifactLocation: ArtifactLocation{
								URI: locURI,
							},
							Region: &Region{StartLine: 1},
						},
					},
				},
				Properties: map[string]interface{}{
					"packageName":     v.PackageName,
					"packageVersion":  v.PackageVersion,
					"confidenceScore": v.ConfidenceScore,
					"category":        ev.Category,
				},
			})
		}
	}

	rulesList := make([]ReportingDescriptor, 0, len(ruleMap))
	for _, r := range ruleMap {
		rulesList = append(rulesList, r)
	}

	report := &SARIFReport{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []Run{
			{
				Tool: Tool{
					Driver: ToolComponent{
						Name:            toolName,
						SemanticVersion: toolVersion,
						InformationURI:  toolURL,
						Rules:           rulesList,
					},
				},
				Results: results,
			},
		},
	}

	return report, nil
}

// WriteSARIFToFile serializes the verdicts into a SARIF 2.1.0 JSON file.
func WriteSARIFToFile(filePath string, verdicts []*analyzer.Verdict) error {
	report, err := GenerateSARIF(verdicts)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling SARIF report: %w", err)
	}

	return os.WriteFile(filePath, data, 0o644)
}

// WriteSARIF writes SARIF JSON directly to an io.Writer.
func WriteSARIF(w io.Writer, verdicts []*analyzer.Verdict) error {
	report, err := GenerateSARIF(verdicts)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func mapSeverityToSARIFLevel(sev analyzer.RiskLevel) string {
	switch sev {
	case analyzer.RiskCritical:
		return "error"
	case analyzer.RiskHigh:
		return "error"
	case analyzer.RiskMedium:
		return "warning"
	default:
		return "note"
	}
}
