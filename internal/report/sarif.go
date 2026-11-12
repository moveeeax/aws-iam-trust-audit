package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/moveeeax/aws-iam-trust-audit/internal/audit"
)

// SARIF 2.1.0, trimmed to the fields code-scanning consumers read.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string       `json:"id"`
	ShortDescription     sarifMessage `json:"shortDescription"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	RuleIndex  int             `json:"ruleIndex"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysical `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation struct {
		URI string `json:"uri"`
	} `json:"artifactLocation"`
}

type sarifLogical struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

func writeSARIF(w io.Writer, res audit.Result) error {
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "aws-iam-trust-audit",
			Version:        Version,
			InformationURI: "https://github.com/moveeeax/aws-iam-trust-audit",
		}},
		Results: []sarifResult{},
	}
	index := map[string]int{}
	for i, r := range audit.Rules {
		rule := sarifRule{ID: r.Name, ShortDescription: sarifMessage{Text: r.Desc}}
		rule.DefaultConfiguration.Level = r.Severity.String()
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
		index[r.Name] = i
	}
	for _, f := range res.Findings {
		run.Results = append(run.Results, sarifResult{
			RuleID:    f.Rule,
			RuleIndex: index[f.Rule],
			Level:     f.Severity,
			Message:   sarifMessage{Text: fmt.Sprintf("role %s, statement %d: %s", f.Role, f.Statement, f.Message)},
			Locations: []sarifLocation{location(f)},
			Properties: map[string]any{
				"role":      f.Role,
				"statement": f.Statement,
				"principal": f.Principal,
			},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	})
}

// location points at the file the role came from. A role read with
// --from-aws has no file, so it gets its ARN as a logical location instead.
func location(f audit.Finding) sarifLocation {
	if strings.HasPrefix(f.File, "arn:") {
		return sarifLocation{LogicalLocations: []sarifLogical{{FullyQualifiedName: f.File, Kind: "resource"}}}
	}
	p := &sarifPhysical{}
	p.ArtifactLocation.URI = filepath.ToSlash(f.File)
	return sarifLocation{PhysicalLocation: p}
}
