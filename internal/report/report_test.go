package report

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moveeeax/aws-iam-trust-audit/internal/audit"
	"github.com/moveeeax/aws-iam-trust-audit/internal/iampolicy"
)

func fixture(t *testing.T, name string) audit.Result {
	t.Helper()
	roles, err := iampolicy.LoadFile(filepath.Join("..", "audit", "testdata", "roles", name))
	if err != nil {
		t.Fatal(err)
	}
	return audit.Run(roles, audit.Options{})
}

func render(t *testing.T, res audit.Result, format string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, res, format); err != nil {
		t.Fatalf("Write(%s): %v", format, err)
	}
	return buf.String()
}

func TestTableShowsAssumersAndFindings(t *testing.T) {
	out := render(t, fixture(t, "oidc-wildcard.json"), "table")
	for _, want := range []string{"WHO MAY ASSUME", "federated-oidc", "sts:AssumeRoleWithWebIdentity",
		"FINDINGS (1 error, 0 warning)", "oidc-wildcard-sub"} {
		if !strings.Contains(out, want) {
			t.Fatalf("table output missing %q:\n%s", want, out)
		}
	}
}

func TestTableSaysNoneWhenClean(t *testing.T) {
	out := render(t, fixture(t, "ec2-app.json"), "table")
	if !strings.Contains(out, "FINDINGS (0 error, 0 warning)") || !strings.Contains(out, "none") {
		t.Fatalf("clean table output:\n%s", out)
	}
}

func TestJSONIsValidAndCarriesSummary(t *testing.T) {
	out := render(t, fixture(t, "root-and-user.json"), "json")
	var parsed struct {
		Summary struct {
			Roles    int `json:"roles"`
			Errors   int `json:"errors"`
			Warnings int `json:"warnings"`
		} `json:"summary"`
		Findings []struct {
			Rule      string `json:"rule"`
			Severity  string `json:"severity"`
			Statement int    `json:"statement"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("json output does not parse: %v\n%s", err, out)
	}
	if parsed.Summary.Roles != 1 || parsed.Summary.Warnings != 2 || parsed.Summary.Errors != 0 {
		t.Fatalf("summary = %+v", parsed.Summary)
	}
	if len(parsed.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(parsed.Findings))
	}
}

func TestJSONCleanRunHasEmptyFindingsArray(t *testing.T) {
	out := render(t, fixture(t, "ec2-app.json"), "json")
	if !strings.Contains(out, "\"findings\": []") {
		t.Fatalf("clean json should carry an empty array, got:\n%s", out)
	}
}

func TestMarkdownHasATableAndDetails(t *testing.T) {
	out := render(t, fixture(t, "vendor-no-externalid.json"), "markdown")
	for _, want := range []string{"## IAM trust audit", "| Severity | Rule |",
		"`cross-account-no-externalid`", "<details><summary>Who may assume each role</summary>"} {
		if !strings.Contains(out, want) {
			t.Fatalf("markdown missing %q:\n%s", want, out)
		}
	}
}

func TestUnknownFormatIsAnError(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, audit.Result{}, "yaml"); err == nil {
		t.Fatal("unknown format should be rejected")
	}
}

func TestSARIFCarriesRulesResultsAndLocations(t *testing.T) {
	Version = "9.9.9"
	t.Cleanup(func() { Version = "dev" })
	out := render(t, fixture(t, "oidc-wildcard.json"), "sarif")
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("sarif does not parse: %v\n%s", err, out)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("version = %q, runs = %d", log.Version, len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "aws-iam-trust-audit" || run.Tool.Driver.Version != "9.9.9" {
		t.Fatalf("driver = %+v", run.Tool.Driver)
	}
	if len(run.Tool.Driver.Rules) != len(audit.Rules) {
		t.Fatalf("rules = %d, want %d", len(run.Tool.Driver.Rules), len(audit.Rules))
	}
	if len(run.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(run.Results))
	}
	r := run.Results[0]
	if r.RuleID != "oidc-wildcard-sub" || r.Level != "error" {
		t.Fatalf("result = %+v", r)
	}
	if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
		t.Fatalf("ruleIndex %d points at %q", r.RuleIndex, run.Tool.Driver.Rules[r.RuleIndex].ID)
	}
	if uri := r.Locations[0].PhysicalLocation.ArtifactLocation.URI; !strings.HasSuffix(uri, "testdata/roles/oidc-wildcard.json") {
		t.Fatalf("uri = %q", uri)
	}
}

func TestSARIFLiveRoleUsesALogicalLocation(t *testing.T) {
	arn := "arn:aws:iam::111122223333:role/open"
	res := audit.Result{Findings: []audit.Finding{{Rule: "wildcard-principal", Severity: "error", Role: "open", File: arn}}}
	out := render(t, res, "sarif")
	if !strings.Contains(out, `"fullyQualifiedName": "`+arn+`"`) || strings.Contains(out, "physicalLocation") {
		t.Fatalf("live finding should carry the ARN as a logical location:\n%s", out)
	}
}

func TestSARIFCleanRunHasEmptyResults(t *testing.T) {
	out := render(t, fixture(t, "ec2-app.json"), "sarif")
	if !strings.Contains(out, `"results": []`) {
		t.Fatalf("clean sarif should carry an empty results array:\n%s", out)
	}
}
