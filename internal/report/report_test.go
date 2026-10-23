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
