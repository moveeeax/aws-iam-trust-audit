package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

var fixtures = filepath.Join("..", "..", "internal", "audit", "testdata", "roles")

func call(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCleanRoleExitsZero(t *testing.T) {
	code, out, _ := call(t, "--dir", filepath.Join(fixtures, "ec2-app.json"))
	if code != exitClean {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
}

func TestFindingsExitOne(t *testing.T) {
	code, out, _ := call(t, "--dir", filepath.Join(fixtures, "wildcard.json"))
	if code != exitFindings {
		t.Fatalf("exit = %d, want 1\n%s", code, out)
	}
}

func TestFailOnNeverStillPrints(t *testing.T) {
	code, out, _ := call(t, "--dir", filepath.Join(fixtures, "wildcard.json"), "--fail-on", "never")
	if code != exitClean {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, "wildcard-principal") {
		t.Fatalf("output should still report the finding:\n%s", out)
	}
}

func TestWarningsDoNotFailUnlessAsked(t *testing.T) {
	code, _, _ := call(t, "--dir", filepath.Join(fixtures, "root-and-user.json"))
	if code != exitClean {
		t.Fatalf("exit = %d, want 0 (warnings only, --fail-on error)", code)
	}
	code, _, _ = call(t, "--dir", filepath.Join(fixtures, "root-and-user.json"), "--fail-on", "warning")
	if code != exitFindings {
		t.Fatalf("exit = %d, want 1 with --fail-on warning", code)
	}
}

func TestIgnoreChangesTheExitCode(t *testing.T) {
	dir := filepath.Join(fixtures, "admin-sts-star.json")
	code, _, _ := call(t, "--dir", dir, "--fail-on", "warning")
	if code != exitFindings {
		t.Fatalf("exit = %d, want 1", code)
	}
	code, out, _ := call(t, "--dir", dir, "--ignore", "wildcard-principal", "--fail-on", "error")
	if code != exitClean {
		t.Fatalf("exit = %d, want 0 after ignoring the only error\n%s", code, out)
	}
	if strings.Contains(out, "wildcard-principal") {
		t.Fatalf("ignored rule must not be printed:\n%s", out)
	}
	if !strings.Contains(out, "no-mfa-condition") {
		t.Fatalf("--ignore must suppress exactly one rule:\n%s", out)
	}
}

func TestParseErrorExitsTwo(t *testing.T) {
	code, _, errOut := call(t, "--dir", filepath.Join("..", "..", "internal", "audit", "testdata", "broken"))
	if code != exitError {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "bad.json") {
		t.Fatalf("stderr should name the file: %q", errOut)
	}
}

func TestMissingDirExitsTwo(t *testing.T) {
	if code, _, _ := call(t, "--dir", filepath.Join(fixtures, "does-not-exist")); code != exitError {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestUnknownIgnoreRuleExitsTwo(t *testing.T) {
	code, _, errOut := call(t, "--dir", fixtures, "--ignore", "no-such-rule")
	if code != exitError {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut, "unknown rule") {
		t.Fatalf("stderr = %q", errOut)
	}
}

func TestBadSeverityExitsTwo(t *testing.T) {
	if code, _, _ := call(t, "--dir", fixtures, "--min-severity", "info"); code != exitError {
		t.Fatalf("exit = %d, want 2", code)
	}
	if code, _, _ := call(t, "--dir", fixtures, "--fail-on", "whenever"); code != exitError {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestJSONFormat(t *testing.T) {
	_, out, _ := call(t, "--dir", filepath.Join(fixtures, "oidc-wildcard.json"), "--format", "json")
	if !strings.Contains(out, "\"rule\": \"oidc-wildcard-sub\"") {
		t.Fatalf("json output:\n%s", out)
	}
}

func TestRulesListing(t *testing.T) {
	code, out, _ := call(t, "--rules")
	if code != exitClean {
		t.Fatalf("exit = %d", code)
	}
	for _, want := range []string{"wildcard-principal", "deny-only-trust", "cross-account-no-externalid"} {
		if !strings.Contains(out, want) {
			t.Fatalf("--rules missing %q:\n%s", want, out)
		}
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := call(t, "--version")
	if code != exitClean || strings.TrimSpace(out) != version {
		t.Fatalf("exit = %d, out = %q", code, out)
	}
}

func TestTrustedAccountsFlagAcceptsCommaList(t *testing.T) {
	_, out, _ := call(t, "--dir", filepath.Join(fixtures, "vendor-no-externalid.json"),
		"--trusted-accounts", "555566667777,888899990000", "--format", "json")
	if !strings.Contains(out, "untrusted-account") {
		t.Fatalf("expected untrusted-account finding:\n%s", out)
	}
	_, out, _ = call(t, "--dir", filepath.Join(fixtures, "vendor-no-externalid.json"),
		"--trusted-accounts", "999988887777", "--format", "json")
	if strings.Contains(out, "untrusted-account") {
		t.Fatalf("listed account must not be flagged:\n%s", out)
	}
}
