package audit

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/moveeeax/aws-iam-trust-audit/internal/iampolicy"
)

func auditFile(t *testing.T, name string, opt Options) Result {
	t.Helper()
	roles, err := iampolicy.LoadFile(filepath.Join("testdata", "roles", name))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return Run(roles, opt)
}

func rules(res Result) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.Rule)
	}
	sort.Strings(out)
	return out
}

func wantRules(t *testing.T, res Result, want ...string) {
	t.Helper()
	got := rules(res)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("rules = %v, want %v", got, want)
	}
}

func TestServiceRoleWithSourceAccountIsClean(t *testing.T) {
	res := auditFile(t, "ec2-app.json", Options{})
	wantRules(t, res)
	if res.Max() != 0 {
		t.Fatalf("max severity = %v, want clean", res.Max())
	}
	if len(res.Roles[0].Assumers) != 1 {
		t.Fatalf("assumers = %d, want 1", len(res.Roles[0].Assumers))
	}
	if got := res.Roles[0].Assumers[0].Who.Kind; got != KindService {
		t.Fatalf("kind = %q, want %q", got, KindService)
	}
}

func TestWildcardPrincipalIsAnError(t *testing.T) {
	res := auditFile(t, "wildcard.json", Options{})
	wantRules(t, res, RuleWildcardPrincipal)
	f := res.Findings[0]
	if f.Severity != "error" {
		t.Fatalf("severity = %q, want error", f.Severity)
	}
	if f.Statement != 0 {
		t.Fatalf("statement = %d, want 0", f.Statement)
	}
	if !strings.HasSuffix(f.File, "wildcard.json") {
		t.Fatalf("file = %q, want the fixture path", f.File)
	}
}

func TestCrossAccountWithoutExternalID(t *testing.T) {
	res := auditFile(t, "vendor-no-externalid.json", Options{})
	wantRules(t, res, RuleCrossAccountNoEID)
	if !strings.Contains(res.Findings[0].Message, "999988887777") {
		t.Fatalf("message should name the external account: %q", res.Findings[0].Message)
	}

	clean := auditFile(t, "vendor-with-externalid.json", Options{})
	wantRules(t, clean)
}

func TestUntrustedAccountIsAWarningOnlyWhenListed(t *testing.T) {
	res := auditFile(t, "vendor-no-externalid.json", Options{TrustedAccounts: []string{"555566667777"}})
	wantRules(t, res, RuleCrossAccountNoEID, RuleUntrustedAccount)

	ok := auditFile(t, "vendor-no-externalid.json", Options{TrustedAccounts: []string{"999988887777"}})
	wantRules(t, ok, RuleCrossAccountNoEID)
}

func TestOIDCWildcardSub(t *testing.T) {
	res := auditFile(t, "oidc-wildcard.json", Options{})
	wantRules(t, res, RuleOIDCWildcardSub)
	if !strings.Contains(res.Findings[0].Message, "every repository") {
		t.Fatalf("message should explain the repository-wide wildcard: %q", res.Findings[0].Message)
	}

	pinned := auditFile(t, "oidc-pinned.json", Options{})
	wantRules(t, pinned)

	missing := auditFile(t, "oidc-no-sub.json", Options{})
	wantRules(t, missing, RuleOIDCWildcardSub)
	if !strings.Contains(missing.Findings[0].Message, "no :sub condition") {
		t.Fatalf("missing-sub message = %q", missing.Findings[0].Message)
	}
}

func TestOIDCWildcardInRefSegment(t *testing.T) {
	roles, err := iampolicy.LoadFile(filepath.Join("testdata", "roles", "oidc-pinned.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Loosen the pinned role to every branch and the rule must fire, naming
	// the repository that stays fixed.
	for op, kv := range roles[0].Trust.Statement[0].Condition {
		for k := range kv {
			if strings.HasSuffix(k, ":sub") {
				roles[0].Trust.Statement[0].Condition[op][k] = iampolicy.StringOrSlice{"repo:moveeeax/app:*"}
			}
		}
	}
	res := Run(roles, Options{})
	wantRules(t, res, RuleOIDCWildcardSub)
	if !strings.Contains(res.Findings[0].Message, "moveeeax/app") {
		t.Fatalf("message = %q, want the pinned repository named", res.Findings[0].Message)
	}
}

func TestRootAndUserPrincipals(t *testing.T) {
	res := auditFile(t, "root-and-user.json", Options{})
	wantRules(t, res, RuleNoMFACondition, RuleRootPrincipal)
	if res.Max() != Warning {
		t.Fatalf("max = %v, want warning", res.Max())
	}
	// --min-severity error hides both.
	only := auditFile(t, "root-and-user.json", Options{MinSeverity: Error})
	wantRules(t, only)
}

func TestWildcardActionIsReported(t *testing.T) {
	res := auditFile(t, "admin-sts-star.json", Options{})
	wantRules(t, res, RuleNoMFACondition, RuleWildcardPrincipal)
	if res.Max() != Error {
		t.Fatalf("max = %v, want error", res.Max())
	}
}

func TestDenyOnlyTrust(t *testing.T) {
	res := auditFile(t, "deny-only.json", Options{})
	wantRules(t, res, RuleDenyOnlyTrust)
	if got := res.Roles[0].Assumers[0].Effect; got != "Deny" {
		t.Fatalf("effect = %q, want Deny", got)
	}
}

func TestIgnoreSuppressesExactlyOneRule(t *testing.T) {
	res := auditFile(t, "root-and-user.json", Options{Ignore: map[string]bool{RuleNoMFACondition: true}})
	wantRules(t, res, RuleRootPrincipal)
}

func TestSelfAccountOverrideRemovesCrossAccount(t *testing.T) {
	res := auditFile(t, "vendor-no-externalid.json", Options{SelfAccount: "999988887777"})
	wantRules(t, res)
}

func TestDirectoryAuditAggregates(t *testing.T) {
	roles, err := iampolicy.LoadDir(filepath.Join("testdata", "roles"))
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 10 {
		t.Fatalf("roles = %d, want 10", len(roles))
	}
	res := Run(roles, Options{})
	errs, warns := res.Counts()
	if errs == 0 || warns == 0 {
		t.Fatalf("counts = %d errors, %d warnings; want both non-zero", errs, warns)
	}
	// Findings are ordered by file so output diffs stay readable.
	for i := 1; i < len(res.Findings); i++ {
		if res.Findings[i-1].File > res.Findings[i].File {
			t.Fatalf("findings not ordered by file at %d", i)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Severity
		bad  bool
	}{{"warning", Warning, false}, {"ERROR", Error, false}, {"fatal", 0, true}} {
		got, err := ParseSeverity(tc.in)
		if tc.bad != (err != nil) {
			t.Fatalf("ParseSeverity(%q) err = %v", tc.in, err)
		}
		if !tc.bad && got != tc.want {
			t.Fatalf("ParseSeverity(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
