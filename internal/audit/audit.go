// Package audit turns parsed trust policies into a list of assumers and a
// list of findings. Every rule here is static: it answers "who may become this
// role" from the document alone, with no AWS call.
package audit

import (
	"fmt"
	"sort"
	"strings"

	"github.com/moveeeax/aws-iam-trust-audit/internal/iampolicy"
)

// Severity ranks a finding.
type Severity int

const (
	Warning Severity = iota + 1
	Error
)

func (s Severity) String() string {
	if s == Error {
		return "error"
	}
	return "warning"
}

// ParseSeverity reads a severity name.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(s) {
	case "warning", "warn":
		return Warning, nil
	case "error", "err":
		return Error, nil
	}
	return 0, fmt.Errorf("unknown severity %q (want warning or error)", s)
}

// Rule names, stable because --ignore takes them.
const (
	RuleWildcardPrincipal = "wildcard-principal"
	RuleCrossAccountNoEID = "cross-account-no-externalid"
	RuleOIDCWildcardSub   = "oidc-wildcard-sub"
	RuleUntrustedAccount  = "untrusted-account"
	RuleRootPrincipal     = "root-principal"
	RuleNoMFACondition    = "no-mfa-condition"
	RuleDenyOnlyTrust     = "deny-only-trust"
)

// Rules lists every rule with its severity and one-line description.
var Rules = []struct {
	Name     string
	Severity Severity
	Desc     string
}{
	{RuleWildcardPrincipal, Error, "principal is \"*\", or the action is sts:* / *"},
	{RuleCrossAccountNoEID, Error, "external account principal with no sts:ExternalId condition"},
	{RuleOIDCWildcardSub, Error, "web-identity principal whose sub claim is unset or wildcarded"},
	{RuleUntrustedAccount, Warning, "account id outside --trusted-accounts"},
	{RuleRootPrincipal, Warning, "bare arn:aws:iam::<id>:root principal"},
	{RuleNoMFACondition, Warning, "IAM user principal without aws:MultiFactorAuthPresent"},
	{RuleDenyOnlyTrust, Warning, "trust document is Deny-only, so nothing can assume the role"},
}

// Finding is one rule hit, located by file and statement index.
type Finding struct {
	Rule      string `json:"rule"`
	Severity  string `json:"severity"`
	Role      string `json:"role"`
	File      string `json:"file"`
	Statement int    `json:"statement"`
	Principal string `json:"principal,omitempty"`
	Message   string `json:"message"`

	sev Severity
}

// Sev returns the typed severity.
func (f Finding) Sev() Severity { return f.sev }

// RoleReport is the resolved trust of one role plus its findings.
type RoleReport struct {
	Role      string    `json:"role"`
	Arn       string    `json:"arn,omitempty"`
	AccountID string    `json:"accountId,omitempty"`
	File      string    `json:"file"`
	Assumers  []Assumer `json:"assumers"`
	Findings  []Finding `json:"findings"`
}

// Options controls the audit.
type Options struct {
	TrustedAccounts []string
	SelfAccount     string
	Ignore          map[string]bool
	MinSeverity     Severity
}

// Result is the whole audit.
type Result struct {
	Roles    []RoleReport `json:"roles"`
	Findings []Finding    `json:"findings"`
}

// Counts returns how many findings there are per severity.
func (r Result) Counts() (errors, warnings int) {
	for _, f := range r.Findings {
		if f.sev == Error {
			errors++
		} else {
			warnings++
		}
	}
	return
}

// Max returns the highest severity present, or 0 when the audit is clean.
func (r Result) Max() Severity {
	var max Severity
	for _, f := range r.Findings {
		if f.sev > max {
			max = f.sev
		}
	}
	return max
}

// Run audits the roles.
func Run(roles []iampolicy.Role, opt Options) Result {
	if opt.MinSeverity == 0 {
		opt.MinSeverity = Warning
	}
	res := Result{}
	for _, r := range roles {
		rep := auditRole(r, opt)
		res.Roles = append(res.Roles, rep)
		res.Findings = append(res.Findings, rep.Findings...)
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Role != b.Role {
			return a.Role < b.Role
		}
		if a.Statement != b.Statement {
			return a.Statement < b.Statement
		}
		return a.Rule < b.Rule
	})
	return res
}

func auditRole(r iampolicy.Role, opt Options) RoleReport {
	rep := RoleReport{Role: r.Name, Arn: r.Arn, AccountID: r.AccountID, File: r.File}
	self := opt.SelfAccount
	if self == "" {
		self = r.AccountID
	}
	trusted := map[string]bool{}
	for _, a := range opt.TrustedAccounts {
		trusted[a] = true
	}
	if self != "" {
		trusted[self] = true
	}

	allowCount := 0
	for i, st := range r.Trust.Statement {
		whos := resolvePrincipals(st.Principal)
		actions := append([]string(nil), st.Action...)
		conds := st.Condition.Flat()
		if st.Allows() {
			allowCount++
		}
		for _, w := range whos {
			rep.Assumers = append(rep.Assumers, Assumer{
				Statement: i, Effect: effect(st), Who: w, Actions: actions, Conditions: conds,
			})
		}
		if len(whos) == 0 {
			rep.Assumers = append(rep.Assumers, Assumer{
				Statement: i, Effect: effect(st),
				Who:     Who{Kind: KindUnknown, Value: "(no principal)"},
				Actions: actions, Conditions: conds,
			})
		}
		if !st.Allows() {
			continue
		}
		rep.Findings = append(rep.Findings, statementFindings(r, i, st, whos, trusted, self, opt)...)
	}

	if allowCount == 0 {
		rep.Findings = append(rep.Findings, finding(RuleDenyOnlyTrust, Warning, r, 0, "",
			"every statement is a Deny, so no principal can assume this role"))
	}

	rep.Findings = filter(rep.Findings, opt)
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		if rep.Findings[i].Statement != rep.Findings[j].Statement {
			return rep.Findings[i].Statement < rep.Findings[j].Statement
		}
		return rep.Findings[i].Rule < rep.Findings[j].Rule
	})
	return rep
}

func statementFindings(r iampolicy.Role, idx int, st iampolicy.Statement, whos []Who,
	trusted map[string]bool, self string, opt Options) []Finding {

	var out []Finding
	add := func(rule string, sev Severity, principal, msg string) {
		f := finding(rule, sev, r, idx, principal, msg)
		out = append(out, f)
	}

	for _, a := range st.Action {
		if a == "*" || strings.EqualFold(a, "sts:*") {
			add(RuleWildcardPrincipal, Error, "",
				fmt.Sprintf("action %q grants every sts call on this role, including TagSession and SetSourceIdentity", a))
			break
		}
	}

	hasExternalID := st.Condition.Has("sts:ExternalId")
	hasMFA := st.Condition.Has("aws:MultiFactorAuthPresent")

	for _, w := range whos {
		switch w.Kind {
		case KindWildcard:
			add(RuleWildcardPrincipal, Error, w.Value,
				"principal is \"*\": any AWS identity that can reach sts:AssumeRole may become this role")
		case KindOIDC:
			out = append(out, oidcFindings(r, idx, st, w)...)
		case KindIAMUser:
			if !hasMFA {
				add(RuleNoMFACondition, Warning, w.Value,
					"IAM user principal with no aws:MultiFactorAuthPresent condition: a leaked long-lived key is enough")
			}
		}
		if w.Kind == KindAccountRoot {
			add(RuleRootPrincipal, Warning, w.Value,
				"account-root principal: every identity in "+w.AccountID+" that is allowed sts:AssumeRole by its own policies may assume this role")
		}
		if w.InAccount() && w.AccountID != self {
			if !hasExternalID {
				add(RuleCrossAccountNoEID, Error, w.Value,
					"account "+w.AccountID+" is external and the statement has no sts:ExternalId condition (confused-deputy)")
			}
			if len(opt.TrustedAccounts) > 0 && !trusted[w.AccountID] {
				add(RuleUntrustedAccount, Warning, w.Value,
					"account "+w.AccountID+" is not in --trusted-accounts")
			}
		}
	}
	return out
}

func oidcFindings(r iampolicy.Role, idx int, st iampolicy.Statement, w Who) []Finding {
	subs := st.Condition.Lookup(":sub")
	if len(subs) == 0 {
		return []Finding{finding(RuleOIDCWildcardSub, Error, r, idx, w.Value,
			"web-identity principal with no :sub condition: any token from this provider may assume the role")}
	}
	var out []Finding
	for _, c := range subs {
		for _, v := range c.Values {
			if !strings.Contains(v, "*") {
				continue
			}
			out = append(out, finding(RuleOIDCWildcardSub, Error, r, idx, w.Value,
				fmt.Sprintf("%s %s=%q %s", c.Operator, c.Key, v, subScope(v))))
		}
	}
	return out
}

// subScope describes what the wildcard actually opens up, which is the part a
// reviewer gets wrong: a wildcard in the repository segment is a different
// problem from one in the ref segment.
func subScope(sub string) string {
	body := strings.TrimPrefix(sub, "repo:")
	seg := strings.SplitN(body, ":", 2)
	repoPart := seg[0]
	if strings.Contains(repoPart, "*") {
		return "matches every repository covered by the pattern"
	}
	return "matches every branch, tag, environment and pull request of " + repoPart
}

func effect(st iampolicy.Statement) string {
	if st.Effect == "" {
		return "Allow"
	}
	return st.Effect
}

func finding(rule string, sev Severity, r iampolicy.Role, idx int, principal, msg string) Finding {
	return Finding{
		Rule: rule, Severity: sev.String(), Role: r.Name, File: r.File,
		Statement: idx, Principal: principal, Message: msg, sev: sev,
	}
}

func filter(in []Finding, opt Options) []Finding {
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		if opt.Ignore[f.Rule] {
			continue
		}
		if f.sev < opt.MinSeverity {
			continue
		}
		out = append(out, f)
	}
	return out
}
