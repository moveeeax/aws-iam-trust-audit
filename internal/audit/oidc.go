package audit

import (
	"fmt"
	"strings"

	"github.com/moveeeax/aws-iam-trust-audit/internal/iampolicy"
)

// Well-known issuers whose subject claim has a documented shape.
const (
	issuerGitHub  = "token.actions.githubusercontent.com"
	issuerGitLab  = "gitlab.com"
	issuerCognito = "cognito-identity.amazonaws.com"
)

// oidcIssuer returns the provider URL a federated principal stands for, which
// is also the prefix of its condition keys: the part after "oidc-provider/" in
// an ARN, or the bare host ("accounts.google.com") as written.
func oidcIssuer(principal string) string {
	v := principal
	if i := strings.Index(v, ":oidc-provider/"); i >= 0 {
		v = v[i+len(":oidc-provider/"):]
	}
	return strings.ToLower(strings.TrimSuffix(v, "/"))
}

// baseOperator strips the set qualifier and the IfExists suffix, leaving the
// comparison itself: "ForAnyValue:StringLikeIfExists" becomes "StringLike".
func baseOperator(op string) string {
	if i := strings.LastIndex(op, ":"); i >= 0 {
		op = op[i+1:]
	}
	return strings.TrimSuffix(op, "IfExists")
}

// pinsValue reports whether the operator restricts the key to the listed
// values. A negated operator only excludes some values and Null only tests
// that the key exists, so neither pins a subject.
func pinsValue(op string) bool {
	base := strings.ToLower(baseOperator(op))
	return base != "null" && !strings.Contains(base, "not")
}

// matchesWildcards reports whether IAM expands * and ? for this operator. Under
// StringEquals they are literal characters.
func matchesWildcards(op string) bool {
	return strings.EqualFold(baseOperator(op), "StringLike")
}

func hasWildcard(v string) bool { return strings.ContainsAny(v, "*?") }

// ownKey reports whether a condition key belongs to the given issuer. A :sub
// key of another provider is not present in this provider's tokens, so it
// does not narrow who this principal admits.
func ownKey(key, issuer, claim string) bool {
	return issuer == "" || strings.EqualFold(key, issuer+":"+claim)
}

func oidcFindings(r iampolicy.Role, idx int, st iampolicy.Statement, w Who) []Finding {
	issuer := oidcIssuer(w.Value)
	// Cognito identity pools put the identity id in sub; the pool is pinned
	// through aud, which is the check AWS documents for them.
	claim := "sub"
	if issuer == issuerCognito {
		claim = "aud"
	}

	var pinned []iampolicy.ConditionEntry
	var notes []string
	for _, c := range st.Condition.Lookup(":" + claim) {
		switch {
		case !ownKey(c.Key, issuer, claim):
			notes = append(notes, fmt.Sprintf("%s belongs to another provider", c.Key))
		case !pinsValue(c.Operator):
			notes = append(notes, fmt.Sprintf("%s %s only excludes values, it does not pin one", c.Operator, c.Key))
		default:
			pinned = append(pinned, c)
		}
	}

	if len(pinned) == 0 {
		msg := fmt.Sprintf("web-identity principal with no :%s condition: any token from this provider may assume the role", claim)
		if claim == "sub" && hasOwn(st.Condition, issuer, "aud") {
			msg = "web-identity principal constrains :aud but has no :sub condition: the audience is the same for every " +
				subjectNoun(issuer) + " on this issuer, so any of them may assume the role"
		}
		if len(notes) > 0 {
			msg += " (" + strings.Join(notes, "; ") + ")"
		}
		return []Finding{finding(RuleOIDCWildcardSub, Error, r, idx, w.Value, msg)}
	}

	var out []Finding
	for _, c := range pinned {
		if !matchesWildcards(c.Operator) {
			continue
		}
		for _, v := range c.Values {
			if !hasWildcard(v) {
				continue
			}
			out = append(out, finding(RuleOIDCWildcardSub, Error, r, idx, w.Value,
				fmt.Sprintf("%s %s=%q %s", c.Operator, c.Key, v, subScope(issuer, claim, v))))
		}
	}
	return out
}

// hasOwn reports whether the statement pins claim for this issuer.
func hasOwn(c iampolicy.Condition, issuer, claim string) bool {
	for _, e := range c.Lookup(":" + claim) {
		if ownKey(e.Key, issuer, claim) && pinsValue(e.Operator) {
			return true
		}
	}
	return false
}

func subjectNoun(issuer string) string {
	switch issuer {
	case issuerGitHub:
		return "repository"
	case issuerGitLab:
		return "project"
	}
	return "workload"
}

// subScope describes what the wildcard actually opens up, which is the part a
// reviewer gets wrong: a wildcard in the repository segment is a different
// problem from one in the ref segment, and a trailing * after a ref name
// matches more than that ref.
func subScope(issuer, claim, sub string) string {
	if strings.Trim(sub, "*?") == "" {
		return "matches every " + claim + " this provider issues"
	}
	var prefix string
	switch {
	case strings.HasPrefix(sub, "repo:"):
		prefix = "repo:"
	case strings.HasPrefix(sub, "project_path:"):
		prefix = "project_path:"
	default:
		return "matches every subject covered by the pattern"
	}
	body := strings.TrimPrefix(sub, prefix)
	seg := strings.SplitN(body, ":", 2)
	repoPart := seg[0]
	if hasWildcard(repoPart) {
		if owner := strings.SplitN(repoPart, "/", 2)[0]; hasWildcard(owner) {
			return "matches repositories of every owner on " + issuerName(issuer)
		}
		return "matches every repository covered by the pattern"
	}
	rest := ""
	if len(seg) == 2 {
		rest = seg[1]
	}
	fixed := rest
	if i := strings.IndexAny(rest, "*?"); i >= 0 {
		fixed = rest[:i]
	}
	if fixed == "" {
		return "matches every branch, tag, environment and pull request of " + repoPart
	}
	if strings.HasSuffix(fixed, "/") || strings.HasSuffix(fixed, ":") {
		return fmt.Sprintf("matches every %q* subject of %s, including refs anyone with push access can create", fixed, repoPart)
	}
	return fmt.Sprintf("matches every subject of %s that starts with %q, not only that one (a trailing wildcard after a ref name also admits e.g. %s-anything)",
		repoPart, fixed, fixed)
}

func issuerName(issuer string) string {
	switch issuer {
	case issuerGitHub:
		return "GitHub Actions"
	case "":
		return "this issuer"
	}
	return issuer
}
