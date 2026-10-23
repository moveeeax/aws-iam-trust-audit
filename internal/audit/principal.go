package audit

import (
	"sort"
	"strings"

	"github.com/moveeeax/aws-iam-trust-audit/internal/iampolicy"
)

// Principal kinds, as resolved from the raw principal string.
const (
	KindWildcard      = "wildcard"
	KindAccount       = "account"
	KindAccountRoot   = "account-root"
	KindIAMUser       = "iam-user"
	KindIAMRole       = "iam-role"
	KindAssumedRole   = "assumed-role"
	KindService       = "service"
	KindOIDC          = "federated-oidc"
	KindSAML          = "federated-saml"
	KindCanonicalUser = "canonical-user"
	KindUnknown       = "unknown"
)

// Who is one resolved principal: what it is, which account it belongs to and
// the literal value from the document.
type Who struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	AccountID string `json:"accountId,omitempty"`
	Type      string `json:"declaredType,omitempty"`
}

// Assumer is one principal of one statement together with the actions it is
// granted and the conditions that narrow it.
type Assumer struct {
	Statement  int                        `json:"statement"`
	Effect     string                     `json:"effect"`
	Who        Who                        `json:"who"`
	Actions    []string                   `json:"actions"`
	Conditions []iampolicy.ConditionEntry `json:"conditions,omitempty"`
}

// ConditionStrings renders the conditions for display.
func (a Assumer) ConditionStrings() []string {
	if len(a.Conditions) == 0 {
		return []string{"none"}
	}
	out := make([]string, 0, len(a.Conditions))
	for _, c := range a.Conditions {
		out = append(out, c.String())
	}
	return out
}

func resolvePrincipals(p *iampolicy.Principal) []Who {
	var out []Who
	if p == nil {
		return out
	}
	if p.Wildcard {
		return []Who{{Kind: KindWildcard, Value: "*", Type: "AWS"}}
	}
	types := make([]string, 0, len(p.ByType))
	for t := range p.ByType {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		for _, v := range p.ByType[t] {
			out = append(out, resolveOne(t, v))
		}
	}
	return out
}

func resolveOne(declared, value string) Who {
	w := Who{Value: value, Type: declared, AccountID: iampolicy.AccountFromArn(value)}
	switch declared {
	case "Service":
		w.Kind = KindService
		return w
	case "CanonicalUser":
		w.Kind = KindCanonicalUser
		return w
	case "Federated":
		switch {
		case strings.Contains(value, ":oidc-provider/"):
			w.Kind = KindOIDC
		case strings.Contains(value, ":saml-provider/"):
			w.Kind = KindSAML
		case strings.Contains(value, "."):
			// A bare provider host, e.g. "accounts.google.com".
			w.Kind = KindOIDC
		default:
			w.Kind = KindUnknown
		}
		return w
	}
	switch {
	case value == "*":
		w.Kind = KindWildcard
	case strings.HasSuffix(value, ":root"):
		w.Kind = KindAccountRoot
	case strings.Contains(value, ":user/"):
		w.Kind = KindIAMUser
	case strings.Contains(value, ":assumed-role/"):
		w.Kind = KindAssumedRole
	case strings.Contains(value, ":role/"):
		w.Kind = KindIAMRole
	case isAccountID(value):
		w.Kind = KindAccount
		w.AccountID = value
	default:
		w.Kind = KindUnknown
	}
	return w
}

// InAccount reports whether the principal is an identity inside some AWS
// account, which is what makes "cross-account" a meaningful question.
func (w Who) InAccount() bool {
	switch w.Kind {
	case KindAccount, KindAccountRoot, KindIAMUser, KindIAMRole, KindAssumedRole:
		return w.AccountID != ""
	}
	return false
}

func isAccountID(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
