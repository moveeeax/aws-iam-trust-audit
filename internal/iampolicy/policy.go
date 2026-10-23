// Package iampolicy parses IAM trust policy documents and the AWS CLI
// responses that carry them.
//
// IAM policy JSON is polymorphic in a way encoding/json does not handle on its
// own: Action, Resource and the values inside Principal are a bare string when
// there is one of them and an array when there are several, and Statement is
// either a single object or a list. Every type here decodes both shapes into
// the array form so the rest of the program only sees slices.
package iampolicy

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// StringOrSlice decodes a JSON string or an array of strings.
type StringOrSlice []string

func (s *StringOrSlice) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = StringOrSlice{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("expected a string or an array of strings, got %s", snippet(b))
	}
	*s = many
	return nil
}

// Principal is the "who" of a trust statement. It is either the bare string
// "*" or a map keyed by principal type (AWS, Service, Federated, CanonicalUser).
type Principal struct {
	Wildcard bool
	ByType   map[string]StringOrSlice
}

func (p *Principal) UnmarshalJSON(b []byte) error {
	p.ByType = map[string]StringOrSlice{}
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		if one == "*" {
			p.Wildcard = true
		} else {
			// Not legal IAM, but seen in hand-written files. Read it as an
			// AWS principal rather than refusing the whole document.
			p.ByType["AWS"] = StringOrSlice{one}
		}
		return nil
	}
	raw := map[string]StringOrSlice{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("expected \"*\" or an object of principal types, got %s", snippet(b))
	}
	for k, v := range raw {
		p.ByType[canonicalType(k)] = v
	}
	return nil
}

// Empty reports whether the statement named no principal at all.
func (p *Principal) Empty() bool {
	return p == nil || (!p.Wildcard && len(p.ByType) == 0)
}

func canonicalType(k string) string {
	switch strings.ToLower(k) {
	case "aws":
		return "AWS"
	case "service":
		return "Service"
	case "federated":
		return "Federated"
	case "canonicaluser":
		return "CanonicalUser"
	}
	return k
}

// Condition is the raw condition block: operator -> key -> values.
type Condition map[string]map[string]StringOrSlice

// Lookup finds condition values by key, ignoring case and the operator. The key
// may be given fully ("token.actions.githubusercontent.com:sub") or as a
// suffix (":sub"), which is how the OIDC rules ask for a claim regardless of
// which provider issued it.
func (c Condition) Lookup(key string) []ConditionEntry {
	var out []ConditionEntry
	want := strings.ToLower(key)
	for op, kv := range c {
		for k, vals := range kv {
			lk := strings.ToLower(k)
			if lk == want || (strings.HasPrefix(want, ":") && strings.HasSuffix(lk, want)) {
				out = append(out, ConditionEntry{Operator: op, Key: k, Values: vals})
			}
		}
	}
	return out
}

// Has reports whether any condition constrains the given key.
func (c Condition) Has(key string) bool { return len(c.Lookup(key)) > 0 }

// ConditionEntry is one resolved operator/key/values triple.
type ConditionEntry struct {
	Operator string
	Key      string
	Values   []string
}

func (e ConditionEntry) String() string {
	return fmt.Sprintf("%s %s=%s", e.Operator, e.Key, strings.Join(e.Values, "|"))
}

// Flat returns every condition as a stable, printable list.
func (c Condition) Flat() []ConditionEntry {
	var out []ConditionEntry
	for op, kv := range c {
		for k, vals := range kv {
			out = append(out, ConditionEntry{Operator: op, Key: k, Values: vals})
		}
	}
	sortEntries(out)
	return out
}

// Statement is one trust policy statement.
type Statement struct {
	Sid          string        `json:"Sid"`
	Effect       string        `json:"Effect"`
	Principal    *Principal    `json:"Principal"`
	NotPrincipal *Principal    `json:"NotPrincipal"`
	Action       StringOrSlice `json:"Action"`
	NotAction    StringOrSlice `json:"NotAction"`
	Condition    Condition     `json:"Condition"`
}

// Allows reports whether the statement is an Allow (the default when an
// obviously malformed document omits Effect is to treat it as Allow, because
// an auditor should look at it rather than skip it).
func (s Statement) Allows() bool { return !strings.EqualFold(s.Effect, "Deny") }

// Statements decodes either a single statement object or an array of them.
type Statements []Statement

func (s *Statements) UnmarshalJSON(b []byte) error {
	trimmed := strings.TrimSpace(string(b))
	if strings.HasPrefix(trimmed, "{") {
		var one Statement
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*s = Statements{one}
		return nil
	}
	var many []Statement
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// Document is a trust policy document.
type Document struct {
	Version   string     `json:"Version"`
	ID        string     `json:"Id"`
	Statement Statements `json:"Statement"`
}

// ParseDocument reads a trust policy document from raw JSON.
func ParseDocument(b []byte) (*Document, error) {
	var d Document
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	if len(d.Statement) == 0 {
		return nil, fmt.Errorf("policy document has no Statement")
	}
	return &d, nil
}

// parseEmbeddedDocument reads AssumeRolePolicyDocument, which the API returns
// as a URL-encoded string and the CLI as a decoded object depending on how it
// was captured.
func parseEmbeddedDocument(raw json.RawMessage) (*Document, error) {
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		decoded, err := url.QueryUnescape(asString)
		if err != nil {
			decoded = asString
		}
		return ParseDocument([]byte(decoded))
	}
	return ParseDocument(raw)
}

func snippet(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 60 {
		s = s[:60] + "..."
	}
	return s
}
