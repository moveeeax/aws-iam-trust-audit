package audit

import (
	"strings"
	"testing"

	"github.com/moveeeax/aws-iam-trust-audit/internal/iampolicy"
)

const (
	githubARN  = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
	gitlabARN  = "arn:aws:iam::111122223333:oidc-provider/gitlab.com"
	githubAud  = `"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"`
	githubSubK = `"token.actions.githubusercontent.com:sub"`
)

// webIdentity audits one AssumeRoleWithWebIdentity statement for the given
// federated principal and condition block.
func webIdentity(t *testing.T, principal, condition string) Result {
	t.Helper()
	doc, err := iampolicy.ParseDocument([]byte(`{"Statement":[{"Effect":"Allow",
	  "Principal":{"Federated":"` + principal + `"},
	  "Action":"sts:AssumeRoleWithWebIdentity",
	  "Condition":{` + condition + `}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return Run([]iampolicy.Role{{Name: "r", File: "r.json", Trust: doc}}, Options{})
}

func TestOIDCConditionIsEvaluatedNotJustPresent(t *testing.T) {
	for _, tc := range []struct {
		name      string
		principal string
		condition string
		want      string // substring of the single finding; "" means clean
	}{
		{"audience only", githubARN,
			`"StringEquals":{` + githubAud + `}`,
			"constrains :aud but has no :sub condition: the audience is the same for every repository"},
		{"negated sub", githubARN,
			`"StringEquals":{` + githubAud + `},"StringNotLike":{` + githubSubK + `:"repo:evil/*"}`,
			"StringNotLike token.actions.githubusercontent.com:sub only excludes values"},
		{"sub of another provider", githubARN,
			`"StringEquals":{` + githubAud + `,"gitlab.com:sub":"project_path:g/p:ref_type:branch:ref:main"}`,
			"gitlab.com:sub belongs to another provider"},
		{"star is literal under StringEquals", githubARN,
			`"StringEquals":{` + githubAud + `,` + githubSubK + `:"repo:moveeeax/*:*"}`,
			""},
		{"pinned with IfExists", githubARN,
			`"StringLikeIfExists":{` + githubSubK + `:"repo:moveeeax/app:ref:refs/heads/main"}`,
			""},
		{"trailing star after the ref", githubARN,
			`"StringLike":{` + githubSubK + `:"repo:moveeeax/app:ref:refs/heads/main*"}`,
			`starts with "ref:refs/heads/main", not only that one`},
		{"question mark is a wildcard too", githubARN,
			`"StringLike":{` + githubSubK + `:"repo:moveeeax/app:ref:refs/heads/v?"}`,
			`starts with "ref:refs/heads/v"`},
		{"every branch", githubARN,
			`"StringLike":{` + githubSubK + `:"repo:moveeeax/app:ref:refs/heads/*"}`,
			`matches every "ref:refs/heads/"* subject of moveeeax/app`},
		{"every owner", githubARN,
			`"StringLike":{` + githubSubK + `:"repo:*/app:*"}`,
			"repositories of every owner on GitHub Actions"},
		{"bare star", githubARN,
			`"StringLike":{` + githubSubK + `:"*"}`,
			"matches every sub this provider issues"},
		{"set operator", githubARN,
			`"ForAnyValue:StringLike":{` + githubSubK + `:["repo:moveeeax/app:ref:refs/heads/main","repo:moveeeax/*"]}`,
			"every repository covered by the pattern"},
		{"gitlab project wildcard", gitlabARN,
			`"StringLike":{"gitlab.com:sub":"project_path:group/*:ref_type:branch:ref:main"}`,
			"every repository covered by the pattern"},
		{"gitlab pinned", gitlabARN,
			`"StringEquals":{"gitlab.com:aud":"https://gitlab.com","gitlab.com:sub":"project_path:group/app:ref_type:branch:ref:main"}`,
			""},
		{"gitlab audience only", gitlabARN,
			`"StringEquals":{"gitlab.com:aud":"https://gitlab.com"}`,
			"same for every project"},
		{"generic issuer wildcard", "accounts.google.com",
			`"StringLike":{"accounts.google.com:sub":"1234*"}`,
			"every subject covered by the pattern"},
		{"cognito pinned through aud", "cognito-identity.amazonaws.com",
			`"StringEquals":{"cognito-identity.amazonaws.com:aud":"us-east-1:11111111-2222-3333-4444-555555555555"},` +
				`"ForAnyValue:StringLike":{"cognito-identity.amazonaws.com:amr":"authenticated"}`,
			""},
		{"cognito without aud", "cognito-identity.amazonaws.com",
			`"ForAnyValue:StringLike":{"cognito-identity.amazonaws.com:amr":"authenticated"}`,
			"no :aud condition"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := webIdentity(t, tc.principal, tc.condition)
			if tc.want == "" {
				wantRules(t, res)
				return
			}
			wantRules(t, res, RuleOIDCWildcardSub)
			if msg := res.Findings[0].Message; !strings.Contains(msg, tc.want) {
				t.Fatalf("message = %q, want it to contain %q", msg, tc.want)
			}
		})
	}
}

func TestOIDCIssuer(t *testing.T) {
	for in, want := range map[string]string{
		githubARN: "token.actions.githubusercontent.com",
		"arn:aws:iam::111122223333:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/ABC": "oidc.eks.eu-west-1.amazonaws.com/id/abc",
		"accounts.google.com": "accounts.google.com",
	} {
		if got := oidcIssuer(in); got != want {
			t.Fatalf("oidcIssuer(%q) = %q, want %q", in, got, want)
		}
	}
}
