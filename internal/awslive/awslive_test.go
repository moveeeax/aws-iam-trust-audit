package awslive

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// fakeIAM serves pre-built ListRoles pages keyed by the incoming Marker and
// records every request it sees.
type fakeIAM struct {
	pages map[string]*iam.ListRolesOutput
	calls []*iam.ListRolesInput
	err   error
}

func (f *fakeIAM) ListRoles(_ context.Context, in *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	f.calls = append(f.calls, in)
	if f.err != nil {
		return nil, f.err
	}
	return f.pages[aws.ToString(in.Marker)], nil
}

// encoded returns a trust document the way the API sends it: URL-encoded.
func encoded(doc string) *string { return aws.String(url.QueryEscape(doc)) }

func role(name, doc string) types.Role {
	return types.Role{
		RoleName:                 aws.String(name),
		Arn:                      aws.String("arn:aws:iam::111122223333:role/ci/" + name),
		Path:                     aws.String("/ci/"),
		AssumeRolePolicyDocument: encoded(doc),
	}
}

const ec2Trust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`
const openTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`

func TestLoadRolesFollowsPagesAndDecodes(t *testing.T) {
	fake := &fakeIAM{pages: map[string]*iam.ListRolesOutput{
		"": {
			Roles:       []types.Role{role("worker", ec2Trust)},
			IsTruncated: true,
			Marker:      aws.String("page2"),
		},
		"page2": {Roles: []types.Role{role("open", openTrust)}},
	}}
	roles, err := LoadRoles(context.Background(), fake, "/ci/")
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 2 {
		t.Fatalf("ListRoles calls = %d, want 2", len(fake.calls))
	}
	for _, in := range fake.calls {
		if aws.ToString(in.PathPrefix) != "/ci/" {
			t.Fatalf("PathPrefix = %q, want /ci/", aws.ToString(in.PathPrefix))
		}
		if aws.ToInt32(in.MaxItems) != pageSize {
			t.Fatalf("MaxItems = %d, want %d", aws.ToInt32(in.MaxItems), pageSize)
		}
	}
	if aws.ToString(fake.calls[1].Marker) != "page2" {
		t.Fatalf("second call marker = %q, want page2", aws.ToString(fake.calls[1].Marker))
	}
	if len(roles) != 2 {
		t.Fatalf("roles = %d, want 2", len(roles))
	}
	// Sorted by ARN, so "open" comes before "worker".
	if roles[0].Name != "open" || roles[1].Name != "worker" {
		t.Fatalf("order = %s, %s", roles[0].Name, roles[1].Name)
	}
	r := roles[0]
	if r.AccountID != "111122223333" || r.File != r.Arn {
		t.Fatalf("role = %+v, want account from ARN and File = ARN", r)
	}
	if got := r.Trust.Statement[0].Principal.ByType["AWS"]; len(got) != 1 || got[0] != "*" {
		t.Fatal("URL-encoded trust document was not decoded")
	}
}

func TestLoadRolesWithoutPathListsEverything(t *testing.T) {
	fake := &fakeIAM{pages: map[string]*iam.ListRolesOutput{"": {Roles: []types.Role{role("worker", ec2Trust)}}}}
	if _, err := LoadRoles(context.Background(), fake, ""); err != nil {
		t.Fatal(err)
	}
	if fake.calls[0].PathPrefix != nil {
		t.Fatalf("PathPrefix = %q, want unset", aws.ToString(fake.calls[0].PathPrefix))
	}
}

func TestLoadRolesErrors(t *testing.T) {
	denied := &fakeIAM{err: errors.New("AccessDenied")}
	if _, err := LoadRoles(context.Background(), denied, ""); err == nil || !strings.Contains(err.Error(), "iam:ListRoles") {
		t.Fatalf("err = %v, want the API error wrapped with the call name", err)
	}

	empty := &fakeIAM{pages: map[string]*iam.ListRolesOutput{"": {}}}
	if _, err := LoadRoles(context.Background(), empty, "/nothing/"); err == nil || !strings.Contains(err.Error(), "/nothing/") {
		t.Fatalf("err = %v, want an empty listing reported with the path", err)
	}

	bad := &fakeIAM{pages: map[string]*iam.ListRolesOutput{"": {Roles: []types.Role{role("broken", `{"Statement":`)}}}}
	if _, err := LoadRoles(context.Background(), bad, ""); err == nil || !strings.Contains(err.Error(), "broken") {
		t.Fatalf("err = %v, want the unparsable role named", err)
	}
}

func TestValidatePath(t *testing.T) {
	for _, ok := range []string{"", "/", "/ci/", "/team/app/"} {
		if err := ValidatePath(ok); err != nil {
			t.Fatalf("ValidatePath(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"ci", "/ci", "ci/"} {
		if err := ValidatePath(bad); err == nil {
			t.Fatalf("ValidatePath(%q) accepted", bad)
		}
	}
}
