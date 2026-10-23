package iampolicy

import (
	"path/filepath"
	"testing"
)

func TestStringOrSliceBothShapes(t *testing.T) {
	doc, err := ParseDocument([]byte(`{"Statement":[
	  {"Effect":"Allow","Action":"sts:AssumeRole"},
	  {"Effect":"Allow","Action":["sts:AssumeRole","sts:TagSession"]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Statement[0].Action) != 1 || doc.Statement[0].Action[0] != "sts:AssumeRole" {
		t.Fatalf("single action decoded as %v", doc.Statement[0].Action)
	}
	if len(doc.Statement[1].Action) != 2 {
		t.Fatalf("array action decoded as %v", doc.Statement[1].Action)
	}
}

func TestStatementSingleObject(t *testing.T) {
	doc, err := ParseDocument([]byte(`{"Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Statement) != 1 {
		t.Fatalf("statements = %d, want 1", len(doc.Statement))
	}
	if !doc.Statement[0].Principal.Wildcard {
		t.Fatal("bare \"*\" principal should decode as a wildcard")
	}
}

func TestPrincipalTypesAreCanonicalised(t *testing.T) {
	doc, err := ParseDocument([]byte(`{"Statement":[{"Effect":"Allow",
	  "Principal":{"service":["ec2.amazonaws.com","ssm.amazonaws.com"],"aws":"111122223333"},
	  "Action":"sts:AssumeRole"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	p := doc.Statement[0].Principal
	if len(p.ByType["Service"]) != 2 {
		t.Fatalf("Service = %v", p.ByType["Service"])
	}
	if len(p.ByType["AWS"]) != 1 {
		t.Fatalf("AWS = %v", p.ByType["AWS"])
	}
}

func TestBadPrincipalValueIsAParseError(t *testing.T) {
	if _, err := ParseDocument([]byte(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":12345}}]}`)); err == nil {
		t.Fatal("a numeric principal value should not parse")
	}
}

func TestDocumentWithoutStatementFails(t *testing.T) {
	if _, err := ParseDocument([]byte(`{"Version":"2012-10-17"}`)); err == nil {
		t.Fatal("a document with no Statement should fail")
	}
}

func TestConditionLookupIsCaseAndOperatorInsensitive(t *testing.T) {
	doc, err := ParseDocument([]byte(`{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole",
	  "Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:org/app:*"},
	               "Bool":{"aws:multifactorauthpresent":"true"}}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	c := doc.Statement[0].Condition
	if !c.Has("aws:MultiFactorAuthPresent") {
		t.Fatal("MFA condition should be found regardless of key case")
	}
	subs := c.Lookup(":sub")
	if len(subs) != 1 || subs[0].Operator != "StringLike" {
		t.Fatalf("sub lookup = %+v", subs)
	}
	if c.Has("sts:ExternalId") {
		t.Fatal("ExternalId is absent and must not be reported")
	}
	if got := len(c.Flat()); got != 2 {
		t.Fatalf("Flat() = %d entries, want 2", got)
	}
}

func TestLoadURLEncodedAssumeRolePolicyDocument(t *testing.T) {
	roles, err := LoadFile(filepath.Join("..", "audit", "testdata", "roles", "admin-sts-star.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 {
		t.Fatalf("roles = %d, want 1", len(roles))
	}
	r := roles[0]
	if r.Name != "LegacyAdmin" || r.AccountID != "111122223333" {
		t.Fatalf("role = %+v", r)
	}
	if r.Trust.Statement[0].Action[0] != "sts:*" {
		t.Fatalf("action = %v", r.Trust.Statement[0].Action)
	}
}

func TestLoadListRolesResponse(t *testing.T) {
	roles, err := LoadFile(filepath.Join("..", "audit", "testdata", "list-roles.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 2 {
		t.Fatalf("roles = %d, want 2", len(roles))
	}
	if roles[0].Name != "AppRole" || roles[1].Name != "PartnerRole" {
		t.Fatalf("names = %q, %q", roles[0].Name, roles[1].Name)
	}
}

func TestLoadBareDocumentUsesFileName(t *testing.T) {
	roles, err := LoadFile(filepath.Join("..", "audit", "testdata", "roles", "ec2-app.json"))
	if err != nil {
		t.Fatal(err)
	}
	if roles[0].Name != "ec2-app" {
		t.Fatalf("name = %q, want ec2-app", roles[0].Name)
	}
}

func TestLoadDirRejectsABrokenFile(t *testing.T) {
	if _, err := LoadDir(filepath.Join("..", "audit", "testdata", "broken")); err == nil {
		t.Fatal("a malformed policy must surface as an error, not as zero findings")
	}
}

func TestAccountFromArn(t *testing.T) {
	if got := AccountFromArn("arn:aws:iam::111122223333:role/App"); got != "111122223333" {
		t.Fatalf("got %q", got)
	}
	if got := AccountFromArn("ec2.amazonaws.com"); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}
