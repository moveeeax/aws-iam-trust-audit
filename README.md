# aws-iam-trust-audit

[![ci](https://github.com/moveeeax/aws-iam-trust-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-iam-trust-audit/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Least-privilege tooling reads permission policies: what a role can do once you are it. The
trust policy decides **who gets to be it**, and it is the half that gets written once during
an integration and never reviewed again.

`aws-iam-trust-audit` reads trust policies — offline from JSON on disk, or live from IAM with
`--from-aws` — prints who may actually assume each role, and names what is too open.

## What it checks

| Rule | Severity | What it means |
| --- | --- | --- |
| `wildcard-principal` | error | `"Principal": {"AWS": "*"}`, or an action of `sts:*` / `*` |
| `cross-account-no-externalid` | error | an external account principal with no `sts:ExternalId` condition — the textbook confused deputy |
| `oidc-wildcard-sub` | error | a web-identity principal whose `:sub` claim is missing, only negated, or wildcarded (`repo:org/*:*` trusts every repo in the org; `ref:refs/heads/main*` also matches `main-anything`) |
| `untrusted-account` | warning | an account id outside `--trusted-accounts` |
| `root-principal` | warning | a bare `arn:aws:iam::<id>:root` principal |
| `no-mfa-condition` | warning | an IAM user principal with no `aws:MultiFactorAuthPresent` condition |
| `deny-only-trust` | warning | every statement is a `Deny`, so nothing can assume the role |

`aws-iam-trust-audit --rules` prints the same list.

## Install

```console
$ go install github.com/moveeeax/aws-iam-trust-audit/cmd/aws-iam-trust-audit@latest
```

Or build from a clone: `go build -o aws-iam-trust-audit ./cmd/aws-iam-trust-audit`.

## Usage

```console
$ aws-iam-trust-audit --dir examples/iam/roles --trusted-accounts 111122223333
WHO MAY ASSUME

  break-glass  (examples/iam/roles/break-glass.json)
    [iam-user]       arn:aws:iam::111122223333:user/oncall
        actions:    sts:AssumeRole
        conditions: none

  github-actions-deploy  (examples/iam/roles/github-actions-deploy.json)
    [federated-oidc] arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com
        actions:    sts:AssumeRoleWithWebIdentity
        conditions: StringEquals token.actions.githubusercontent.com:aud=sts.amazonaws.com; StringLike token.actions.githubusercontent.com:sub=repo:acme-corp/*:*

FINDINGS (2 error, 3 warning)

  ERROR   oidc-wildcard-sub
          role github-actions-deploy, statement 0 (examples/iam/roles/github-actions-deploy.json)
          principal arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com
          StringLike token.actions.githubusercontent.com:sub="repo:acme-corp/*:*" matches every repository covered by the pattern

  ERROR   cross-account-no-externalid
          role vendor-monitoring, statement 0 (examples/iam/roles/vendor-monitoring.json)
          principal arn:aws:iam::999988887777:root
          account 999988887777 is external and the statement has no sts:ExternalId condition (confused-deputy)
$ echo $?
1
```

More:

```console
$ aws-iam-trust-audit --dir ./iam --trusted-accounts 111122223333,444455556666 --fail-on error
$ aws-iam-trust-audit --dir ./iam --format markdown --ignore no-mfa-condition
$ aws-iam-trust-audit --dir ./iam --format json | jq '.summary'
$ aws-iam-trust-audit --dir ./iam --format sarif --fail-on never > trust-audit.sarif
```

### Reading roles live

`--from-aws` lists the roles with `iam:ListRoles`, which returns each trust policy in the
listing, so no `get-role` call per role is needed. Credentials come from the default AWS chain
(environment, shared config, SSO, instance or task role); `--profile` picks a shared-config
profile and `--role-path` limits the listing to one IAM path.

```console
$ aws-iam-trust-audit --from-aws --profile audit --role-path /ci/ --trusted-accounts 111122223333
```

The only permission it needs is `iam:ListRoles`. IAM is global, so the region does not
matter; when none is configured the client signs for `us-east-1`. Findings for live roles name
the role ARN where file-based runs name the file.

### OIDC trust

For a `Federated` web-identity principal the `oidc-wildcard-sub` rule reads the condition
block rather than checking that a `:sub` key is present somewhere:

- only `:sub` keys of the principal's own provider count. A condition on `gitlab.com:sub`
  does not narrow a `token.actions.githubusercontent.com` principal;
- negated operators (`StringNotEquals`, `StringNotLike`) and `Null` exclude values or test
  existence, they do not pin a subject, so a statement with only those is reported as having
  no `:sub` condition. A statement that pins `:aud` but not `:sub` gets its own message: the
  audience is the same for every repository on the issuer;
- `*` and `?` are wildcards only under `StringLike`. Under `StringEquals` they are literal
  characters and are not reported;
- for GitHub (`repo:owner/name:...`) and GitLab (`project_path:group/name:...`) subjects the
  message says which segment the wildcard opens: every owner, every repository, every ref, or
  every ref that merely starts with the pinned name;
- Cognito identity pools carry the identity id in `sub` and are pinned through `:aud`, so for
  `cognito-identity.amazonaws.com` the rule checks `:aud` instead.

### Input it accepts

Point `--dir` at a directory (walked recursively) or a single `.json` file. Each file may be:

- a bare trust policy document (`{"Version": ..., "Statement": [...]}`) — the file name becomes the role name;
- an `aws iam get-role` response (`{"Role": {...}}`);
- an `aws iam list-roles` response (`{"Roles": [...]}`);
- a plain array of role objects.

`AssumeRolePolicyDocument` is read either as an object or as the URL-encoded string the API
returns. No credentials, no network, no `terraform` binary — so the audit runs on committed
output or a saved API dump in CI.

```console
$ aws iam list-roles > /tmp/roles.json && aws-iam-trust-audit --dir /tmp/roles.json
```

### Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--dir` | `.` | directory or file of trust policy JSON |
| `--from-aws` | – | read roles live with `iam:ListRoles` instead of `--dir` |
| `--profile` | – | shared-config profile for `--from-aws` |
| `--role-path` | – | with `--from-aws`, only roles under this IAM path (`/ci/`) |
| `--format` | `table` | `table`, `json`, `markdown` or `sarif` (SARIF 2.1.0) |
| `--trusted-accounts` | – | account ids that are expected (repeatable or comma-separated) |
| `--account` | role ARN | the account that owns these roles, for the cross-account check |
| `--min-severity` | `warning` | report findings at this severity and above |
| `--ignore` | – | rule name to suppress (repeatable or comma-separated) |
| `--fail-on` | `error` | exit 1 when a finding reaches this severity, or `never` |
| `--rules` | – | list the rules and exit |

Exit codes: **0** clean, **1** findings at or above `--fail-on`, **2** a parse, usage or AWS
API error.

## As a GitHub Action

```yaml
- uses: moveeeax/aws-iam-trust-audit@v0.1.0
  with:
    dir: iam/roles
    format: markdown
    trusted-accounts: "111122223333,444455556666"
    fail-on: error
```

Outputs `exit-code`, `report` and `report-file` (the path of the rendered report), and writes
the report to the job summary.

To audit the account itself, configure credentials first and set `from-aws`:

```yaml
- uses: aws-actions/configure-aws-credentials@v6
  with:
    role-to-assume: arn:aws:iam::111122223333:role/trust-audit
    aws-region: us-east-1
- uses: moveeeax/aws-iam-trust-audit@v0.1.0
  with:
    from-aws: "true"
    role-path: /ci/
    trusted-accounts: "111122223333"
```

The job needs `id-token: write` for the OIDC credentials step. With `format: sarif`, the
`report-file` output can go straight to code scanning:

```yaml
- uses: moveeeax/aws-iam-trust-audit@v0.1.0
  id: trust
  continue-on-error: true
  with:
    dir: iam/roles
    format: sarif
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: ${{ steps.trust.outputs.report-file }}
```

## How it works

The whole program is static JSON reading plus seven rules. The only genuinely annoying part
is that IAM policy JSON is polymorphic: `Action`, `Resource` and the values inside `Principal`
are a bare string when there is one of them and an array when there are several, and
`Statement` is either an object or a list. `internal/iampolicy` decodes every one of those
shapes into the array form, so the rules never branch on it.

Each principal is then resolved to a kind — `service`, `account`, `account-root`, `iam-user`,
`iam-role`, `federated-oidc`, `federated-saml`, `wildcard` — because the kind is what decides
which rules even apply. An MFA condition is meaningless for `ec2.amazonaws.com`, and
"cross-account" only means something for an identity that lives in an account.

Condition lookups ignore the key's case and accept a suffix like `:sub`, so the OIDC rules
work for any identity provider rather than only GitHub's. The OIDC rule then checks the
operator and the key's provider prefix, as described under [OIDC trust](#oidc-trust).

## Not in scope (yet)

A graph of which accounts reach which roles, ranking findings by the permissions the role
carries, checking OIDC providers themselves (`iam:ListOpenIDConnectProviders`), and
cross-checking trust against CloudTrail `AssumeRole` events to flag trust that has never been
exercised.

## License

MIT — see [LICENSE](LICENSE).
