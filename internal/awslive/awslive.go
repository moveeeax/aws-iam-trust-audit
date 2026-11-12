// Package awslive reads role trust policies straight from IAM with
// iam:ListRoles, which returns every role's AssumeRolePolicyDocument in the
// listing itself, so one paginated call per 1000 roles is the whole cost.
package awslive

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/moveeeax/aws-iam-trust-audit/internal/iampolicy"
)

// pageSize is the largest MaxItems iam:ListRoles accepts.
const pageSize = 1000

// fallbackRegion is used when neither the profile nor the environment names
// a region. IAM is a global service, but the SDK still needs a region to
// resolve the endpoint and sign the request.
const fallbackRegion = "us-east-1"

// NewClient builds an IAM client from the default credential chain, or from
// the named shared-config profile when profile is not empty.
func NewClient(ctx context.Context, profile string) (*iam.Client, error) {
	var opts []func(*config.LoadOptions) error
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	if cfg.Region == "" {
		cfg.Region = fallbackRegion
	}
	return iam.NewFromConfig(cfg), nil
}

// ValidatePath checks a --role-path value against the shape IAM accepts for
// PathPrefix: "/" alone, or a string that starts and ends with "/".
func ValidatePath(p string) error {
	if p == "" || p == "/" {
		return nil
	}
	if !strings.HasPrefix(p, "/") || !strings.HasSuffix(p, "/") {
		return fmt.Errorf("role path %q must start and end with \"/\", e.g. /ci/", p)
	}
	return nil
}

// LoadRoles lists every role under pathPrefix ("" means all roles) and
// returns them sorted by ARN, so output is stable between runs.
func LoadRoles(ctx context.Context, client iam.ListRolesAPIClient, pathPrefix string) ([]iampolicy.Role, error) {
	in := &iam.ListRolesInput{MaxItems: aws.Int32(pageSize)}
	if pathPrefix != "" {
		in.PathPrefix = aws.String(pathPrefix)
	}
	var roles []iampolicy.Role
	pages := iam.NewListRolesPaginator(client, in)
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("iam:ListRoles: %w", err)
		}
		for _, r := range page.Roles {
			name, arn := aws.ToString(r.RoleName), aws.ToString(r.Arn)
			if r.AssumeRolePolicyDocument == nil {
				return nil, fmt.Errorf("iam:ListRoles: role %q came back without AssumeRolePolicyDocument", name)
			}
			role, err := iampolicy.RoleFromAPI(name, arn, *r.AssumeRolePolicyDocument)
			if err != nil {
				return nil, err
			}
			roles = append(roles, role)
		}
	}
	if len(roles) == 0 {
		where := "this account"
		if pathPrefix != "" {
			where = "path " + pathPrefix
		}
		return nil, fmt.Errorf("iam:ListRoles returned no roles under %s", where)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].Arn < roles[j].Arn })
	return roles, nil
}
