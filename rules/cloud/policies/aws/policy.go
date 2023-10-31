package aws

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/liamg/iamgo"
)

var (
	// The wildcard character (*) at the end of the Resource value means that the statement allows permission
	// for the logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents, and logs:DescribeLogStreams
	// actions on any log group
	//arn:aws:logs:us-west-2:123456789012:log-group:SampleLogGroupName:*
	cloudwatchLogStreamResourceRegex = regexp.MustCompile(`^arn:aws:logs:.*:.+:log-group:.+:\*`)
)

type PolicyChecker struct {
	results scan.Results
}

func (c *PolicyChecker) CheckWildcards(policies []iam.Policy) scan.Results {
	for _, policy := range policies {
		if policy.Builtin.IsTrue() {
			continue
		}
		statements, _ := policy.Document.Parsed.Statements()
		for _, statement := range statements {
			c.checkStatement(policy.Document, statement)
		}
	}

	return c.results
}

func (c *PolicyChecker) checkStatement(src iam.Document, statement iamgo.Statement) {
	effect, _ := statement.Effect()
	if effect != iamgo.EffectAllow {
		return
	}

	actions, r := statement.Actions()
	for _, action := range actions {
		if strings.Contains(action, "*") {
			c.results.Add(
				fmt.Sprintf("Policy document uses wildcarded action %v", actions),
				src.MetadataFromIamGo(statement.Range(), r),
			)
		} else {
			c.results.AddPassed(src)
		}
	}

	resources, r := statement.Resources()
	for _, resource := range resources {
		if resource == "*" {
			if actions, allowed := iam.IsWildcardAllowed(actions...); !allowed {
				c.results.Add(
					fmt.Sprintf("Policy document uses sensitive actions %v on wildcarded resource %q", actions, resource),
					src.MetadataFromIamGo(statement.Range(), r),
				)
			} else {
				c.results.AddPassed(src)
			}
		} else if strings.Contains(resource, "*") &&
			// allow all objects in the bucket to be specified
			!(strings.HasSuffix(resource, "/*") && strings.HasPrefix(resource, "arn:aws:s3")) &&
			!(cloudwatchLogStreamResourceRegex.MatchString(resource)) {
			c.results.Add(
				fmt.Sprintf("Policy document uses sensitive actions %v on wildcarded resource %q", actions, resource),
				src.MetadataFromIamGo(statement.Range(), r),
			)

		} else {
			c.results.AddPassed(src)
		}
	}
	principals, _ := statement.Principals()
	if all, r := principals.All(); all {
		c.results.Add(
			"Policy document uses wildcarded principal.",
			src.MetadataFromIamGo(statement.Range(), r),
		)
	}
	aws, r := principals.AWS()
	for _, principal := range aws {
		if strings.Contains(principal, "*") {
			c.results.Add(
				"Policy document uses wildcarded principal.",
				src.MetadataFromIamGo(statement.Range(), r),
			)
		} else {
			c.results.AddPassed(src)
		}
	}
}
