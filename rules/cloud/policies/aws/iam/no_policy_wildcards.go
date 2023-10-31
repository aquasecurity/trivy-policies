package iam

import (
	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/rules"
	"github.com/aquasecurity/trivy-policies/rules/cloud/policies/aws"
)

var CheckNoPolicyWildcards = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0057",
		Provider:  providers.AWSProvider,
		Service:   "iam",
		ShortCode: "no-policy-wildcards",
		Frameworks: map[framework.Framework][]string{
			framework.Default:     nil,
			framework.CIS_AWS_1_4: {"1.16"},
		},
		Summary:     "IAM policy should avoid use of wildcards and instead apply the principle of least privilege",
		Impact:      "Overly permissive policies may grant access to sensitive resources",
		Resolution:  "Specify the exact permissions required, and to which resources they should apply instead of using wildcards.",
		Explanation: `You should use the principle of least privilege when defining your IAM policies. This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPolicyWildcardsGoodExamples,
			BadExamples:         terraformNoPolicyWildcardsBadExamples,
			Links:               terraformNoPolicyWildcardsLinks,
			RemediationMarkdown: terraformNoPolicyWildcardsRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoPolicyWildcardsGoodExamples,
			BadExamples:         cloudFormationNoPolicyWildcardsBadExamples,
			Links:               cloudFormationNoPolicyWildcardsLinks,
			RemediationMarkdown: cloudFormationNoPolicyWildcardsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) scan.Results {
		checker := aws.PolicyChecker{}

		results := checker.CheckWildcards(s.AWS.IAM.Policies)
		for _, group := range s.AWS.IAM.Groups {
			results = append(results, checker.CheckWildcards(group.Policies)...)
		}
		for _, user := range s.AWS.IAM.Users {
			results = append(results, checker.CheckWildcards(user.Policies)...)
		}
		for _, role := range s.AWS.IAM.Roles {
			results = append(results, checker.CheckWildcards(role.Policies)...)
		}
		return results
	},
)
