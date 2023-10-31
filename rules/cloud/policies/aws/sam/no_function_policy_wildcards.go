package sam

import (
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/rules"
	"github.com/aquasecurity/trivy-policies/rules/cloud/policies/aws"
)

var CheckNoFunctionPolicyWildcards = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0114",
		Provider:    providers.AWSProvider,
		Service:     "sam",
		ShortCode:   "no-function-policy-wildcards",
		Summary:     "Function policies should avoid use of wildcards and instead apply the principle of least privilege",
		Impact:      "Overly permissive policies may grant access to sensitive resources",
		Resolution:  "Specify the exact permissions required, and to which resources they should apply instead of using wildcards.",
		Explanation: `You should use the principle of least privilege when defining your IAM policies. This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.`,
		Links: []string{
			"https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-function.html#sam-function-policies",
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoFunctionPolicyWildcardsGoodExamples,
			BadExamples:         cloudFormationNoFunctionPolicyWildcardsBadExamples,
			Links:               cloudFormationNoFunctionPolicyWildcardsLinks,
			RemediationMarkdown: cloudFormationNoFunctionPolicyWildcardsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) scan.Results {
		checker := aws.PolicyChecker{}

		var results scan.Results

		for _, function := range s.AWS.SAM.Functions {
			if function.Metadata.IsUnmanaged() {
				continue
			}
			results = append(results, checker.CheckWildcards(function.Policies)...)
		}
		return results
	},
)
