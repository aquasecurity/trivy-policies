package iam

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSetMinimumPasswordLength(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Minimum password length set to 8",
			input: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:      trivyTypes.NewTestMetadata(),
					MinimumLength: trivyTypes.Int(8, trivyTypes.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "Minimum password length set to 15",
			input: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:      trivyTypes.NewTestMetadata(),
					MinimumLength: trivyTypes.Int(15, trivyTypes.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := CheckSetMinimumPasswordLength.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSetMinimumPasswordLength.LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
