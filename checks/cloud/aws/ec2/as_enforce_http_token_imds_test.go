package ec2

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ec2"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestASCheckIMDSAccessRequiresToken(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "Launch configuration with optional tokens",
			input: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     trivyTypes.NewTestMetadata(),
							HttpTokens:   trivyTypes.String("optional", trivyTypes.NewTestMetadata()),
							HttpEndpoint: trivyTypes.String("enabled", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Launch template with optional tokens",
			input: ec2.EC2{
				LaunchTemplates: []ec2.LaunchTemplate{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Instance: ec2.Instance{
							Metadata: trivyTypes.NewTestMetadata(),
							MetadataOptions: ec2.MetadataOptions{
								Metadata:     trivyTypes.NewTestMetadata(),
								HttpTokens:   trivyTypes.String("optional", trivyTypes.NewTestMetadata()),
								HttpEndpoint: trivyTypes.String("enabled", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Launch configuration with required tokens",
			input: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     trivyTypes.NewTestMetadata(),
							HttpTokens:   trivyTypes.String("required", trivyTypes.NewTestMetadata()),
							HttpEndpoint: trivyTypes.String("enabled", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.EC2 = test.input
			results := CheckASIMDSAccessRequiresToken.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckASIMDSAccessRequiresToken.LongID() {
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
