package appservice

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/appservice"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAuthenticationEnabled(t *testing.T) {
	tests := []struct {
		name     string
		input    appservice.AppService
		expected bool
	}{
		{
			name: "App service authentication disabled",
			input: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Authentication: struct{ Enabled trivyTypes.BoolValue }{
							Enabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "App service authentication enabled",
			input: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Authentication: struct{ Enabled trivyTypes.BoolValue }{
							Enabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
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
			testState.Azure.AppService = test.input
			results := CheckAuthenticationEnabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAuthenticationEnabled.LongID() {
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
