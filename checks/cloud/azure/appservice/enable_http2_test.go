package appservice

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/appservice"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableHttp2(t *testing.T) {
	tests := []struct {
		name     string
		input    appservice.AppService
		expected bool
	}{
		{
			name: "HTTP2 disabled",
			input: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       trivyTypes.BoolValue
							MinimumTLSVersion trivyTypes.StringValue
						}{
							EnableHTTP2: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "HTTP2 enabled",
			input: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       trivyTypes.BoolValue
							MinimumTLSVersion trivyTypes.StringValue
						}{
							EnableHTTP2: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
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
			results := CheckEnableHttp2.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableHttp2.LongID() {
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
