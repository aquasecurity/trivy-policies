package gke

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/gke"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckUseServiceAccount(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster node config with default service account",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:              trivyTypes.NewTestMetadata(),
						RemoveDefaultNodePool: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						NodeConfig: gke.NodeConfig{
							Metadata:       trivyTypes.NewTestMetadata(),
							ServiceAccount: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster node config with service account provided",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:              trivyTypes.NewTestMetadata(),
						RemoveDefaultNodePool: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						NodeConfig: gke.NodeConfig{
							Metadata:       trivyTypes.NewTestMetadata(),
							ServiceAccount: trivyTypes.String("service-account", trivyTypes.NewTestMetadata()),
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
			testState.Google.GKE = test.input
			results := CheckUseServiceAccount.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckUseServiceAccount.LongID() {
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
