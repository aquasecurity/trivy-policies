package compute

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/compute"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckDiskEncryptionRequired(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Disk with plaintext encryption key",
			input: compute.Compute{
				Disks: []compute.Disk{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata: trivyTypes.NewTestMetadata(),
							RawKey:   trivyTypes.Bytes([]byte("b2ggbm8gdGhpcyBpcyBiYWQ"), trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance disk with plaintext encryption key",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						BootDisks: []compute.Disk{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata: trivyTypes.NewTestMetadata(),
									RawKey:   trivyTypes.Bytes([]byte("b2ggbm8gdGhpcyBpcyBiYWQ"), trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Disks with no plaintext encryption keys",
			input: compute.Compute{
				Disks: []compute.Disk{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata: trivyTypes.NewTestMetadata(),
							RawKey:   trivyTypes.Bytes([]byte(""), trivyTypes.NewTestMetadata()),
						},
					},
				},
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						BootDisks: []compute.Disk{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata: trivyTypes.NewTestMetadata(),
									RawKey:   trivyTypes.Bytes([]byte(""), trivyTypes.NewTestMetadata()),
								},
							},
						},
						AttachedDisks: []compute.Disk{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata: trivyTypes.NewTestMetadata(),
									RawKey:   trivyTypes.Bytes([]byte(""), trivyTypes.NewTestMetadata()),
								},
							},
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
			testState.Google.Compute = test.input
			results := CheckDiskEncryptionRequired.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckDiskEncryptionRequired.LongID() {
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
