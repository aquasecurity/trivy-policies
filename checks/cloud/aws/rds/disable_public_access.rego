# METADATA
# title: "RDS Publicly Accessible"
# description: "Ensures RDS instances and RDS Cluster instances are not launched into the public cloud."
# scope: package
# schemas:
# - input: schema["cloud"]
# related_resources:
# - http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html
# custom:
#   avd_id: AVD-AWS-0180
#   provider: aws
#   service: rds
#   severity: HIGH
#   short_code: enable-public-access
#   recommended_action: "Remove the public endpoint from the RDS instance."
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: rds
#           provider: aws
#   terraform:
#       good_examples: "checks/cloud/aws/rds/disable_public_access.tf.go"
#   cloud_formation:
#       good_examples: "checks/cloud/aws/rds/disable_public_access.cf.go"

package builtin.aws.rds.aws0180

import data.lib.result

deny[res] {
	instance := input.aws.rds.instances[_]
	instance.publicaccess.value
	res := result.new("Instance has Public Access enabled", instance.publicaccess)
}

deny[res] {
	instance := input.aws.rds.clusters[_].instances[_].instance
	instance.publicaccess.value
	res := result.new("Cluster instance has Public Access enabled", instance.publicaccess)
}
