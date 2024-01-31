# METADATA
# custom:
#   library: true
package lib.result

new(message, metadata) := {
	"metadata": metadata,
	"msg": message,
}

is_managed(cause) := get_metadata(cause).managed

get_metadata(cause) := object.get(cause, "__defsec_metadata", cause)
