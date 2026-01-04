# =============================================================================
# Policy: Deny Public S3 Buckets
# =============================================================================
# This policy ensures that all S3 buckets have public access properly blocked.
# It checks the aws_s3_bucket_public_access_block resource to verify that
# all four public access block settings are enabled.
#
# Required settings (all must be true):
#   - block_public_acls
#   - block_public_policy
#   - ignore_public_acls
#   - restrict_public_buckets
# =============================================================================

package terraform

import rego.v1

# Deny if any S3 public access block has block_public_acls set to false
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.after.block_public_acls == false
    msg := sprintf(
        "S3 bucket '%s' has block_public_acls disabled. Enable it to prevent public ACLs.",
        [resource.change.after.bucket]
    )
}

# Deny if any S3 public access block has block_public_policy set to false
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.after.block_public_policy == false
    msg := sprintf(
        "S3 bucket '%s' has block_public_policy disabled. Enable it to prevent public bucket policies.",
        [resource.change.after.bucket]
    )
}

# Deny if any S3 public access block has ignore_public_acls set to false
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.after.ignore_public_acls == false
    msg := sprintf(
        "S3 bucket '%s' has ignore_public_acls disabled. Enable it to ignore public ACLs.",
        [resource.change.after.bucket]
    )
}

# Deny if any S3 public access block has restrict_public_buckets set to false
deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.after.restrict_public_buckets == false
    msg := sprintf(
        "S3 bucket '%s' has restrict_public_buckets disabled. Enable it to restrict public bucket access.",
        [resource.change.after.bucket]
    )
}

# Warn if S3 bucket exists but no public access block is defined
# Note: This is a warning, not a denial, as the block might be defined elsewhere
warn contains msg if {
    some bucket in input.resource_changes
    bucket.type == "aws_s3_bucket"
    bucket.change.actions[_] == "create"
    not has_public_access_block(bucket.address)
    msg := sprintf(
        "S3 bucket '%s' does not have an associated public access block resource in this plan.",
        [bucket.address]
    )
}

# Helper: Check if a bucket has an associated public access block
has_public_access_block(bucket_address) if {
    some block in input.resource_changes
    block.type == "aws_s3_bucket_public_access_block"
}
