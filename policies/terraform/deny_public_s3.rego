# =============================================================================
# Policy: Deny Public S3 Buckets
# =============================================================================
# This policy ensures that all S3 buckets have public access properly blocked.
# It checks the aws_s3_bucket_public_access_block resource to verify that
# all four public access block settings are enabled.
# =============================================================================

package terraform

# Deny if any S3 public access block has block_public_acls set to false
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.after.block_public_acls == false
    msg := sprintf(
        "S3 bucket '%s' has block_public_acls disabled. Enable it to prevent public ACLs.",
        [resource.change.after.bucket]
    )
}

# Deny if any S3 public access block has block_public_policy set to false
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.after.block_public_policy == false
    msg := sprintf(
        "S3 bucket '%s' has block_public_policy disabled. Enable it to prevent public bucket policies.",
        [resource.change.after.bucket]
    )
}

# Deny if any S3 public access block has ignore_public_acls set to false
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.after.ignore_public_acls == false
    msg := sprintf(
        "S3 bucket '%s' has ignore_public_acls disabled. Enable it to ignore public ACLs.",
        [resource.change.after.bucket]
    )
}

# Deny if any S3 public access block has restrict_public_buckets set to false
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.after.restrict_public_buckets == false
    msg := sprintf(
        "S3 bucket '%s' has restrict_public_buckets disabled. Enable it to restrict public bucket access.",
        [resource.change.after.bucket]
    )
}
