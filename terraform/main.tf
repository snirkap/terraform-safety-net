# =============================================================================
# Terraform Safety Net - Demo Resources
# =============================================================================
# This configuration creates minimal AWS resources to demonstrate:
#   1. S3 bucket with public access block (policy-compliant)
#   2. Security Group with intentionally insecure rule (policy violation)
#
# The Security Group rule below violates the deny_sg_0_0_0_0.rego policy.
# To fix: Change the cidr_blocks to a specific IP range (e.g., "10.0.0.0/8")
# =============================================================================

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "aws_caller_identity" "current" {}

data "aws_vpc" "default" {
  default = true
}

# -----------------------------------------------------------------------------
# S3 Bucket - Compliant Example
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "demo" {
  bucket_prefix = "terraform-safety-net-demo-"

  tags = {
    Name        = "terraform-safety-net-demo"
    Description = "Demo bucket for Terraform Safety Net"
  }
}

# S3 Public Access Block - All settings enabled (policy-compliant)
resource "aws_s3_bucket_public_access_block" "demo" {
  bucket = aws_s3_bucket.demo.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Bucket Versioning - Best practice
resource "aws_s3_bucket_versioning" "demo" {
  bucket = aws_s3_bucket.demo.id

  versioning_configuration {
    status = "Enabled"
  }
}

# S3 Bucket Server-Side Encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "demo" {
  bucket = aws_s3_bucket.demo.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# -----------------------------------------------------------------------------
# Security Group - INTENTIONALLY INSECURE (for demo)
# -----------------------------------------------------------------------------
# WARNING: This configuration violates the deny_sg_0_0_0_0.rego policy!
#
# The ingress rule below allows SSH (port 22) from 0.0.0.0/0 (the entire internet).
# This is a common security misconfiguration that the policy check will catch.
#
# TO FIX: Change cidr_blocks to a specific IP range, for example:
#   cidr_blocks = ["10.0.0.0/8"]  # Private network only
#   cidr_blocks = ["192.168.1.0/24"]  # Specific subnet
#   cidr_blocks = ["203.0.113.50/32"]  # Single IP address
# -----------------------------------------------------------------------------

resource "aws_security_group" "demo" {
  name_prefix = "terraform-safety-net-demo-"
  description = "Demo security group for Terraform Safety Net"
  vpc_id      = data.aws_vpc.default.id

  # INSECURE: This rule allows SSH from anywhere (0.0.0.0/0)
  # This will FAIL the policy check until fixed!
  ingress {
    description = "SSH from anywhere - INSECURE"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"] # Fixed: Restricted to private network
  }

  # Egress rule - allow all outbound (common pattern)
  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "terraform-safety-net-demo"
    Description = "Demo security group - initially insecure for policy demo"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# -----------------------------------------------------------------------------
# Outputs
# -----------------------------------------------------------------------------

output "s3_bucket_name" {
  description = "Name of the demo S3 bucket"
  value       = aws_s3_bucket.demo.id
}

output "s3_bucket_arn" {
  description = "ARN of the demo S3 bucket"
  value       = aws_s3_bucket.demo.arn
}

output "security_group_id" {
  description = "ID of the demo security group"
  value       = aws_security_group.demo.id
}

output "security_group_name" {
  description = "Name of the demo security group"
  value       = aws_security_group.demo.name
}

output "aws_account_id" {
  description = "AWS Account ID where resources are deployed"
  value       = data.aws_caller_identity.current.account_id
}
