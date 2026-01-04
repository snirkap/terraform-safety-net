# Terraform Safety Net

A template repository demonstrating secure Terraform deployment practices with:

- **Plan Artifact Generation**: Terraform plan saved as a file for review and approval
- **Policy-as-Code**: OPA/Conftest policies enforce security rules before deployment
- **Cryptographic Signing**: Sigstore cosign keyless signing ensures plan integrity
- **Separation of Concerns**: Plan workflow (PR) vs Apply workflow (manual trigger)

## What This Demonstrates

```
+-----------------------------------------------------------------------+
|                        TERRAFORM SAFETY NET                           |
+-----------------------------------------------------------------------+
|                                                                       |
|   +-----------+     +-----------+     +-----------+     +-----------+ |
|   |  PR Opens | --> | terraform | --> |  Policy   | --> |   Sign    | |
|   |           |     |   plan    |     |   Check   |     |   Plan    | |
|   +-----------+     +-----------+     +-----------+     +-----------+ |
|                            |                |                 |       |
|                            v                v                 v       |
|                     +---------------------------------------------+   |
|                     |            Upload Artifacts                 |   |
|                     |   - tfplan (binary plan file)               |   |
|                     |   - tfplan.json (for policy checks)         |   |
|                     |   - tfplan.bundle (cosign signature)        |   |
|                     +---------------------------------------------+   |
|                                         |                             |
|   ======================================|===========================  |
|                                         |                             |
|                                         v                             |
|   +-----------+     +-----------+     +-----------+     +-----------+ |
|   |  Manual   | --> |  Download | --> |  Verify   | --> | terraform | |
|   |  Trigger  |     | Artifacts |     | Signature |     |   apply   | |
|   +-----------+     +-----------+     +-----------+     +-----------+ |
|                                                                       |
+-----------------------------------------------------------------------+
```

## Security Features

| Feature | Description |
|---------|-------------|
| **OIDC Authentication** | No long-lived AWS credentials; uses GitHub OIDC to assume IAM roles |
| **Policy-as-Code** | OPA/Rego policies block insecure configurations before deployment |
| **Signed Artifacts** | Cosign keyless signing ensures plan files haven't been tampered with |
| **Manual Apply** | Apply workflow requires explicit manual trigger with confirmation |
| **Immutable Plans** | Applies use saved plan files, not fresh plans |

## Repository Structure

```
terraform-safety-net/
├── README.md                          # This file
├── terraform/
│   ├── main.tf                        # Demo resources (S3 bucket, Security Group)
│   ├── versions.tf                    # Terraform and provider versions
│   ├── providers.tf                   # AWS provider configuration
│   └── backend.tf.example             # Remote backend template
├── policies/
│   └── terraform/
│       ├── deny_public_s3.rego        # Block public S3 buckets
│       ├── deny_sg_0_0_0_0.rego       # Block 0.0.0.0/0 on SSH/RDP
│       └── deny_iam_wildcards.rego    # Block IAM * wildcards
├── scripts/
│   ├── plan.sh                        # Run terraform init/plan
│   ├── policy_check.sh                # Run conftest policy checks
│   ├── sign_plan.sh                   # Sign plan with cosign
│   ├── verify_plan.sh                 # Verify plan signature
│   └── apply.sh                       # Apply the terraform plan
└── .github/workflows/
    ├── plan.yml                       # PR workflow: plan + policy + sign
    └── apply.yml                      # Manual workflow: verify + apply
```

## Prerequisites

### Tools

| Tool | Version | Installation |
|------|---------|--------------|
| Terraform | >= 1.5.0 | [terraform.io](https://developer.hashicorp.com/terraform/downloads) |
| Conftest | >= 0.46.0 | [conftest.dev](https://www.conftest.dev/install/) |
| Cosign | >= 2.0 | [sigstore.dev](https://docs.sigstore.dev/cosign/installation/) |
| AWS CLI | >= 2.0 | [aws.amazon.com](https://aws.amazon.com/cli/) |

### AWS Account Setup

#### Step 1: Create OIDC Identity Provider

**Via AWS Console:**
1. Go to **IAM** → **Identity providers** → **Add provider**
2. Select **OpenID Connect**
3. Enter:
   - **Provider URL**: `https://token.actions.githubusercontent.com`
   - **Audience**: `sts.amazonaws.com`
4. Click **Add provider**

**Or via AWS CLI:**
```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1 1c58a3a8518e8759bf075b76b750d4f2df264fcd
```

#### Step 2: Create IAM Role

**Via AWS Console:**
1. Go to **IAM** → **Roles** → **Create role**
2. Select **Web identity**
3. Choose:
   - **Identity provider**: `token.actions.githubusercontent.com`
   - **Audience**: `sts.amazonaws.com`
4. Click **Next**, then name the role: `github-actions-terraform-safety-net`
5. After creation, edit the trust policy to restrict to your repo:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::YOUR_ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:YOUR_ORG/terraform-safety-net:*"
        }
      }
    }
  ]
}
```

#### Step 3: Create and Attach IAM Policy

Create a policy named `terraform-safety-net-policy` with these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3BucketManagement",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketVersioning",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetEncryptionConfiguration",
        "s3:ListBucket",
        "s3:PutBucketAcl",
        "s3:PutBucketPolicy",
        "s3:PutBucketVersioning",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutEncryptionConfiguration",
        "s3:GetBucketTagging",
        "s3:PutBucketTagging",
        "s3:GetBucketCORS",
        "s3:GetBucketWebsite",
        "s3:GetBucketLogging",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetAccelerateConfiguration",
        "s3:GetBucketRequestPayment",
        "s3:GetLifecycleConfiguration",
        "s3:GetReplicationConfiguration",
        "s3:GetBucketLocation"
      ],
      "Resource": "arn:aws:s3:::terraform-safety-net-demo-*"
    },
    {
      "Sid": "SecurityGroupManagement",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateSecurityGroup",
        "ec2:DeleteSecurityGroup",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSecurityGroupRules",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:CreateTags",
        "ec2:DeleteTags"
      ],
      "Resource": "*"
    },
    {
      "Sid": "VPCRead",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeVpcAttribute",
        "ec2:DescribeAccountAttributes"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CallerIdentity",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    }
  ]
}
```

Attach this policy to the role created in Step 2.

#### Step 4: Configure GitHub Repository

1. Go to your repo → **Settings** → **Secrets and variables** → **Actions**
2. Add secret: `AWS_ROLE_ARN` = `arn:aws:iam::YOUR_ACCOUNT_ID:role/github-actions-terraform-safety-net`
3. Add variable: `AWS_REGION` = `us-east-1` (or your preferred region)

## Usage

### Initial Setup (Demo Fails First)

The demo is designed to **fail initially** to demonstrate the policy enforcement:

1. **Fork or clone this repository**

2. **Create a pull request** with any change (or trigger the plan workflow manually)

3. **Observe the failure**:
   ```
   FAIL - terraform/tfplan.json - terraform - Security group 'aws_security_group.demo'
          allows ingress on port 22 from 0.0.0.0/0. Restrict to specific IP ranges.
   ```

4. **Fix the violation** in `terraform/main.tf`:

   Change:
   ```hcl
   cidr_blocks = ["0.0.0.0/0"]  # <- POLICY VIOLATION
   ```

   To:
   ```hcl
   cidr_blocks = ["10.0.0.0/8"]  # <- Compliant: private network only
   ```

5. **Push the fix** and watch the workflow pass

### Running Locally

```bash
# 1. Initialize and create plan
./scripts/plan.sh

# 2. Run policy checks (will fail with insecure config)
./scripts/policy_check.sh
# ERROR: Security group allows ingress on port 22 from 0.0.0.0/0

# 3. Fix terraform/main.tf (change 0.0.0.0/0 to 10.0.0.0/8)

# 4. Re-run plan and policy check
./scripts/plan.sh
./scripts/policy_check.sh
# SUCCESS: All policy checks passed!

# 5. Sign the plan (requires OIDC identity - in CI this is automatic)
./scripts/sign_plan.sh

# 6. Verify the signature
./scripts/verify_plan.sh

# 7. Apply the plan
./scripts/apply.sh
```

### GitHub Actions Workflows

#### Plan Workflow (`.github/workflows/plan.yml`)

Triggers on:
- Pull requests to `main`/`master`
- Manual trigger (workflow_dispatch)

Steps:
1. Checkout code
2. Setup Terraform
3. Configure AWS credentials (OIDC)
4. `terraform init`
5. `terraform fmt -check`
6. `terraform validate`
7. `terraform plan -out=tfplan`
8. `terraform show -json tfplan > tfplan.json`
9. `conftest test tfplan.json` (policy check)
10. `cosign sign-blob tfplan` (keyless signing)
11. Upload artifacts (tfplan, tfplan.json, tfplan.bundle)

#### Apply Workflow (`.github/workflows/apply.yml`)

Triggers on:
- Manual trigger only (workflow_dispatch)
- Requires typing "apply" to confirm

Steps:
1. Download artifacts from plan workflow
2. Install cosign
3. `cosign verify-blob tfplan` (verify signature)
4. Configure AWS credentials (OIDC)
5. `terraform init`
6. `terraform apply tfplan`

## Policies

### deny_public_s3.rego

Ensures S3 buckets have all public access block settings enabled:

- `block_public_acls = true`
- `block_public_policy = true`
- `ignore_public_acls = true`
- `restrict_public_buckets = true`

### deny_sg_0_0_0_0.rego

Prevents security groups from allowing inbound traffic from the entire internet on sensitive ports:

- Port 22 (SSH)
- Port 3389 (RDP)

Blocked CIDRs:
- `0.0.0.0/0`
- `::/0` (IPv6)

### deny_iam_wildcards.rego

Blocks overly permissive IAM policies:

- `Action: "*"` (allows all actions)
- `Resource: "*"` in Allow statements

## Fixing the Demo

The default configuration **intentionally fails** to demonstrate policy enforcement.

### Security Group Violation

**File**: `terraform/main.tf`

**Problem**:
```hcl
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]  # VIOLATION: Open to the world
}
```

**Fix Options**:

```hcl
# Option 1: Restrict to private network
cidr_blocks = ["10.0.0.0/8"]

# Option 2: Restrict to specific subnet
cidr_blocks = ["192.168.1.0/24"]

# Option 3: Restrict to single IP
cidr_blocks = ["203.0.113.50/32"]

# Option 4: Remove the ingress rule entirely
# (delete the entire ingress block)
```

## Signature Verification

For production, configure identity verification in the apply workflow:

```yaml
env:
  CERTIFICATE_IDENTITY: "https://github.com/YOUR_ORG/YOUR_REPO/.github/workflows/plan.yml@refs/heads/main"
  CERTIFICATE_OIDC_ISSUER: "https://token.actions.githubusercontent.com"
```

This ensures only plans signed by your specific workflow can be applied.

## Customization

### Adding New Policies

1. Create a new `.rego` file in `policies/terraform/`
2. Use the `package terraform` package name
3. Define `deny` rules that return error messages
4. The policy will automatically be included in checks

Example policy:
```rego
package terraform

import rego.v1

deny contains msg if {
    some resource in input.resource_changes
    resource.type == "aws_instance"
    resource.change.after.instance_type == "t2.micro"
    msg := sprintf(
        "Instance '%s' uses t2.micro. Use t3.micro or larger.",
        [resource.address]
    )
}
```

### Configuring Remote Backend

1. Create an S3 bucket for state storage
2. Create a DynamoDB table for state locking
3. Copy `terraform/backend.tf.example` to `terraform/backend.tf`
4. Update the values with your bucket and table names

## Troubleshooting

### Policy check fails with "conftest not found"

Install conftest:
```bash
# macOS
brew install conftest

# Linux
wget https://github.com/open-policy-agent/conftest/releases/download/v0.46.0/conftest_0.46.0_Linux_x86_64.tar.gz
tar xzf conftest_0.46.0_Linux_x86_64.tar.gz
sudo mv conftest /usr/local/bin/
```

### Cosign signing fails locally

Keyless signing requires an OIDC identity. In GitHub Actions, this is automatic. Locally:

```bash
# Option 1: Use browser-based OIDC (opens browser)
cosign sign-blob --yes --bundle tfplan.bundle tfplan

# Option 2: Use a key pair for local testing
cosign generate-key-pair
cosign sign-blob --key cosign.key --bundle tfplan.bundle tfplan
```

### AWS credentials not configured

Ensure you've:
1. Created the OIDC identity provider in AWS
2. Created the IAM role with correct trust policy
3. Added `AWS_ROLE_ARN` secret to GitHub
4. Uncommented the AWS authentication step in workflows

### Terraform init fails

If using a remote backend, ensure:
1. The S3 bucket exists
2. The DynamoDB table exists
3. Your IAM role has permissions to access them

For local testing, you can use local state (no backend.tf needed).

## Security Best Practices

1. **Never commit secrets**: Use OIDC, not access keys
2. **Pin versions**: Lock Terraform and provider versions
3. **Review before apply**: The manual trigger prevents accidental deployments
4. **Verify signatures**: Always verify plan signatures before applying
5. **Least privilege**: Grant minimum required permissions to IAM roles
6. **Branch protection**: Require PR reviews before merging
7. **Audit logs**: Monitor CloudTrail for Terraform operations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run policy checks locally
5. Submit a pull request