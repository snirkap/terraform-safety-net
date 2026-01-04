#!/usr/bin/env bash
# =============================================================================
# Terraform Plan Script
# =============================================================================
# This script runs the Terraform planning workflow:
#   1. Initialize Terraform
#   2. Check formatting
#   3. Validate configuration
#   4. Generate plan file
#
# Usage: ./scripts/plan.sh [terraform_dir]
#   terraform_dir: Path to Terraform configuration (default: ./terraform)
#
# Output: Creates tfplan file in the terraform directory
# =============================================================================

set -euo pipefail

# Configuration
TERRAFORM_DIR="${1:-./terraform}"
PLAN_FILE="tfplan"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Change to terraform directory
if [[ ! -d "${TERRAFORM_DIR}" ]]; then
    log_error "Terraform directory not found: ${TERRAFORM_DIR}"
    exit 1
fi

cd "${TERRAFORM_DIR}"
log_info "Working directory: $(pwd)"

# Step 1: Initialize Terraform
log_info "Initializing Terraform..."
terraform init -input=false

# Step 2: Check formatting
log_info "Checking Terraform formatting..."
if ! terraform fmt -check -recursive -diff; then
    log_error "Terraform files are not properly formatted."
    log_info "Run 'terraform fmt -recursive' to fix formatting issues."
    exit 1
fi
log_success "Terraform formatting check passed."

# Step 3: Validate configuration
log_info "Validating Terraform configuration..."
terraform validate
log_success "Terraform configuration is valid."

# Step 4: Generate plan
log_info "Generating Terraform plan..."
terraform plan -input=false -out="${PLAN_FILE}"

# Verify plan file was created
if [[ -f "${PLAN_FILE}" ]]; then
    log_success "Plan file created: ${PLAN_FILE}"
    log_info "Plan file size: $(du -h "${PLAN_FILE}" | cut -f1)"
else
    log_error "Failed to create plan file."
    exit 1
fi

log_success "Terraform plan completed successfully!"
echo ""
log_info "Next steps:"
echo "  1. Run policy checks: ./scripts/policy_check.sh"
echo "  2. Sign the plan: ./scripts/sign_plan.sh"
