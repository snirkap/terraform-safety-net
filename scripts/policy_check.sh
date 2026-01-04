#!/usr/bin/env bash
# =============================================================================
# Policy Check Script
# =============================================================================
# This script runs OPA/Conftest policy checks against the Terraform plan:
#   1. Convert plan to JSON format
#   2. Run Conftest policies against the JSON
#
# Usage: ./scripts/policy_check.sh [terraform_dir] [policies_dir]
#   terraform_dir: Path to Terraform configuration (default: ./terraform)
#   policies_dir: Path to Rego policies (default: ./policies/terraform)
#
# Requirements: conftest must be installed
# =============================================================================

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TERRAFORM_DIR="${1:-${REPO_ROOT}/terraform}"
POLICIES_DIR="${2:-${REPO_ROOT}/policies/terraform}"
PLAN_FILE="tfplan"
PLAN_JSON="tfplan.json"

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

# Verify directories exist
if [[ ! -d "${TERRAFORM_DIR}" ]]; then
    log_error "Terraform directory not found: ${TERRAFORM_DIR}"
    exit 1
fi

if [[ ! -d "${POLICIES_DIR}" ]]; then
    log_error "Policies directory not found: ${POLICIES_DIR}"
    exit 1
fi

# Change to terraform directory
cd "${TERRAFORM_DIR}"
log_info "Working directory: $(pwd)"

# Verify plan file exists
if [[ ! -f "${PLAN_FILE}" ]]; then
    log_error "Plan file not found: ${PLAN_FILE}"
    log_info "Run './scripts/plan.sh' first to generate the plan."
    exit 1
fi

# Step 1: Convert plan to JSON
log_info "Converting Terraform plan to JSON..."
terraform show -json "${PLAN_FILE}" > "${PLAN_JSON}"

if [[ -f "${PLAN_JSON}" ]]; then
    log_success "Plan JSON created: ${PLAN_JSON}"
    log_info "JSON file size: $(du -h "${PLAN_JSON}" | cut -f1)"
else
    log_error "Failed to create plan JSON."
    exit 1
fi

# Step 2: Check if conftest is installed
if ! command -v conftest &> /dev/null; then
    log_error "conftest is not installed."
    log_info "Install conftest: https://www.conftest.dev/install/"
    log_info "  brew install conftest  # macOS"
    log_info "  choco install conftest  # Windows"
    log_info "  Download from GitHub releases for Linux"
    exit 1
fi

log_info "Conftest version: $(conftest --version)"

# Step 3: Run policy checks
log_info "Running policy checks..."
log_info "Policies directory: ${POLICIES_DIR}"

echo ""
echo "=========================================="
echo "  POLICY CHECK RESULTS"
echo "=========================================="
echo ""

# Run conftest and capture exit code
set +e
conftest test "${PLAN_JSON}" \
    --policy "${POLICIES_DIR}" \
    --output stdout \
    --no-color
CONFTEST_EXIT_CODE=$?
set -e

echo ""
echo "=========================================="

if [[ ${CONFTEST_EXIT_CODE} -eq 0 ]]; then
    log_success "All policy checks passed!"
    log_info "The Terraform plan is compliant with all policies."
else
    log_error "Policy checks failed!"
    log_info "Please review the policy violations above and fix your Terraform configuration."
    log_info ""
    log_info "Common fixes:"
    log_info "  - S3 public access: Ensure all block_public_* settings are true"
    log_info "  - Security group: Use specific CIDR blocks instead of 0.0.0.0/0"
    log_info "  - IAM wildcards: Use specific actions and resource ARNs"
    exit 1
fi

log_success "Policy check completed successfully!"
echo ""
log_info "Next step: Sign the plan with ./scripts/sign_plan.sh"
