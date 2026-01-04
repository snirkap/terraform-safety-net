#!/usr/bin/env bash
# =============================================================================
# Sign Plan Script
# =============================================================================
# This script signs the Terraform plan file using Sigstore cosign:
#   1. Verify plan file exists
#   2. Sign the plan as a blob using keyless signing (OIDC)
#   3. Store the signature bundle for verification
#
# Usage: ./scripts/sign_plan.sh [terraform_dir]
#   terraform_dir: Path to Terraform configuration (default: ./terraform)
#
# Requirements:
#   - cosign must be installed
#   - For keyless signing: OIDC identity (GitHub Actions, Google, Microsoft, etc.)
#
# Output: Creates tfplan.bundle file containing signature and certificate
# =============================================================================

set -euo pipefail

# Configuration
TERRAFORM_DIR="${1:-./terraform}"
PLAN_FILE="tfplan"
BUNDLE_FILE="tfplan.bundle"

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

# Verify terraform directory exists
if [[ ! -d "${TERRAFORM_DIR}" ]]; then
    log_error "Terraform directory not found: ${TERRAFORM_DIR}"
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

# Check if cosign is installed
if ! command -v cosign &> /dev/null; then
    log_error "cosign is not installed."
    log_info "Install cosign: https://docs.sigstore.dev/cosign/installation/"
    log_info "  brew install cosign  # macOS"
    log_info "  go install github.com/sigstore/cosign/v2/cmd/cosign@latest  # Go"
    log_info "  Download from GitHub releases"
    exit 1
fi

log_info "cosign version: $(cosign version 2>&1 | head -n1 || echo 'unknown')"

# Calculate hash of the plan file for reference
PLAN_HASH=$(sha256sum "${PLAN_FILE}" | cut -d' ' -f1)
log_info "Plan file hash (SHA256): ${PLAN_HASH}"

# Sign the plan file
log_info "Signing plan file with cosign (keyless)..."
log_info "This will use OIDC-based identity (GitHub Actions, Google, etc.)"

# In CI (GitHub Actions), this uses the ACTIONS_ID_TOKEN_REQUEST_* environment variables
# For local testing, this will open a browser for OIDC authentication
cosign sign-blob \
    --yes \
    --bundle "${BUNDLE_FILE}" \
    "${PLAN_FILE}"

# Verify bundle was created
if [[ -f "${BUNDLE_FILE}" ]]; then
    log_success "Signature bundle created: ${BUNDLE_FILE}"
    log_info "Bundle file size: $(du -h "${BUNDLE_FILE}" | cut -f1)"

    # Show bundle contents (certificate info)
    log_info "Bundle contents preview:"
    if command -v jq &> /dev/null; then
        jq -r '.verificationMaterial.x509CertificateChain.certificates[0].rawBytes' "${BUNDLE_FILE}" 2>/dev/null | \
            base64 -d 2>/dev/null | \
            openssl x509 -noout -subject -issuer 2>/dev/null || \
            log_warning "Could not parse certificate details"
    fi
else
    log_error "Failed to create signature bundle."
    exit 1
fi

log_success "Plan file signed successfully!"
echo ""
log_info "Created artifacts:"
echo "  - ${PLAN_FILE} (Terraform plan)"
echo "  - tfplan.json (Plan in JSON format)"
echo "  - ${BUNDLE_FILE} (Signature bundle)"
echo ""
log_info "To verify the signature later, run:"
echo "  ./scripts/verify_plan.sh"
