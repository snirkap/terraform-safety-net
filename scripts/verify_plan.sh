#!/usr/bin/env bash
# =============================================================================
# Verify Plan Script
# =============================================================================
# This script verifies the Terraform plan file signature using cosign:
#   1. Verify the signature bundle exists
#   2. Verify the signature against the plan file
#   3. Optionally verify the signer identity
#
# Usage: ./scripts/verify_plan.sh [terraform_dir] [--certificate-identity IDENTITY] [--certificate-oidc-issuer ISSUER]
#   terraform_dir: Path to Terraform configuration (default: ./terraform)
#
# Requirements:
#   - cosign must be installed
#   - tfplan and tfplan.bundle files must exist
#
# Environment variables:
#   CERTIFICATE_IDENTITY: Expected signer identity (email or URI)
#   CERTIFICATE_OIDC_ISSUER: Expected OIDC issuer URL
# =============================================================================

set -euo pipefail

# Configuration
TERRAFORM_DIR="${1:-./terraform}"
PLAN_FILE="tfplan"
BUNDLE_FILE="tfplan.bundle"

# Optional identity verification (can be set via env vars or args)
CERTIFICATE_IDENTITY="${CERTIFICATE_IDENTITY:-}"
CERTIFICATE_OIDC_ISSUER="${CERTIFICATE_OIDC_ISSUER:-}"

# Parse additional arguments
shift || true
while [[ $# -gt 0 ]]; do
    case $1 in
        --certificate-identity)
            CERTIFICATE_IDENTITY="$2"
            shift 2
            ;;
        --certificate-oidc-issuer)
            CERTIFICATE_OIDC_ISSUER="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

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
    exit 1
fi

# Verify bundle file exists
if [[ ! -f "${BUNDLE_FILE}" ]]; then
    log_error "Signature bundle not found: ${BUNDLE_FILE}"
    log_info "The plan file has not been signed or the bundle is missing."
    exit 1
fi

# Check if cosign is installed
if ! command -v cosign &> /dev/null; then
    log_error "cosign is not installed."
    log_info "Install cosign: https://docs.sigstore.dev/cosign/installation/"
    exit 1
fi

log_info "cosign version: $(cosign version 2>&1 | head -n1 || echo 'unknown')"

# Calculate hash of the plan file
PLAN_HASH=$(sha256sum "${PLAN_FILE}" | cut -d' ' -f1)
log_info "Plan file hash (SHA256): ${PLAN_HASH}"

# Build verification command
VERIFY_CMD=(cosign verify-blob)
VERIFY_CMD+=(--bundle "${BUNDLE_FILE}")

# Add identity verification if specified
if [[ -n "${CERTIFICATE_IDENTITY}" ]]; then
    log_info "Verifying signer identity: ${CERTIFICATE_IDENTITY}"
    VERIFY_CMD+=(--certificate-identity "${CERTIFICATE_IDENTITY}")
fi

if [[ -n "${CERTIFICATE_OIDC_ISSUER}" ]]; then
    log_info "Verifying OIDC issuer: ${CERTIFICATE_OIDC_ISSUER}"
    VERIFY_CMD+=(--certificate-oidc-issuer "${CERTIFICATE_OIDC_ISSUER}")
fi

# If no identity specified, use wildcards to accept any identity
# This is for demo purposes; in production, you should specify the expected identity
if [[ -z "${CERTIFICATE_IDENTITY}" ]] && [[ -z "${CERTIFICATE_OIDC_ISSUER}" ]]; then
    log_warning "No identity verification specified. Using permissive verification."
    log_warning "For production, set CERTIFICATE_IDENTITY and CERTIFICATE_OIDC_ISSUER."
    VERIFY_CMD+=(--certificate-identity-regexp ".*")
    VERIFY_CMD+=(--certificate-oidc-issuer-regexp ".*")
fi

VERIFY_CMD+=("${PLAN_FILE}")

# Verify the signature
log_info "Verifying plan file signature..."
echo ""
echo "=========================================="
echo "  SIGNATURE VERIFICATION"
echo "=========================================="
echo ""

if "${VERIFY_CMD[@]}"; then
    echo ""
    echo "=========================================="
    log_success "Signature verification PASSED!"
    log_info "The plan file is authentic and has not been tampered with."

    # Extract and display certificate info
    if command -v jq &> /dev/null; then
        log_info ""
        log_info "Certificate details:"
        CERT_B64=$(jq -r '.verificationMaterial.x509CertificateChain.certificates[0].rawBytes' "${BUNDLE_FILE}" 2>/dev/null || echo "")
        if [[ -n "${CERT_B64}" ]]; then
            echo "${CERT_B64}" | base64 -d 2>/dev/null | \
                openssl x509 -noout -subject -issuer -dates 2>/dev/null | \
                sed 's/^/  /' || true
        fi
    fi
else
    echo ""
    echo "=========================================="
    log_error "Signature verification FAILED!"
    log_error "The plan file may have been tampered with or the signature is invalid."
    log_error "DO NOT apply this plan!"
    exit 1
fi

echo ""
log_success "Verification completed successfully!"
log_info "It is now safe to apply this plan."
echo ""
log_info "Next step: Apply the plan with ./scripts/apply.sh"
