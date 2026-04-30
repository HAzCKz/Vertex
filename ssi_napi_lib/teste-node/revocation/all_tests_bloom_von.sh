#!/usr/bin/env bash
set -euo pipefail

WALLET_PASS="${WALLET_PASS:-minha_senha_teste}"
GENESIS_FILE="${GENESIS_FILE:-./von_genesis.txn}"
BFILTER_BASE_URL="${BFILTER_BASE_URL:-http://127.0.0.1:8080}"
BFILTER_ADMIN_TOKEN="${BFILTER_ADMIN_TOKEN:-dev-admin-token}"

export WALLET_PASS GENESIS_FILE BFILTER_BASE_URL BFILTER_ADMIN_TOKEN
export TRUSTEE_SEED="${TRUSTEE_SEED:-000000000000000000000000Trustee1}"
export TRUSTEE_DID="${TRUSTEE_DID:-V4SGRU86Z58d6TV7PBUe6f}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REVOC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================"
echo "🚀 SUÍTE REVOCATION BLOOM + VON"
echo "Root:   ${ROOT_DIR}"
echo "Revoc:  ${REVOC_DIR}"
echo "Bloom:  ${BFILTER_BASE_URL}"
echo "Env:    GENESIS_FILE=${GENESIS_FILE} WALLET_PASS=***"
echo "============================================================"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_22_bloom_service_integration_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_23_multi_credential_presentation_revoked_by_one_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_24_three_credentials_first_contact_anoncrypt_then_authcrypt_envelope_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_25_mixed_revocable_and_non_revocable_presentation_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_40_verify_mixed_presentation_package_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_41_create_presentation_package_with_revocation_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_42_issuer_operational_methods_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_43_daily_windows_multi_day_packages_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_44_revocation_boundary_from_window_10_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_49_v2_last_valid_window_with_ten_confirmation_windows_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_58_v2_default_ten_confirmation_windows_do_not_extend_validity_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_59_v2_incremental_confirmation_windows_confirm_real_revocation_von.js"
echo

echo "============================================================"
echo "✅ RESULTADO: teste Bloom/VON de revogação passou."
echo "============================================================"
