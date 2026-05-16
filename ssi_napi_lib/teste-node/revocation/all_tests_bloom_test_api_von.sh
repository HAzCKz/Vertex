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
echo "🚀 SUÍTE REVOCATION BLOOM TEST API + VON"
echo "Root:   ${ROOT_DIR}"
echo "Revoc:  ${REVOC_DIR}"
echo "Bloom:  ${BFILTER_BASE_URL}"
echo "Env:    GENESIS_FILE=${GENESIS_FILE} WALLET_PASS=***"
echo "OBS:    requer BFILTER_ENABLE_TEST_API=1 no serviço bfilter"
echo "============================================================"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_47_reset_bloom_to_default_and_reanchor_manifest_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_46_bloom_test_mode_rotation_multifilter_lookup_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_48_split_revocation_across_two_bloom_filters_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_50_v2_false_positive_holder_must_disprove_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_51_v2_last_valid_window_false_positive_refuted_by_confirmation_windows_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_52_v2_mixed_presentation_false_positive_refuted_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_58_v2_default_ten_confirmation_windows_do_not_extend_validity_von.js"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_59_v2_incremental_confirmation_windows_confirm_real_revocation_von.js"
echo

echo "============================================================"
echo "✅ RESULTADO: testes Bloom test API + VON passaram."
echo "============================================================"
