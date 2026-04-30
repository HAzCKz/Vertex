#!/usr/bin/env bash
set -euo pipefail

WALLET_PASS="${WALLET_PASS:-minha_senha_teste}"
GENESIS_FILE="${GENESIS_FILE:-./von_genesis.txn}"

export WALLET_PASS GENESIS_FILE
export TRUSTEE_SEED="${TRUSTEE_SEED:-000000000000000000000000Trustee1}"
export TRUSTEE_DID="${TRUSTEE_DID:-V4SGRU86Z58d6TV7PBUe6f}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REVOC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================================"
echo "🚀 SUÍTE REVOCATION VON: K + ATTRIB + Manifest"
echo "Root:   ${ROOT_DIR}"
echo "Revoc:  ${REVOC_DIR}"
echo "Env:    GENESIS_FILE=${GENESIS_FILE} WALLET_PASS=***"
echo "============================================================"
echo

RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_10_k_vector_attrib_roundtrip_von.js"
echo
RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_12_single_k_per_issuer_von.js"
echo
RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_11_manifest_anchor_von.js"
echo
RESET_WALLET=1 BFILTER_BASE_URL="${BFILTER_BASE_URL:-http://127.0.0.1:8080}" MANIFEST_ISSUER_DID="${TRUSTEE_DID}" node "${REVOC_DIR}/test_revocation_54_reanchor_current_manifest_without_reset_von.js"
echo
RESET_WALLET=1 MANIFEST_ISSUER_DID="${TRUSTEE_DID}" node "${REVOC_DIR}/test_revocation_53_manifest_attr_hash_matches_manifest_file_von.js"
echo
RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_20_e2e_ssi_revocable_flow_von.js"
echo
RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_21_issue_revocable_reuses_k_von.js"
echo
RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_32_presentation_root_merkle_must_match_proof_von.js"
echo
RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_33_verifier_recomputes_l_from_ledger_k_von.js"
echo
RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_34_invalid_k_index_rejected_von.js"
echo
RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_35_duplicate_k_index_rejected_von.js"
echo
RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_36_tmp_must_not_belong_to_k_von.js"
echo
RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_37_l_value_mismatch_rejected_von.js"
echo
RESET_WALLET=1 node "${REVOC_DIR}/test_revocation_38_all_time_units_revocation_von.js"
echo

echo "============================================================"
echo "✅ RESULTADO: testes VON de revogação passaram."
echo "============================================================"
