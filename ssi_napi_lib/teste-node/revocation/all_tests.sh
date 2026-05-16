#!/usr/bin/env bash
set -euo pipefail

echo "🚀 SUÍTE REVOCATION (Node) - local"
export WALLET_PASS="${WALLET_PASS:-minha_senha_teste}"

node teste-node/revocation/test_revocation_01_issue_list_get_package.js
node teste-node/revocation/test_revocation_02_holder_store_get_build_proof.js
node teste-node/revocation/test_revocation_03_verify_local_and_negative_tamper.js
node teste-node/revocation/test_revocation_30_li_randomness_local.js
node teste-node/revocation/test_revocation_31_holder_discloses_only_allowed_window_tokens.js
node teste-node/revocation/test_revocation_39_extract_revocation_controls_from_presentation_local.js

echo "✅ SUÍTE REVOCATION completa."
