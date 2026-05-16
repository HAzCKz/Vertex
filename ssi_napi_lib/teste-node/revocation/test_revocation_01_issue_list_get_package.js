/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
node teste-node/revocation/test_revocation_01_issue_list_get_package.js
*/

const path = require("path");
const {
  assert,
  loadIndyAgent,
  fn,
  parseJsonSafe,
  walletCreateOpenIdempotent,
  cleanupWalletFamily,
  ensureWalletDir,
  makeKValues,
  sampleManifest,
  sampleKLedgerAnchor,
  sampleCredentialJson,
} = require("./_helpers");

const REQUIRED_EXTRA_WINDOWS_FOR_FP = 10;

(async () => {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_issuer_01.db");

  if (RESET) cleanupWalletFamily(issuerDb);

  const issuer = new IndyAgent();
  await walletCreateOpenIdempotent(issuer, issuerDb, pass);

  try {
    const createRevocableCredentialPackage = fn(
      issuer,
      "createRevocableCredentialPackage",
      "create_revocable_credential_package"
    );
    const listIssuedCredentials = fn(
      issuer,
      "listIssuedCredentials",
      "list_issued_credentials"
    );
    const getIssuedCredential = fn(
      issuer,
      "getIssuedCredential",
      "get_issued_credential"
    );

    const credentialId = `revocable-cred-${Date.now()}`;
    const now = Math.floor(Date.now() / 1000);
    const validityEnd = now + 86400 * 30;
    const extraWindowsForFp = REQUIRED_EXTRA_WINDOWS_FOR_FP;
    const kValues = makeKValues();
    const kLedgerAnchor = sampleKLedgerAnchor("did:example:issuer:001");

    console.log("🚀 TESTE REVOGAÇÃO 01: package + list + get");

    const packageJson = await createRevocableCredentialPackage(
      credentialId,
      "did:example:holder:alice",
      "mock:creddef:issuer:001",
      "mock:schema:issuer:001",
      sampleCredentialJson(),
      "did:example:issuer:001",
      JSON.stringify(kValues),
      now,
      validityEnd,
      "days",
      1,
      extraWindowsForFp,
      JSON.stringify(sampleManifest("did:example:issuer:001")),
      JSON.stringify(kLedgerAnchor)
    );

    const pkg = parseJsonSafe(packageJson, "revocable_package");
    assert(pkg.type === "ssi.revocable_credential.package", "type do pacote inválido");
    assert(pkg.version === 1, "version do pacote inválida");
    assert(pkg.control_values.window_count >= 30, "window_count inesperado");
    assert(typeof pkg.control_values.seed === "string" && pkg.control_values.seed.length > 10, "seed inválida");
    assert(pkg.control_values.start_time === now, "start_time inválido");
    assert(pkg.control_values.validity_end === validityEnd, "validity_end inválido");
    assert(pkg.control_values.extra_windows_for_fp === REQUIRED_EXTRA_WINDOWS_FOR_FP, "extra_windows_for_fp inválido");
    assert(pkg.control_attributes.seed === pkg.control_values.seed, "control_attributes.seed inválido");
    assert(pkg.control_attributes.start_time === String(now), "control_attributes.start_time inválido");
    assert(pkg.control_attributes.root_merkle_L === pkg.control_values.root_merkle_l, "control_attributes.root_merkle_L inválido");
    assert(pkg.k_ledger_anchor.k_vector_id === kLedgerAnchor.k_vector_id, "k_ledger_anchor inválido");
    assert(pkg.delivery_payload.revocation_binding.k_vector_id === kLedgerAnchor.k_vector_id, "delivery_payload.revocation_binding.k_vector_id inválido");
    assert(pkg.delivery_payload.revocation_binding.manifest_attr_key === "REVOCATION_MANIFEST", "manifest_attr_key inválido");
    assert(pkg.delivery_payload.control_attributes.seed === pkg.control_values.seed, "delivery_payload.control_attributes.seed inválido");
    assert(pkg.issuer_record.issuer_local_credential_id === credentialId, "issuer_record com id_local inválido");
    assert(pkg.issuer_record.status === "active", "issuer_record.status deveria ser active");
    assert(pkg.issuer_record.k_ledger_anchor.k_vector_id === kLedgerAnchor.k_vector_id, "issuer_record.k_ledger_anchor inválido");
    assert(Array.isArray(pkg.issuer_record.revocation_keys_by_window), "revocation_keys_by_window inválido");
    assert(
      pkg.issuer_record.revocation_keys_by_window.length === pkg.control_values.window_count,
      "quantidade de revocation_keys difere de window_count"
    );
    assert(Array.isArray(pkg.holder_bundle.tmp_vector_b64), "tmp_vector_b64 inválido");
    assert(pkg.holder_bundle.k_ledger_anchor.k_vector_id === kLedgerAnchor.k_vector_id, "holder_bundle.k_ledger_anchor inválido");
    assert(
      pkg.holder_bundle.tmp_vector_b64.length === pkg.control_values.window_count,
      "tmp_vector_b64 deveria ter um tmp por janela"
    );
    assert(pkg.holder_bundle.vectors_summary.window_count === pkg.control_values.window_count, "vectors_summary.window_count inválido");
    assert(pkg.holder_bundle.vectors_summary.t_count === pkg.control_values.window_count, "vectors_summary.t_count inválido");
    assert(pkg.holder_bundle.vectors_summary.s_count === pkg.control_values.window_count, "vectors_summary.s_count inválido");
    assert(pkg.holder_bundle.vectors_summary.l_count === pkg.control_values.window_count, "vectors_summary.l_count inválido");
    assert(pkg.issuer_record.vectors_summary.t_compact_size_bytes > 0, "vectors_summary.t_compact_size_bytes inválido");

    const listedJson = await listIssuedCredentials(null);
    const listed = parseJsonSafe(listedJson, "issued_credentials");
    assert(Array.isArray(listed), "listIssuedCredentials deveria retornar array");
    assert(
      listed.some((item) => item.issuer_local_credential_id === credentialId),
      "credential emitida não apareceu em listIssuedCredentials"
    );

    const fetchedJson = await getIssuedCredential(credentialId);
    const fetched = parseJsonSafe(fetchedJson, "issued_credential");
    assert(fetched.issuer_local_credential_id === credentialId, "getIssuedCredential retornou id errado");
    assert(fetched.control.root_merkle_l === pkg.control_values.root_merkle_l, "root_merkle_l divergente");
    assert(fetched.control.validity_end === validityEnd, "validity_end persistido divergente");
    assert(fetched.vectors_summary.window_count === pkg.control_values.window_count, "vectors_summary persistido divergente");
    assert(fetched.k_ledger_anchor.k_vector_id === kLedgerAnchor.k_vector_id, "k_ledger_anchor persistido divergente");

    console.log("✅ OK: TESTE REVOGAÇÃO 01 passou.");
  } finally {
    try { await issuer.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 01:", e && e.stack ? e.stack : e);
  process.exit(1);
});
