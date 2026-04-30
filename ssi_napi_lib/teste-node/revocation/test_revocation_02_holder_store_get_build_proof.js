/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
node teste-node/revocation/test_revocation_02_holder_store_get_build_proof.js
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
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_issuer_02.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_holder_02.db");

  if (RESET) {
    cleanupWalletFamily(issuerDb);
    cleanupWalletFamily(holderDb);
  }

  const issuer = new IndyAgent();
  const holder = new IndyAgent();

  await walletCreateOpenIdempotent(issuer, issuerDb, pass);
  await walletCreateOpenIdempotent(holder, holderDb, pass);

  try {
    const createRevocableCredentialPackage = fn(
      issuer,
      "createRevocableCredentialPackage",
      "create_revocable_credential_package"
    );
    const storeReceivedRevocableCredential = fn(
      holder,
      "storeReceivedRevocableCredential",
      "store_received_revocable_credential"
    );
    const getHolderRevocationBundle = fn(
      holder,
      "getHolderRevocationBundle",
      "get_holder_revocation_bundle"
    );
    const buildPresentationRevocationProof = fn(
      holder,
      "buildPresentationRevocationProof",
      "build_presentation_revocation_proof"
    );

    const credentialId = `revocable-cred-holder-${Date.now()}`;
    const bundleId = `bundle-${Date.now()}`;
    const now = Math.floor(Date.now() / 1000);
    const validityEnd = now + 86400 * 10;
    const kLedgerAnchor = sampleKLedgerAnchor("did:example:issuer:002");

    console.log("🚀 TESTE REVOGAÇÃO 02: holder store + get + build proof");

    const packageJson = await createRevocableCredentialPackage(
      credentialId,
      "did:example:holder:bob",
      "mock:creddef:issuer:002",
      "mock:schema:issuer:002",
      sampleCredentialJson(),
      "did:example:issuer:002",
      JSON.stringify(makeKValues()),
      now,
      validityEnd,
      "days",
      1,
      REQUIRED_EXTRA_WINDOWS_FOR_FP,
      JSON.stringify(sampleManifest("did:example:issuer:002")),
      JSON.stringify(kLedgerAnchor)
    );

    const pkg = parseJsonSafe(packageJson, "revocable_package");
    assert(
      pkg.control_values.extra_windows_for_fp === REQUIRED_EXTRA_WINDOWS_FOR_FP,
      "extra_windows_for_fp inválido no pacote"
    );
    assert(
      pkg.control_values.confirmation_window_count === REQUIRED_EXTRA_WINDOWS_FOR_FP,
      "confirmation_window_count inválido no pacote"
    );

    const storedJson = await storeReceivedRevocableCredential(
      bundleId,
      JSON.stringify(pkg.holder_bundle),
      credentialId
    );
    const stored = parseJsonSafe(storedJson, "stored_bundle");
    assert(stored.ok === true, "storeReceivedRevocableCredential deveria retornar ok=true");
    assert(stored.bundle_id_local === bundleId, "bundle_id_local divergente");
    assert(stored.credential_id_local === credentialId, "credential_id_local divergente");

    const bundleJson = await getHolderRevocationBundle(bundleId);
    const bundle = parseJsonSafe(bundleJson, "holder_bundle");
    assert(bundle.credential_id === credentialId, "bundle salvo sem credential_id");
    assert(bundle.control.root_merkle_l === pkg.control_values.root_merkle_l, "bundle salvo com root inválida");
    assert(bundle.control.validity_end === validityEnd, "bundle salvo com validity_end inválido");
    assert(bundle.control.extra_windows_for_fp === REQUIRED_EXTRA_WINDOWS_FOR_FP, "bundle salvo com extra_windows_for_fp inválido");
    assert(bundle.k_ledger_anchor.k_vector_id === kLedgerAnchor.k_vector_id, "bundle salvo com k_ledger_anchor inválido");
    assert(Array.isArray(bundle.tmp_vector_b64), "bundle.tmp_vector_b64 inválido");
    assert(bundle.tmp_vector_b64.length === bundle.control.window_count, "bundle.tmp_vector_b64 deveria acompanhar window_count");
    assert(bundle.vectors_summary.s_count === bundle.control.window_count, "bundle.vectors_summary.s_count inválido");

    const proofJson = await buildPresentationRevocationProof(bundleId, 0, null);
    const proofResponse = parseJsonSafe(proofJson, "presentation_revocation_proof");
    assert(proofResponse.ok === true, "buildPresentationRevocationProof deveria retornar ok=true");
    assert(proofResponse.credential_id_local === credentialId, "proof com credential_id_local incorreto");
    assert(proofResponse.proof.window_index === 0, "window_index incorreto");
    assert(
      proofResponse.proof.control.root_merkle_l === pkg.control_values.root_merkle_l,
      "prova com root_merkle_l incorreta"
    );
    assert(proofResponse.proof.control.validity_end === validityEnd, "prova com validity_end incorreto");
    assert(proofResponse.proof.k_ledger_anchor.k_vector_id === kLedgerAnchor.k_vector_id, "prova com k_ledger_anchor incorreto");
    assert(Array.isArray(proofResponse.proof.merkle_path), "merkle_path deveria ser array");

    console.log("✅ OK: TESTE REVOGAÇÃO 02 passou.");
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 02:", e && e.stack ? e.stack : e);
  process.exit(1);
});
