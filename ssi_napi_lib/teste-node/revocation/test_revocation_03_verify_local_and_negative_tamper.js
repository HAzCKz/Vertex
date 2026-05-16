/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
node teste-node/revocation/test_revocation_03_verify_local_and_negative_tamper.js
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
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_issuer_03.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_holder_03.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_verifier_03.db");

  if (RESET) {
    cleanupWalletFamily(issuerDb);
    cleanupWalletFamily(holderDb);
    cleanupWalletFamily(verifierDb);
  }

  const issuer = new IndyAgent();
  const holder = new IndyAgent();
  const verifier = new IndyAgent();

  await walletCreateOpenIdempotent(issuer, issuerDb, pass);
  await walletCreateOpenIdempotent(holder, holderDb, pass);
  await walletCreateOpenIdempotent(verifier, verifierDb, pass);

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
    const buildPresentationRevocationProof = fn(
      holder,
      "buildPresentationRevocationProof",
      "build_presentation_revocation_proof"
    );
    const verifyPresentationRevocationProof = fn(
      verifier,
      "verifyPresentationRevocationProof",
      "verify_presentation_revocation_proof"
    );

    const credentialId = `revocable-cred-verify-${Date.now()}`;
    const bundleId = `bundle-verify-${Date.now()}`;
    const now = Math.floor(Date.now() / 1000);
    const validityEnd = now + 86400 * 5;
    const kLedgerAnchor = sampleKLedgerAnchor("did:example:issuer:003");

    console.log("🚀 TESTE REVOGAÇÃO 03: verify local + negativo com tamper");

    const packageJson = await createRevocableCredentialPackage(
      credentialId,
      "did:example:holder:charlie",
      "mock:creddef:issuer:003",
      "mock:schema:issuer:003",
      sampleCredentialJson(),
      "did:example:issuer:003",
      JSON.stringify(makeKValues()),
      now,
      validityEnd,
      "days",
      1,
      REQUIRED_EXTRA_WINDOWS_FOR_FP,
      JSON.stringify(sampleManifest("did:example:issuer:003")),
      JSON.stringify(kLedgerAnchor)
    );

    const pkg = parseJsonSafe(packageJson, "revocable_package");
    assert(pkg.control_values.validity_end === validityEnd, "validity_end inválido no pacote");
    assert(pkg.control_values.extra_windows_for_fp === REQUIRED_EXTRA_WINDOWS_FOR_FP, "extra_windows_for_fp inválido no pacote");
    assert(pkg.control_values.confirmation_window_count === REQUIRED_EXTRA_WINDOWS_FOR_FP, "confirmation_window_count inválido no pacote");
    assert(pkg.holder_bundle.tmp_vector_b64.length === pkg.control_values.window_count, "tmp_vector_b64 inválido no pacote");
    assert(pkg.delivery_payload.revocation_binding.k_vector_id === kLedgerAnchor.k_vector_id, "delivery_payload deveria carregar k_vector_id");

    await storeReceivedRevocableCredential(
      bundleId,
      JSON.stringify(pkg.holder_bundle),
      credentialId
    );

    const proofJson = await buildPresentationRevocationProof(bundleId, 0, null);
    const proofResponse = parseJsonSafe(proofJson, "proof_response");
    proofResponse.proof.manifest = null;
    proofResponse.proof.k_ledger_anchor = null;

    const verifyJson = await verifyPresentationRevocationProof(
      JSON.stringify(proofResponse.proof)
    );
    const verifyResponse = parseJsonSafe(verifyJson, "verify_response");
    assert(verifyResponse.ok === true, "verify deveria retornar ok=true");
    assert(verifyResponse.status.verified === true, "prova local válida deveria verificar");
    assert(verifyResponse.status.revoked === false, "revoked deveria ser false antes do Bloom");
    assert(verifyResponse.status.window_index === 0, "window_index inválido");
    assert(verifyResponse.proof.control.validity_end === validityEnd, "verify response deveria preservar validity_end");
    assert(verifyResponse.proof.k_ledger_anchor === null, "verify response deveria manter k_ledger_anchor nulo no modo local");
    assert(
      typeof verifyResponse.status.revocation_key === "string" &&
        verifyResponse.status.revocation_key.length > 10,
      "revocation_key inválida"
    );

    const tamperedProof = {
      ...proofResponse.proof,
      l_value: makeKValues(1)[0],
    };

    const tamperedVerifyJson = await verifyPresentationRevocationProof(
      JSON.stringify(tamperedProof)
    );
    const tamperedVerify = parseJsonSafe(tamperedVerifyJson, "tampered_verify_response");
    assert(
      tamperedVerify.status.verified === false,
      "prova adulterada deveria falhar na validação local"
    );
    assert(
      String(tamperedVerify.status.details || "").includes("Falha"),
      "mensagem da prova adulterada deveria indicar falha"
    );

    console.log("✅ OK: TESTE REVOGAÇÃO 03 passou.");
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
    try { await verifier.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 03:", e && e.stack ? e.stack : e);
  process.exit(1);
});
