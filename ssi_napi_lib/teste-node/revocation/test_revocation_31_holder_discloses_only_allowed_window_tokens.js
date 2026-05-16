/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
node teste-node/revocation/test_revocation_31_holder_discloses_only_allowed_window_tokens.js
*/

/*
Teste local de disclosure mínimo na prova complementar de revogação.

O fluxo:
- cria/abre wallets de issuer e holder;
- issuer gera um pacote de credencial revogável com várias janelas;
- holder armazena o bundle revogável;
- holder monta a prova de revogação para uma janela específica;
- verifier valida a prova localmente.

Depois valida:
- a prova contém apenas os dados mínimos da janela escolhida;
- não vaza o vetor completo de T, L ou tmp;
- o t_entry revelado é exatamente o da janela autorizada;
- o l_value revelado é apenas o necessário junto com o merkle_path;
- a prova continua válida mesmo com disclosure mínimo;
- sem consulta Bloom, o status permanece revoked=false.

Foco do teste:
validar que o holder revela somente os tokens estritamente
necessários da janela autorizada ao montar a prova de revogação.
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

function hasOwn(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

(async () => {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_issuer_31.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_holder_31.db");

  if (RESET) {
    cleanupWalletFamily(issuerDb);
    cleanupWalletFamily(holderDb);
  }

  const issuer = new IndyAgent();
  const holder = new IndyAgent();
  const verifier = new IndyAgent();

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
    const verifyPresentationRevocationProof = fn(
      verifier,
      "verifyPresentationRevocationProof",
      "verify_presentation_revocation_proof"
    );

    const credentialId = `revocable-cred-window-scope-${Date.now()}`;
    const bundleId = `bundle-window-scope-${Date.now()}`;
    const now = Math.floor(Date.now() / 1000);
    const windowCount = 12;
    const chosenWindowIndex = 5;
    const validityEnd = now + ((windowCount - 1) * 3600);
    const issuerDid = "did:example:issuer:031";
    const kLedgerAnchor = sampleKLedgerAnchor(issuerDid, {
      k_vector_id: `k-vector-window-scope-${Date.now()}`,
    });

    console.log("🚀 TESTE REVOGAÇÃO 31: holder divulga apenas os tokens da janela permitida");

    const packageJson = await createRevocableCredentialPackage(
      credentialId,
      "did:example:holder:carol",
      "mock:creddef:issuer:031",
      "mock:schema:issuer:031",
      sampleCredentialJson(),
      issuerDid,
      JSON.stringify(makeKValues()),
      now,
      validityEnd,
      "hours",
      1,
      REQUIRED_EXTRA_WINDOWS_FOR_FP,
      JSON.stringify(sampleManifest(issuerDid)),
      JSON.stringify(kLedgerAnchor)
    );
    const pkg = parseJsonSafe(packageJson, "revocable_package");
    assert(pkg.control_values.window_count === windowCount + REQUIRED_EXTRA_WINDOWS_FOR_FP, "window_count inesperado no pacote");

    const storedJson = await storeReceivedRevocableCredential(
      bundleId,
      JSON.stringify(pkg.holder_bundle),
      credentialId
    );
    const stored = parseJsonSafe(storedJson, "stored_bundle");
    assert(stored.ok === true, "storeReceivedRevocableCredential deveria retornar ok=true");

    const bundleJson = await getHolderRevocationBundle(bundleId);
    const bundle = parseJsonSafe(bundleJson, "holder_bundle");
    assert(bundle.control.window_count === windowCount + REQUIRED_EXTRA_WINDOWS_FOR_FP, "bundle salvo com window_count inesperado");

    const proofJson = await buildPresentationRevocationProof(
      bundleId,
      chosenWindowIndex,
      credentialId
    );
    const proofResponse = parseJsonSafe(proofJson, "presentation_revocation_proof");
    assert(proofResponse.ok === true, "buildPresentationRevocationProof deveria retornar ok=true");

    const proof = proofResponse.proof;
    const proofJsonString = JSON.stringify(proof);

    console.log("1) Conferindo a estrutura mínima da prova entregue ao verifier...");
    assert(proof.window_index === chosenWindowIndex, "window_index incorreto na prova");
    assert(hasOwn(proof, "t_entry"), "prova deveria carregar apenas um t_entry");
    assert(hasOwn(proof, "l_value"), "prova deveria carregar apenas um l_value");
    assert(hasOwn(proof, "merkle_path"), "prova deveria carregar o merkle_path");
    assert(Array.isArray(proof.merkle_path), "merkle_path deveria ser array");
    assert(hasOwn(proof, "control"), "prova deveria carregar control");
    assert(!hasOwn(proof, "t_entries"), "prova não deveria carregar o vetor T completo");
    assert(!hasOwn(proof, "l_values"), "prova não deveria carregar o vetor L completo");
    assert(!hasOwn(proof, "tmp_vector_b64"), "prova não deveria carregar o vetor tmp completo");
    assert(!hasOwn(proof, "vectors_summary"), "prova não deveria carregar vectors_summary do bundle");

    console.log("2) Garantindo que o holder revelou apenas o T da janela autorizada...");
    assert(
      JSON.stringify(proof.t_entry) === JSON.stringify(bundle.t_entries[chosenWindowIndex]),
      "o t_entry enviado ao verifier deveria ser exatamente o da janela autorizada"
    );
    for (let i = 0; i < bundle.t_entries.length; i += 1) {
      if (i === chosenWindowIndex) continue;
      assert(
        proofJsonString.includes(JSON.stringify(bundle.t_entries[i])) === false,
        `a prova vazou o T completo da janela não autorizada ${i}`
      );
    }

    console.log("3) Garantindo que o holder não vazou tmp de outras janelas...");
    assert(
      proof.t_entry.tmp_b64 === bundle.tmp_vector_b64[chosenWindowIndex],
      "tmp da prova deveria ser o tmp da janela autorizada"
    );
    for (let i = 0; i < bundle.tmp_vector_b64.length; i += 1) {
      if (i === chosenWindowIndex) continue;
      assert(
        proofJsonString.includes(bundle.tmp_vector_b64[i]) === false,
        `a prova vazou tmp da janela não autorizada ${i}`
      );
    }

    console.log("4) Garantindo que o holder não vazou L além do necessário para Merkle...");
    const allowedLValues = new Set([proof.l_value, ...proof.merkle_path]);
    assert(
      proof.l_value === bundle.l_values[chosenWindowIndex],
      "l_value da prova deveria corresponder à janela autorizada"
    );
    for (let i = 0; i < bundle.l_values.length; i += 1) {
      const candidate = bundle.l_values[i];
      if (proofJsonString.includes(candidate)) {
        assert(
          allowedLValues.has(candidate),
          `a prova vazou um valor L fora da janela autorizada e fora do merkle_path: janela ${i}`
        );
      }
    }

    console.log("5) Verifier validando a prova com disclosure mínimo...");
    const verifierInput = {
      ...proof,
      manifest: null,
      k_ledger_anchor: null,
    };
    const verifyJson = await verifyPresentationRevocationProof(JSON.stringify(verifierInput));
    const verifyResponse = parseJsonSafe(verifyJson, "verify_response");
    assert(verifyResponse.ok === true, "verifyPresentationRevocationProof deveria retornar ok=true");
    assert(verifyResponse.status.verified === true, "o verifier deveria validar a prova localmente");
    assert(verifyResponse.status.revoked === false, "sem consulta Bloom, revoked deveria permanecer false");

    console.log("✅ OK: TESTE REVOGAÇÃO 31 passou.");
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 31:", e && e.stack ? e.stack : e);
  process.exit(1);
});
