/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
node teste-node/revocation/test_revocation_59_v2_incremental_confirmation_windows_confirm_real_revocation_von.js

Para subir o bfilter em modo de testes:
cd /home/yugi/programacao/bfilter
BFILTER_ENABLE_TEST_API=1 \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
cargo run
*/

/*
Teste E2E do fluxo v2 com confirmação incremental de revogação real.

Cenário:
- issuer emite 1 credencial com 365 janelas válidas e 10 extras de confirmação;
- issuer revoga a credencial a partir da última janela válida;
- holder primeiro envia só a última janela válida;
- verifier recebe hit e pede a próxima janela;
- holder entrega as janelas extras uma a uma;
- verifier só confirma revoked_by_policy quando esgota as 10 extras e totaliza 11 hits consecutivos.
*/

const crypto = require("crypto");
const path = require("path");
const {
  NETWORK_CONFIG,
  assert,
  downloadGenesisHttp,
  loadIndyAgent,
  fn,
  walletCreateOpenIdempotent,
  parseJsonSafe,
  extractNonce,
  cleanupWalletFamily,
  ensureWalletDir,
} = require("./_helpers");

const CONTROL_ATTRS = [
  "seed",
  "start_time",
  "unit_of_time",
  "time_window",
  "root_merkle_L",
];

const VALID_WINDOW_COUNT = 365;
const EXTRA_CONFIRMATION_WINDOWS = 10;
const PRIMARY_LAST_VALID_WINDOW_INDEX = VALID_WINDOW_COUNT - 1;

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function sha256Base64(input) {
  return crypto.createHash("sha256").update(input).digest("base64");
}

async function tryRegisterDid(agent, genesisFile, submitterDid, did, verkey, role) {
  try {
    await agent.registerDidOnLedger(genesisFile, submitterDid, did, verkey, role);
  } catch (e) {
    const msg = e?.message || String(e);
    if (/already exists|exists|DID.*exist|NYM.*exist|Ledger/i.test(msg)) {
      console.log(`ℹ️ DID já estava no ledger, seguindo: ${did}`);
      return;
    }
    throw e;
  }
}

async function fetchManifestEnvelope(baseUrl) {
  const resp = await fetch(`${baseUrl}/manifest`);
  assert(resp.ok, `Falha GET /manifest: ${resp.status}`);
  const manifestBodyText = await resp.text();
  const envelope = JSON.parse(manifestBodyText);
  assert(envelope.ok === true, "manifesto Bloom deveria retornar ok=true");
  envelope.manifest_hash_body = sha256Base64(manifestBodyText);
  return envelope;
}

function buildManifestAnchorFromEnvelope(issuerDid, baseUrl, manifestEnvelope) {
  return {
    issuer_did: issuerDid,
    manifest_url: `${baseUrl}/manifest`,
    manifest_hash: String(manifestEnvelope.manifest_hash_body || ""),
    manifest_version: String(manifestEnvelope?.manifest?.version || 1),
    updated_at: nowSec(),
  };
}

(async () => {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";
  const BFILTER_BASE_URL = (process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080").replace(/\/+$/, "");
  const TRUSTEE_SEED = process.env.TRUSTEE_SEED || NETWORK_CONFIG.trusteeSeed;
  const TRUSTEE_DID = process.env.TRUSTEE_DID || NETWORK_CONFIG.trusteeDid;
  const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_v2_incremental_real_revoke_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_v2_incremental_real_revoke_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_v2_incremental_real_revoke_verifier.db");

  const genesisAbs = path.join(process.cwd(), process.env.GENESIS_FILE || NETWORK_CONFIG.genesisFile);
  await downloadGenesisHttp(NETWORK_CONFIG.genesisUrl, genesisAbs);

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
    console.log("🚀 TESTE REVOGAÇÃO 59: confirmação incremental da revogação real com 10 extras");

    await issuer.connectNetwork(genesisAbs);
    await holder.connectNetwork(genesisAbs);
    await verifier.connectNetwork(genesisAbs);

    const importDidFromSeed = fn(issuer, "importDidFromSeed", "import_did_from_seed");
    const createAndRegisterSchema = fn(issuer, "createAndRegisterSchema", "create_and_register_schema");
    const creddefSaveLocal = fn(issuer, "creddefSaveLocal", "creddef_save_local");
    const creddefRegisterFromLocal = fn(issuer, "creddefRegisterFromLocal", "creddef_register_from_local");
    const fetchSchemaFromLedger = fn(issuer, "fetchSchemaFromLedger", "fetch_schema_from_ledger");
    const fetchCredDefFromLedger = fn(issuer, "fetchCredDefFromLedger", "fetch_cred_def_from_ledger");
    const createCredentialOffer = fn(issuer, "createCredentialOffer", "create_credential_offer");
    const createLinkSecret = fn(holder, "createLinkSecret", "create_link_secret");
    const createCredentialRequest = fn(holder, "createCredentialRequest", "create_credential_request");
    const storeCredential = fn(holder, "storeCredential", "store_credential");
    const revocationWriteManifestAnchorOnLedger = fn(
      issuer,
      "revocationWriteManifestAnchorOnLedger",
      "revocation_write_manifest_anchor_on_ledger"
    );
    const issueRevocableCredential = fn(issuer, "issueRevocableCredential", "issue_revocable_credential");
    const storeReceivedRevocableCredential = fn(
      holder,
      "storeReceivedRevocableCredential",
      "store_received_revocable_credential"
    );
    const buildPresentationRevocationProofV2 = fn(
      holder,
      "buildPresentationRevocationProofV2",
      "build_presentation_revocation_proof_v2"
    );
    const verifyPresentationRevocationProofV2 = fn(
      verifier,
      "verifyPresentationRevocationProofV2",
      "verify_presentation_revocation_proof_v2"
    );
    const revokeIssuedCredentialFromWindow = fn(
      issuer,
      "revokeIssuedCredentialFromWindow",
      "revoke_issued_credential_from_window"
    );

    console.log("1) Criando e registrando issuer, holder e verifier...");
    const [trusteeDid] = await importDidFromSeed(TRUSTEE_SEED);
    assert(trusteeDid === TRUSTEE_DID, `Trustee DID inesperado: ${trusteeDid}`);

    const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
    const [holderDid, holderVerkey] = await holder.createOwnDid();
    const [verifierDid, verifierVerkey] = await verifier.createOwnDid();

    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, issuerDid, issuerVerkey, "ENDORSER");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, holderDid, holderVerkey, "ENDORSER");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, verifierDid, verifierVerkey, "ENDORSER");

    console.log("2) Ancorando manifesto atual do Bloom no ledger...");
    const manifestEnvelope = await fetchManifestEnvelope(BFILTER_BASE_URL);
    const manifest = buildManifestAnchorFromEnvelope(issuerDid, BFILTER_BASE_URL, manifestEnvelope);
    const writeManifestJson = await revocationWriteManifestAnchorOnLedger(
      genesisAbs,
      issuerDid,
      JSON.stringify(manifest)
    );
    const writeManifest = parseJsonSafe(writeManifestJson, "write_manifest");
    assert(writeManifest.ok === true, "write manifesto falhou");

    console.log("3) Emitindo credencial com 365 janelas válidas + 10 extras...");
    const schemaIdRev = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRevV2IncrementalRealRevoke_${Date.now()}`,
      `1.${nowSec()}`,
      ["nome", "cpf", "idade", ...CONTROL_ATTRS]
    );

    const localJson = await creddefSaveLocal(
      issuerDid,
      schemaIdRev,
      `TAG_REV_V2_INCREMENTAL_REAL_REVOKE_${Date.now()}`,
      false,
      "prod"
    );
    const local = parseJsonSafe(localJson, "creddef_local");
    const reg = await creddefRegisterFromLocal(genesisAbs, local.id_local, issuerDid);
    const credDefIdRev = reg.credDefId || reg.cred_def_id;

    const schemaRevLedger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdRev), "schema_rev");
    const credDefRevLedger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdRev), "creddef_rev");

    try {
      await createLinkSecret("default");
    } catch (_) {}

    const startTime = nowSec();
    const validityEnd = startTime + 86400 * (VALID_WINDOW_COUNT - 1);
    const offerJson = await createCredentialOffer(credDefIdRev, `offer-v2-incremental-real-revoke-${Date.now()}`);
    const requestJson = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefRevLedger),
      offerJson
    );
    const requestMetadataId = extractNonce(offerJson);

    const issuedJson = await issueRevocableCredential(
      genesisAbs,
      `issued-v2-incremental-real-revoke-${Date.now()}`,
      holderDid,
      credDefIdRev,
      schemaIdRev,
      offerJson,
      requestJson,
      JSON.stringify({
        nome: "Alice Incremental Real Revoke",
        cpf: "12345678900",
        idade: "29",
      }),
      startTime,
      validityEnd,
      "days",
      1,
      EXTRA_CONFIRMATION_WINDOWS,
      JSON.stringify(manifest),
      null,
      null
    );
    const issued = parseJsonSafe(issuedJson, "issued_revocable_v2_incremental_real_revoke");
    assert(issued.control_values.base_window_count === VALID_WINDOW_COUNT, "base_window_count inválido");
    assert(issued.control_values.confirmation_window_count === EXTRA_CONFIRMATION_WINDOWS, "confirmation_window_count inválido");
    assert(issued.control_values.last_valid_window_index === PRIMARY_LAST_VALID_WINDOW_INDEX, "last_valid_window_index inválido");

    const credentialId = `cred-v2-incremental-real-revoke-${Date.now()}`;
    await storeCredential(
      credentialId,
      issued.credential_json,
      requestMetadataId,
      JSON.stringify(credDefRevLedger),
      null
    );

    const bundleId = `bundle-v2-incremental-real-revoke-${Date.now()}`;
    const storedBundleJson = await storeReceivedRevocableCredential(
      bundleId,
      JSON.stringify(issued.holder_bundle),
      credentialId
    );
    const storedBundle = parseJsonSafe(storedBundleJson, "stored_bundle");
    assert(storedBundle.ok === true, "bundle deveria ser armazenado com ok=true");

    console.log("4) Baseline: antes da revogação a última janela válida deve ser aceita...");
    const proofBeforeJson = await buildPresentationRevocationProofV2(
      bundleId,
      PRIMARY_LAST_VALID_WINDOW_INDEX,
      0,
      credentialId
    );
    const proofBefore = parseJsonSafe(proofBeforeJson, "proof_before");
    const policy = {
      max_consecutive_hits_for_revoke: 1 + EXTRA_CONFIRMATION_WINDOWS,
      max_windows_to_request: EXTRA_CONFIRMATION_WINDOWS,
      allow_post_expiry_confirmation_windows: true,
      holder_must_disprove_with_additional_windows: true,
    };
    const verifyBeforeJson = await verifyPresentationRevocationProofV2(
      JSON.stringify(proofBefore.proof_sequence),
      null,
      JSON.stringify(policy)
    );
    const verifyBefore = parseJsonSafe(verifyBeforeJson, "verify_before");
    assert(verifyBefore.ok === true, "verify_before deveria retornar ok=true");
    assert(verifyBefore.status.decision === "valid_not_revoked", "antes da revogação deveria ser valid_not_revoked");

    console.log("5) Issuer revogando a credencial a partir da última janela válida...");
    const revokeJson = await revokeIssuedCredentialFromWindow(
      issued.issuer_record.issuer_local_credential_id,
      BFILTER_ADMIN_TOKEN,
      PRIMARY_LAST_VALID_WINDOW_INDEX,
      "revogacao-real-para-confirmacao-incremental",
      "teste-node-revocation-59"
    );
    const revoke = parseJsonSafe(revokeJson, "revoke_from_last_valid_window");
    assert(revoke.ok === true, "revokeIssuedCredentialFromWindow deveria retornar ok=true");
    assert(revoke.revocation_keys_written === 1 + EXTRA_CONFIRMATION_WINDOWS, "deveriam ser gravadas 11 chaves");

    const manifestAfterEnvelope = await fetchManifestEnvelope(BFILTER_BASE_URL);
    const manifestAfter = buildManifestAnchorFromEnvelope(issuerDid, BFILTER_BASE_URL, manifestAfterEnvelope);
    const writeManifestAfterJson = await revocationWriteManifestAnchorOnLedger(
      genesisAbs,
      issuerDid,
      JSON.stringify(manifestAfter)
    );
    const writeManifestAfter = parseJsonSafe(writeManifestAfterJson, "write_manifest_after");
    assert(writeManifestAfter.ok === true, "reanchor do manifesto após revogação falhou");

    console.log("6) Holder entrega a última janela válida e depois as extras uma a uma...");
    const perStep = [];
    for (let additionalWindowCount = 0; additionalWindowCount <= EXTRA_CONFIRMATION_WINDOWS; additionalWindowCount++) {
      const proofJson = await buildPresentationRevocationProofV2(
        bundleId,
        PRIMARY_LAST_VALID_WINDOW_INDEX,
        additionalWindowCount,
        credentialId
      );
      const proofResponse = parseJsonSafe(proofJson, `proof_sequence_${additionalWindowCount}`);
      assert(proofResponse.ok === true, `proof_sequence_${additionalWindowCount} deveria retornar ok=true`);

      const proofSequence = {
        ...proofResponse.proof_sequence,
        primary_proof: {
          ...proofResponse.proof_sequence.primary_proof,
          manifest: writeManifestAfter.manifest,
        },
        confirmation_proofs: proofResponse.proof_sequence.confirmation_proofs.map((proof) => ({
          ...proof,
          manifest: writeManifestAfter.manifest,
        })),
      };

      const verifyJson = await verifyPresentationRevocationProofV2(
        JSON.stringify(proofSequence),
        null,
        JSON.stringify(policy)
      );
      const verify = parseJsonSafe(verifyJson, `verify_step_${additionalWindowCount}`);
      assert(verify.ok === true, `verify_step_${additionalWindowCount} deveria retornar ok=true`);

      const expectedHits = 1 + additionalWindowCount;
      assert(verify.status.consecutive_hits === expectedHits, `consecutive_hits inválido na etapa ${additionalWindowCount}`);
      assert(verify.status.trace.length === expectedHits, `trace length inválido na etapa ${additionalWindowCount}`);
      assert(
        verify.status.trace.every((item) => item.maybe_present === true),
        `todas as consultas deveriam dar hit na etapa ${additionalWindowCount}`
      );

      if (additionalWindowCount < EXTRA_CONFIRMATION_WINDOWS) {
        const expectedNextWindowIndex = PRIMARY_LAST_VALID_WINDOW_INDEX + additionalWindowCount + 1;
        assert(
          verify.status.decision === "needs_next_window",
          `na etapa ${additionalWindowCount} a decisão deveria ser needs_next_window`
        );
        assert(verify.status.revoked === false, `na etapa ${additionalWindowCount} não deveria confirmar revogação`);
        assert(verify.status.accepted === false, `na etapa ${additionalWindowCount} a apresentação não deveria ser aceita`);
        assert(
          verify.status.requires_more_windows === true,
          `na etapa ${additionalWindowCount} deveria pedir a próxima janela`
        );
        assert(
          verify.status.next_required_window_index === expectedNextWindowIndex,
          `na etapa ${additionalWindowCount} o verifier deveria pedir a janela ${expectedNextWindowIndex}`
        );
      } else {
        assert(verify.status.decision === "revoked_by_policy", "na etapa final a decisão deveria ser revoked_by_policy");
        assert(verify.status.revoked === true, "na etapa final a credencial deveria ser revogada");
        assert(verify.status.accepted === false, "na etapa final a apresentação não deveria ser aceita");
        assert(verify.status.requires_more_windows === false, "na etapa final não deveria pedir novas janelas");
      }

      perStep.push({
        additional_window_count: additionalWindowCount,
        checked_windows: expectedHits,
        decision: verify.status.decision,
        next_required_window_index: verify.status.next_required_window_index,
      });
    }

    const finalStep = perStep[perStep.length - 1];
    assert(finalStep.decision === "revoked_by_policy", "o passo final deveria confirmar revoked_by_policy");

    console.log("✅ OK: TESTE REVOGAÇÃO 59 passou.");
    console.log("📌 Resumo final:", {
      valid_window_count: VALID_WINDOW_COUNT,
      extra_confirmation_windows: EXTRA_CONFIRMATION_WINDOWS,
      primary_window_index: PRIMARY_LAST_VALID_WINDOW_INDEX,
      incremental_decisions: perStep,
      final_decision: finalStep.decision,
      final_checked_windows: finalStep.checked_windows,
    });
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
    try { await verifier.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 59:", e && e.stack ? e.stack : e);
  process.exit(1);
});
