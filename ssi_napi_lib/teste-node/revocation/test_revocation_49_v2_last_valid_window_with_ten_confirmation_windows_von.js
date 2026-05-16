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
node teste-node/revocation/test_revocation_49_v2_last_valid_window_with_ten_confirmation_windows_von.js

Para subir o bfilter:
cd /home/yugi/programacao/bfilter
BFILTER_ADMIN_TOKEN="dev-admin-token" cargo run
*/

/*
Teste E2E do fluxo v2 de revogação com esgotamento de todas as janelas de confirmação.

O cenário:
- cria issuer, holder e verifier;
- emite 1 credencial revogável com 365 janelas válidas e 10 extras de confirmação;
- holder monta uma apresentação e entrega 11 janelas ao verifier:
  - a última janela válida;
  - as 10 janelas extras de confirmação;
- verifier valida antes da revogação;
- issuer revoga a credencial a partir da última janela válida;
- verifier revalida o mesmo pacote v2.

Depois valida:
- antes da revogação a credencial é aceita;
- após a revogação, as 11 janelas ficam marcadas no Bloom;
- o verifier só decide revoked_by_policy quando todas as 11 consultas elegíveis retornam hit;
- as 10 janelas extras servem só para confirmação e não para ampliar validade.

Depois da revogação, o teste reancora o manifesto atualizado do Bloom
antes de revalidar a sequência v2.
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

(async () => {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";
  const BFILTER_BASE_URL = process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080";
  const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";
  const TRUSTEE_SEED = process.env.TRUSTEE_SEED || NETWORK_CONFIG.trusteeSeed;
  const TRUSTEE_DID = process.env.TRUSTEE_DID || NETWORK_CONFIG.trusteeDid;

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_v2_last_valid_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_v2_last_valid_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_v2_last_valid_verifier.db");

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
    const revocationBuildManifestAnchor = fn(
      issuer,
      "revocationBuildManifestAnchor",
      "revocation_build_manifest_anchor"
    );
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
    const createPresentationPackageWithRevocationV2 = fn(
      holder,
      "createPresentationPackageWithRevocationV2",
      "create_presentation_package_with_revocation_v2"
    );
    const verifyMixedPresentationPackageV2 = fn(
      verifier,
      "verifyMixedPresentationPackageV2",
      "verify_mixed_presentation_package_v2"
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

    console.log("🚀 TESTE REVOGAÇÃO 49: v2 com última janela válida + 10 janelas extras");

    console.log("1) Criando e registrando explicitamente os 3 atores SSI no ledger...");
    const [trusteeDid] = await importDidFromSeed(TRUSTEE_SEED);
    assert(trusteeDid === TRUSTEE_DID, `Trustee DID inesperado: ${trusteeDid}`);

    const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
    const [holderDid, holderVerkey] = await holder.createOwnDid();
    const [verifierDid, verifierVerkey] = await verifier.createOwnDid();

    assert(typeof issuerDid === "string" && issuerDid.length > 10, "issuerDid inválido");
    assert(typeof holderDid === "string" && holderDid.length > 10, "holderDid inválido");
    assert(typeof verifierDid === "string" && verifierDid.length > 10, "verifierDid inválido");

    console.log("   - Issuer DID:", issuerDid);
    console.log("   - Holder DID:", holderDid);
    console.log("   - Verifier DID:", verifierDid);

    console.log("   Registrando issuer como ENDORSER...");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, issuerDid, issuerVerkey, "ENDORSER");
    console.log("   Registrando holder como ENDORSER para deixá-lo visível no ledger durante o teste...");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, holderDid, holderVerkey, "ENDORSER");
    console.log("   Registrando verifier como ENDORSER para deixá-lo visível no ledger durante o teste...");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, verifierDid, verifierVerkey, "ENDORSER");

    console.log("2) Ancorando manifesto do Bloom no ledger...");
    const manifestResp = await fetch(`${BFILTER_BASE_URL}/manifest`);
    assert(manifestResp.ok, `Falha GET /manifest: ${manifestResp.status}`);
    const manifestBodyText = await manifestResp.text();
    const manifestEnvelope = JSON.parse(manifestBodyText);
    assert(manifestEnvelope.ok === true, "manifesto Bloom deveria retornar ok=true");
    const manifestHash = sha256Base64(manifestBodyText);

    const manifestJson = await revocationBuildManifestAnchor(
      issuerDid,
      `${BFILTER_BASE_URL}/manifest`,
      manifestHash,
      String(manifestEnvelope.manifest.version || 1)
    );
    const manifest = parseJsonSafe(manifestJson, "manifest_anchor");
    const writeManifestJson = await revocationWriteManifestAnchorOnLedger(
      genesisAbs,
      issuerDid,
      JSON.stringify(manifest)
    );
    const writeManifest = parseJsonSafe(writeManifestJson, "write_manifest");
    assert(writeManifest.ok === true, "write manifesto falhou");

    console.log("3) Registrando Schema/CredDef revogável...");
    const schemaIdRev = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRevV2LastWindow_${Date.now()}`,
      `1.${nowSec()}`,
      ["nome", "cpf", "idade", ...CONTROL_ATTRS]
    );

    const localJson = await creddefSaveLocal(issuerDid, schemaIdRev, `TAG_REV_V2_LAST_${Date.now()}`, false, "prod");
    const local = parseJsonSafe(localJson, "creddef_local");
    const reg = await creddefRegisterFromLocal(genesisAbs, local.id_local, issuerDid);
    const credDefIdRev = reg.credDefId || reg.cred_def_id;

    const schemaRevLedger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdRev), "schema_rev");
    const credDefRevLedger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdRev), "creddef_rev");

    try {
      await createLinkSecret("default");
    } catch (_) {}

    console.log("4) Emitindo credencial com 365 janelas válidas + 10 extras...");
    const startTime = nowSec();
    const validityEnd = startTime + 86400 * (VALID_WINDOW_COUNT - 1);
    const offerJson = await createCredentialOffer(credDefIdRev, `offer-v2-last-window-${Date.now()}`);
    const requestJson = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefRevLedger),
      offerJson
    );
    const requestMetadataId = extractNonce(offerJson);

    const issuedJson = await issueRevocableCredential(
      genesisAbs,
      `issued-v2-last-window-${Date.now()}`,
      holderDid,
      credDefIdRev,
      schemaIdRev,
      offerJson,
      requestJson,
      JSON.stringify({
        nome: "Alice V2 Last Window",
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
    const issued = parseJsonSafe(issuedJson, "issued_revocable_v2");

    assert(issued.control_values.window_count === VALID_WINDOW_COUNT + EXTRA_CONFIRMATION_WINDOWS, "window_count total inválido");
    assert(issued.control_values.base_window_count === VALID_WINDOW_COUNT, "base_window_count inválido");
    assert(issued.control_values.confirmation_window_count === EXTRA_CONFIRMATION_WINDOWS, "confirmation_window_count inválido");
    assert(issued.control_values.last_valid_window_index === PRIMARY_LAST_VALID_WINDOW_INDEX, "last_valid_window_index inválido");
    assert(
      issued.control_values.last_confirmation_window_index === VALID_WINDOW_COUNT + EXTRA_CONFIRMATION_WINDOWS - 1,
      "last_confirmation_window_index inválido"
    );

    const credentialId = `cred-v2-last-window-${Date.now()}`;
    await storeCredential(
      credentialId,
      issued.credential_json,
      requestMetadataId,
      JSON.stringify(credDefRevLedger),
      null
    );

    const bundleId = `bundle-v2-last-window-${Date.now()}`;
    const storedBundleJson = await storeReceivedRevocableCredential(
      bundleId,
      JSON.stringify(issued.holder_bundle),
      credentialId
    );
    const storedBundle = parseJsonSafe(storedBundleJson, "stored_bundle");
    assert(storedBundle.ok === true, "bundle deveria ser armazenado com ok=true");

    console.log("5) Holder criando apresentação e entregando 11 janelas ao verifier...");
    const presReq = {
      nonce: String(Date.now() * 1000 + 45678),
      name: "ProofReqRevocationV2LastValidWithConfirmation",
      version: "0.1",
      requested_attributes: {
        attr_nome: { name: "nome", restrictions: [{ cred_def_id: credDefIdRev }] },
        attr_cpf: { name: "cpf", restrictions: [{ cred_def_id: credDefIdRev }] },
        attr_seed: { name: "seed", restrictions: [{ cred_def_id: credDefIdRev }] },
        attr_start: { name: "start_time", restrictions: [{ cred_def_id: credDefIdRev }] },
        attr_unit: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefIdRev }] },
        attr_window: { name: "time_window", restrictions: [{ cred_def_id: credDefIdRev }] },
        attr_root: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefIdRev }] },
      },
      requested_predicates: {},
    };

    const reqCreds = {
      requested_attributes: {
        attr_nome: { cred_id: credentialId, revealed: true },
        attr_cpf: { cred_id: credentialId, revealed: true },
        attr_seed: { cred_id: credentialId, revealed: true },
        attr_start: { cred_id: credentialId, revealed: true },
        attr_unit: { cred_id: credentialId, revealed: true },
        attr_window: { cred_id: credentialId, revealed: true },
        attr_root: { cred_id: credentialId, revealed: true },
      },
      requested_predicates: {},
    };

    const schemasMap = { [schemaIdRev]: schemaRevLedger };
    const credDefsMap = { [credDefIdRev]: credDefRevLedger };
    const policy = {
      max_consecutive_hits_for_revoke: 1 + EXTRA_CONFIRMATION_WINDOWS,
      max_windows_to_request: EXTRA_CONFIRMATION_WINDOWS,
      allow_post_expiry_confirmation_windows: true,
    };

    const presentationPackageV2Json = await createPresentationPackageWithRevocationV2(
      JSON.stringify(presReq),
      JSON.stringify(reqCreds),
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap),
      JSON.stringify([
        {
          credential_id_local: credentialId,
          primary_window_index: PRIMARY_LAST_VALID_WINDOW_INDEX,
          additional_window_count: EXTRA_CONFIRMATION_WINDOWS,
        },
      ])
    );
    const presentationPackageV2 = parseJsonSafe(presentationPackageV2Json, "presentation_package_v2");
    assert(presentationPackageV2.ok === true, "presentation package v2 deveria retornar ok=true");
    assert(Array.isArray(presentationPackageV2.revocation_proof_sequences), "revocation_proof_sequences deveria ser array");
    assert(presentationPackageV2.revocation_proof_sequences.length === 1, "deveria existir 1 sequência de prova");
    const proofSequence = presentationPackageV2.revocation_proof_sequences[0].proof_sequence;
    assert(proofSequence.primary_proof.window_index === PRIMARY_LAST_VALID_WINDOW_INDEX, "janela principal inválida");
    assert(proofSequence.confirmation_proofs.length === EXTRA_CONFIRMATION_WINDOWS, "deveriam existir 10 provas de confirmação");
    assert(proofSequence.confirmation_proofs[0].window_index === PRIMARY_LAST_VALID_WINDOW_INDEX + 1, "primeira confirmação inválida");
    assert(
      proofSequence.confirmation_proofs[EXTRA_CONFIRMATION_WINDOWS - 1].window_index ===
        PRIMARY_LAST_VALID_WINDOW_INDEX + EXTRA_CONFIRMATION_WINDOWS,
      "última confirmação inválida"
    );

    console.log("6) Verifier validando antes da revogação...");
    const verifyBeforeJson = await verifyMixedPresentationPackageV2(
      JSON.stringify(presReq),
      presentationPackageV2.presentation_json,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap),
      JSON.stringify([
        {
          credential_id_local: credentialId,
          cred_def_id: credDefIdRev,
          proof_sequence: proofSequence,
        },
      ]),
      null,
      JSON.stringify(policy)
    );
    const before = parseJsonSafe(verifyBeforeJson, "verify_before_v2");
    assert(before.ok === true, "verify before v2 deveria retornar ok=true");
    assert(before.cryptographic_valid === true, "a apresentação deveria ser criptograficamente válida");
    assert(before.proofs_verified === true, "as provas deveriam verificar");
    assert(before.revoked === false, "antes da revogação não deveria haver status revoked");
    assert(before.requires_more_windows === false, "antes da revogação não deveria pedir mais janelas");
    assert(before.accepted === true, "antes da revogação a apresentação deveria ser aceita");
    assert(before.per_credential_status.length === 1, "deveria existir exatamente 1 status por credencial");
    assert(before.per_credential_status[0].revocation_status.decision === "valid_not_revoked", "decisão antes da revogação deveria ser valid_not_revoked");

    const isolatedBeforeJson = await verifyPresentationRevocationProofV2(
      JSON.stringify(proofSequence),
      null,
      JSON.stringify(policy)
    );
    const isolatedBefore = parseJsonSafe(isolatedBeforeJson, "isolated_before_v2");
    assert(isolatedBefore.ok === true, "verifyPresentationRevocationProofV2 antes deveria retornar ok=true");
    assert(isolatedBefore.status.decision === "valid_not_revoked", "decisão isolada antes da revogação inválida");

    console.log("7) Issuer revogando a credencial a partir da última janela válida...");
    const revokeJson = await revokeIssuedCredentialFromWindow(
      issued.issuer_record.issuer_local_credential_id,
      BFILTER_ADMIN_TOKEN,
      PRIMARY_LAST_VALID_WINDOW_INDEX,
      "revogacao-na-ultima-janela-valida-com-confirmacao-extra",
      "teste-node-revocation-49"
    );
    const revoke = parseJsonSafe(revokeJson, "revoke_from_last_valid_window");
    assert(revoke.ok === true, "revokeIssuedCredentialFromWindow deveria retornar ok=true");
    assert(revoke.revoke_from_window === PRIMARY_LAST_VALID_WINDOW_INDEX, "revogação deveria iniciar na última janela válida");
    assert(revoke.revocation_keys_written === 1 + EXTRA_CONFIRMATION_WINDOWS, "deveriam ser gravadas 11 chaves");
    assert(revoke.window_starts_written.length === 1 + EXTRA_CONFIRMATION_WINDOWS, "deveriam existir 11 window_starts gravados");
    assert(revoke.bloom.ok === true, "o Bloom deveria aceitar a revogação");

    const manifestAfterResp = await fetch(`${BFILTER_BASE_URL}/manifest`);
    assert(manifestAfterResp.ok, `Falha GET /manifest após revogação: ${manifestAfterResp.status}`);
    const manifestAfterBodyText = await manifestAfterResp.text();
    const manifestAfterEnvelope = JSON.parse(manifestAfterBodyText);
    assert(manifestAfterEnvelope.ok === true, "manifesto Bloom pós-revogação deveria retornar ok=true");
    const manifestAfterHash = sha256Base64(manifestAfterBodyText);
    const manifestAfterJson = await revocationBuildManifestAnchor(
      issuerDid,
      `${BFILTER_BASE_URL}/manifest`,
      manifestAfterHash,
      String(manifestAfterEnvelope.manifest.version || 1)
    );
    const writeManifestAfter = parseJsonSafe(
      await revocationWriteManifestAnchorOnLedger(genesisAbs, issuerDid, manifestAfterJson),
      "write_manifest_after"
    );
    assert(writeManifestAfter.ok === true, "reanchor do manifesto após revogação falhou");
    const proofSequenceAfter = {
      ...proofSequence,
      primary_proof: {
        ...proofSequence.primary_proof,
        manifest: writeManifestAfter.manifest,
      },
      confirmation_proofs: proofSequence.confirmation_proofs.map((proof) => ({
        ...proof,
        manifest: writeManifestAfter.manifest,
      })),
    };

    console.log("8) Verifier revalidando com os novos recursos anti-falso-positivo...");
    const verifyAfterJson = await verifyMixedPresentationPackageV2(
      JSON.stringify(presReq),
      presentationPackageV2.presentation_json,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap),
      JSON.stringify([
        {
          credential_id_local: credentialId,
          cred_def_id: credDefIdRev,
          proof_sequence: proofSequenceAfter,
        },
      ]),
      null,
      JSON.stringify(policy)
    );
    const after = parseJsonSafe(verifyAfterJson, "verify_after_v2");
    assert(after.ok === true, "verify after v2 deveria retornar ok=true");
    assert(after.cryptographic_valid === true, "a apresentação deve continuar criptograficamente válida");
    assert(after.proofs_verified === true, "as provas complementares devem continuar válidas");
    assert(after.revoked === true, "a credencial deveria ser considerada revogada");
    assert(after.requires_more_windows === false, "não deveria ser necessário pedir novas janelas");
    assert(after.accepted === false, "a apresentação não deveria ser aceita após a revogação");

    const afterStatus = after.per_credential_status[0];
    assert(afterStatus.revoked === true, "o status consolidado deveria marcar revoked=true");
    assert(afterStatus.accepted === false, "o status consolidado não deveria ser aceito");
    assert(afterStatus.requires_more_windows === false, "o status consolidado não deveria pedir mais janelas");
    assert(afterStatus.revocation_status.decision === "revoked_by_policy", "a decisão deveria ser revoked_by_policy");
    assert(afterStatus.revocation_status.consecutive_hits === 1 + EXTRA_CONFIRMATION_WINDOWS, "deveriam existir 11 hits consecutivos");
    assert(Array.isArray(afterStatus.revocation_status.trace), "trace deveria ser array");
    assert(afterStatus.revocation_status.trace.length === 1 + EXTRA_CONFIRMATION_WINDOWS, "trace deveria conter exatamente 11 verificações");
    assert(
      afterStatus.revocation_status.trace.every((item) => item.maybe_present === true),
      "as 11 janelas deveriam estar marcadas como maybe_present=true após a revogação"
    );

    const isolatedAfterJson = await verifyPresentationRevocationProofV2(
      JSON.stringify(proofSequenceAfter),
      null,
      JSON.stringify(policy)
    );
    const isolatedAfter = parseJsonSafe(isolatedAfterJson, "isolated_after_v2");
    assert(isolatedAfter.ok === true, "verifyPresentationRevocationProofV2 após deveria retornar ok=true");
    assert(isolatedAfter.status.decision === "revoked_by_policy", "decisão isolada após a revogação inválida");
    assert(isolatedAfter.status.revoked === true, "status isolado deveria marcar revoked=true");
    assert(isolatedAfter.status.trace.length === 1 + EXTRA_CONFIRMATION_WINDOWS, "status isolado deveria verificar 11 janelas");

    console.log("✅ OK: TESTE REVOGAÇÃO 49 passou.");
    console.log("📌 Resumo final:", {
      valid_window_count: VALID_WINDOW_COUNT,
      extra_confirmation_windows: EXTRA_CONFIRMATION_WINDOWS,
      primary_window_index: PRIMARY_LAST_VALID_WINDOW_INDEX,
      decision_before: before.per_credential_status[0].revocation_status.decision,
      decision_after: after.per_credential_status[0].revocation_status.decision,
      consecutive_hits_after: after.per_credential_status[0].revocation_status.consecutive_hits,
      trace_len_after: after.per_credential_status[0].revocation_status.trace.length,
      accepted_before: before.accepted,
      accepted_after: after.accepted,
    });
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
    try { await verifier.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 49:", e && e.stack ? e.stack : e);
  process.exit(1);
});
