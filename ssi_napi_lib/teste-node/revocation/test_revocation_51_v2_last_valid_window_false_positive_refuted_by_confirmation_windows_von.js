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
node teste-node/revocation/test_revocation_51_v2_last_valid_window_false_positive_refuted_by_confirmation_windows_von.js

Para subir o bfilter em modo de testes:
cd /home/yugi/programacao/bfilter
BFILTER_ENABLE_TEST_API=1 \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
cargo run
*/

/*
Teste E2E do fluxo v2 na borda da validade.

Objetivo:
- emitir uma credencial com 365 janelas válidas e 10 extras de confirmação disponíveis;
- usar como janela principal a última janela válida;
- induzir um falso positivo apenas nessa última janela válida;
- validar que, com só 1 janela, o verifier pede a próxima janela;
- validar que, quando o holder entrega 2 janelas extras pós-expiração, o falso positivo é refutado.

Esse teste garante que as janelas extras:
- não ampliam a validade da credencial;
- servem somente para confirmar ou refutar um falso positivo da última janela válida;
- podem existir em quantidade maior na credencial, embora o holder use aqui só as 2 primeiras necessárias.
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
const REQUIRED_EXTRA_WINDOWS_FOR_FP = 10;
const EXTRA_CONFIRMATION_WINDOWS = 2;
const PRIMARY_LAST_VALID_WINDOW_INDEX = VALID_WINDOW_COUNT - 1;
const TEST_FILTER_M_BITS = Number(process.env.TEST_FILTER_M_BITS || "256");
const TEST_FILTER_K = Number(process.env.TEST_FILTER_K || "3");
const DUMMY_BATCH_SIZE = Number(process.env.DUMMY_BATCH_SIZE || "32");
const MAX_FP_BATCHES = Number(process.env.MAX_FP_BATCHES || "200");

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

async function resetBfilterForTests(baseUrl, adminToken, mBits, k) {
  const resp = await fetch(`${baseUrl}/test/reset`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${adminToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      filter_id: `test-last-valid-fp-v2-${Date.now()}`,
      m_bits: mBits,
      k,
    }),
  });

  const bodyText = await resp.text();
  if (resp.status === 404) {
    throw new Error(
      "O endpoint /test/reset não está disponível. Suba o bfilter com BFILTER_ENABLE_TEST_API=1."
    );
  }

  assert(resp.ok, `Falha POST /test/reset: ${resp.status} ${bodyText}`);
  const body = JSON.parse(bodyText);
  assert(body.ok === true, "reset do bfilter deveria retornar ok=true");
  return body;
}

async function writeDummyRevocations({
  baseUrl,
  adminToken,
  issuerDid,
  targetWindowStart,
  count,
}) {
  const revocationKeys = Array.from({ length: count }, (_, idx) =>
    `dummy-last-valid-fp-v2-${Date.now()}-${process.pid}-${idx}-${Math.random()}`
  );
  const windowStarts = Array.from({ length: count }, () => targetWindowStart);

  const resp = await fetch(`${baseUrl}/admin/revocations/v2`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${adminToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      issuer_did: issuerDid,
      credential_record_id: `dummy-last-valid-fp-batch-${Date.now()}`,
      revocation_keys: revocationKeys,
      window_starts: windowStarts,
      reason: "force-false-positive-on-last-valid-window",
      requested_by: "teste-node-revocation-51",
    }),
  });

  const bodyText = await resp.text();
  assert(resp.ok, `Falha POST /admin/revocations/v2: ${resp.status} ${bodyText}`);
  const body = JSON.parse(bodyText);
  assert(body.ok === true, "escrita dummy no Bloom deveria retornar ok=true");
  return body;
}

function withManifestOnProofSequence(proofSequence, manifestAnchor) {
  return {
    ...proofSequence,
    primary_proof: {
      ...proofSequence.primary_proof,
      manifest: manifestAnchor,
    },
    confirmation_proofs: (proofSequence.confirmation_proofs || []).map((proof) => ({
      ...proof,
      manifest: manifestAnchor,
    })),
  };
}

(async () => {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";
  const BFILTER_BASE_URL = (process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080").replace(/\/+$/, "");
  const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";
  const TRUSTEE_SEED = process.env.TRUSTEE_SEED || NETWORK_CONFIG.trusteeSeed;
  const TRUSTEE_DID = process.env.TRUSTEE_DID || NETWORK_CONFIG.trusteeDid;

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_v2_last_valid_fp_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_v2_last_valid_fp_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_v2_last_valid_fp_verifier.db");

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
    console.log("🚀 TESTE REVOGAÇÃO 51: falso positivo na última janela válida refutado pelas janelas extras");

    console.log("1) Resetando o bfilter em modo de testes com filtro pequeno...");
    await resetBfilterForTests(BFILTER_BASE_URL, BFILTER_ADMIN_TOKEN, TEST_FILTER_M_BITS, TEST_FILTER_K);
    const manifestEnvelope = await fetchManifestEnvelope(BFILTER_BASE_URL);

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
    const createPresentationPackageWithRevocationV2 = fn(
      holder,
      "createPresentationPackageWithRevocationV2",
      "create_presentation_package_with_revocation_v2"
    );
    const verifyPresentationRevocationProofV2 = fn(
      verifier,
      "verifyPresentationRevocationProofV2",
      "verify_presentation_revocation_proof_v2"
    );
    const verifyMixedPresentationPackageV2 = fn(
      verifier,
      "verifyMixedPresentationPackageV2",
      "verify_mixed_presentation_package_v2"
    );

    console.log("2) Criando e registrando explicitamente issuer, holder e verifier...");
    const [trusteeDid] = await importDidFromSeed(TRUSTEE_SEED);
    assert(trusteeDid === TRUSTEE_DID, `Trustee DID inesperado: ${trusteeDid}`);

    const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
    const [holderDid, holderVerkey] = await holder.createOwnDid();
    const [verifierDid, verifierVerkey] = await verifier.createOwnDid();

    console.log("   - Issuer DID:", issuerDid);
    console.log("   - Holder DID:", holderDid);
    console.log("   - Verifier DID:", verifierDid);

    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, issuerDid, issuerVerkey, "ENDORSER");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, holderDid, holderVerkey, "ENDORSER");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, verifierDid, verifierVerkey, "ENDORSER");

    console.log("3) Ancorando manifesto do Bloom no ledger...");
    const manifest = buildManifestAnchorFromEnvelope(issuerDid, BFILTER_BASE_URL, manifestEnvelope);
    const writeManifestJson = await revocationWriteManifestAnchorOnLedger(
      genesisAbs,
      issuerDid,
      JSON.stringify(manifest)
    );
    const writeManifest = parseJsonSafe(writeManifestJson, "write_manifest");
    assert(writeManifest.ok === true, "write manifesto falhou");

    console.log("4) Emitindo credencial revogável com 365 janelas válidas + 10 extras disponíveis...");
    const schemaIdRev = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRevV2LastValidFalsePositive_${Date.now()}`,
      `1.${nowSec()}`,
      ["nome", "cpf", "idade", ...CONTROL_ATTRS]
    );

    const localJson = await creddefSaveLocal(
      issuerDid,
      schemaIdRev,
      `TAG_REV_V2_LAST_VALID_FP_${Date.now()}`,
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
    const offerJson = await createCredentialOffer(credDefIdRev, `offer-v2-last-valid-fp-${Date.now()}`);
    const requestJson = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefRevLedger),
      offerJson
    );
    const requestMetadataId = extractNonce(offerJson);

    const issuedJson = await issueRevocableCredential(
      genesisAbs,
      `issued-v2-last-valid-fp-${Date.now()}`,
      holderDid,
      credDefIdRev,
      schemaIdRev,
      offerJson,
      requestJson,
      JSON.stringify({
        nome: "Alice Last Valid FP V2",
        cpf: "12345678900",
        idade: "29",
      }),
      startTime,
      validityEnd,
      "days",
      1,
      REQUIRED_EXTRA_WINDOWS_FOR_FP,
      JSON.stringify(manifest),
      null,
      null
    );
    const issued = parseJsonSafe(issuedJson, "issued_revocable_v2_last_valid_fp");

    const credentialId = `cred-v2-last-valid-fp-${Date.now()}`;
    await storeCredential(
      credentialId,
      issued.credential_json,
      requestMetadataId,
      JSON.stringify(credDefRevLedger),
      null
    );

    const bundleId = `bundle-v2-last-valid-fp-${Date.now()}`;
    const storedBundleJson = await storeReceivedRevocableCredential(
      bundleId,
      JSON.stringify(issued.holder_bundle),
      credentialId
    );
    const storedBundle = parseJsonSafe(storedBundleJson, "stored_bundle");
    assert(storedBundle.ok === true, "bundle deveria ser armazenado com ok=true");

    const policy = {
      max_consecutive_hits_for_revoke: 11,
      max_windows_to_request: 10,
      allow_post_expiry_confirmation_windows: true,
      holder_must_disprove_with_additional_windows: true,
    };

    const primaryWindowStart = startTime + PRIMARY_LAST_VALID_WINDOW_INDEX * 86400;

    console.log("5) Holder preparando 2 versões da prova para a última janela válida...");
    const proofSequenceOneWindowJson = await buildPresentationRevocationProofV2(
      bundleId,
      PRIMARY_LAST_VALID_WINDOW_INDEX,
      0,
      credentialId
    );
    const proofSequenceOneWindow = parseJsonSafe(proofSequenceOneWindowJson, "proof_sequence_one_window");
    assert(proofSequenceOneWindow.ok === true, "proof_sequence_one_window deveria retornar ok=true");
    assert(
      proofSequenceOneWindow.proof_sequence.primary_proof.window_index === PRIMARY_LAST_VALID_WINDOW_INDEX,
      "a prova principal deveria usar a última janela válida"
    );
    assert(
      proofSequenceOneWindow.proof_sequence.confirmation_proofs.length === 0,
      "a primeira sequência não deveria ter janelas extras"
    );

    const proofSequenceThreeWindowsJson = await buildPresentationRevocationProofV2(
      bundleId,
      PRIMARY_LAST_VALID_WINDOW_INDEX,
      EXTRA_CONFIRMATION_WINDOWS,
      credentialId
    );
    const proofSequenceThreeWindows = parseJsonSafe(proofSequenceThreeWindowsJson, "proof_sequence_three_windows");
    assert(proofSequenceThreeWindows.ok === true, "proof_sequence_three_windows deveria retornar ok=true");
    assert(
      proofSequenceThreeWindows.proof_sequence.confirmation_proofs.length === EXTRA_CONFIRMATION_WINDOWS,
      "a sequência deveria conter 2 janelas extras de confirmação"
    );
    assert(
      proofSequenceThreeWindows.proof_sequence.confirmation_proofs[0].window_index === PRIMARY_LAST_VALID_WINDOW_INDEX + 1,
      "a primeira janela extra deveria ser imediatamente após a última janela válida"
    );
    assert(
      proofSequenceThreeWindows.proof_sequence.confirmation_proofs[1].window_index === PRIMARY_LAST_VALID_WINDOW_INDEX + 2,
      "a segunda janela extra deveria ser a janela subsequente"
    );

    console.log("6) Validando baseline: antes do falso positivo tudo deve ficar válido...");
    const isolatedBaselineJson = await verifyPresentationRevocationProofV2(
      JSON.stringify(proofSequenceThreeWindows.proof_sequence),
      null,
      JSON.stringify(policy)
    );
    const isolatedBaseline = parseJsonSafe(isolatedBaselineJson, "isolated_baseline");
    assert(isolatedBaseline.ok === true, "baseline isolado deveria retornar ok=true");
    assert(isolatedBaseline.status.decision === "valid_not_revoked", "baseline isolado deveria ser valid_not_revoked");

    const presReq = {
      nonce: String(Date.now() * 1000 + 67890),
      name: "ProofReqRevocationV2LastValidFalsePositive",
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
    let currentManifestAnchor = manifest;

    console.log("7) Forçando falso positivo apenas na última janela válida e capturando a refutação nas janelas extras...");
    let primaryWindowLooksRevoked = false;
    let fpBatchesUsed = 0;
    for (let attempt = 1; attempt <= MAX_FP_BATCHES; attempt++) {
      const proofSequenceOneWindowCurrent = withManifestOnProofSequence(
        proofSequenceOneWindow.proof_sequence,
        currentManifestAnchor
      );
      const proofSequenceThreeWindowsCurrent = withManifestOnProofSequence(
        proofSequenceThreeWindows.proof_sequence,
        currentManifestAnchor
      );
      const isolatedCheckJson = await verifyPresentationRevocationProofV2(
        JSON.stringify(proofSequenceOneWindowCurrent),
        null,
        JSON.stringify(policy)
      );
      const isolatedCheck = parseJsonSafe(isolatedCheckJson, `isolated_check_attempt_${attempt}`);
      if (isolatedCheck.status.decision === "needs_next_window") {
        const isolatedThreeWindowsCheckJson = await verifyPresentationRevocationProofV2(
          JSON.stringify(proofSequenceThreeWindowsCurrent),
          null,
          JSON.stringify(policy)
        );
        const isolatedThreeWindowsCheck = parseJsonSafe(
          isolatedThreeWindowsCheckJson,
          `isolated_three_windows_check_attempt_${attempt}`
        );
        if (isolatedThreeWindowsCheck.status.decision === "false_positive_confirmed") {
          primaryWindowLooksRevoked = true;
          fpBatchesUsed = attempt - 1;
          break;
        }
      }

      await writeDummyRevocations({
        baseUrl: BFILTER_BASE_URL,
        adminToken: BFILTER_ADMIN_TOKEN,
        issuerDid,
        targetWindowStart: primaryWindowStart,
        count: DUMMY_BATCH_SIZE,
      });
      const manifestCurrentEnvelope = await fetchManifestEnvelope(BFILTER_BASE_URL);
      currentManifestAnchor = buildManifestAnchorFromEnvelope(
        issuerDid,
        BFILTER_BASE_URL,
        manifestCurrentEnvelope
      );
    }
    assert(primaryWindowLooksRevoked, "não foi possível induzir falso positivo na última janela válida dentro do limite");

    const writeManifestAfterFpJson = await revocationWriteManifestAnchorOnLedger(
      genesisAbs,
      issuerDid,
      JSON.stringify(currentManifestAnchor)
    );
    const writeManifestAfterFp = parseJsonSafe(writeManifestAfterFpJson, "write_manifest_after_fp");
    assert(writeManifestAfterFp.ok === true, "reanchor do manifesto após falso positivo falhou");
    const proofSequenceOneWindowAfterFp = withManifestOnProofSequence(
      proofSequenceOneWindow.proof_sequence,
      writeManifestAfterFp.manifest
    );
    const proofSequenceThreeWindowsAfterFp = withManifestOnProofSequence(
      proofSequenceThreeWindows.proof_sequence,
      writeManifestAfterFp.manifest
    );

    console.log("8) Com só a última janela válida, o verifier deve pedir a próxima janela...");
    const isolatedOneWindowAfterFpJson = await verifyPresentationRevocationProofV2(
      JSON.stringify(proofSequenceOneWindowAfterFp),
      null,
      JSON.stringify(policy)
    );
    const isolatedOneWindowAfterFp = parseJsonSafe(isolatedOneWindowAfterFpJson, "isolated_one_window_after_fp");
    assert(isolatedOneWindowAfterFp.ok === true, "isolated_one_window_after_fp deveria retornar ok=true");
    assert(
      isolatedOneWindowAfterFp.status.decision === "needs_next_window",
      "com só a última janela válida o verifier deveria pedir a próxima janela"
    );
    assert(isolatedOneWindowAfterFp.status.accepted === false, "com só 1 janela a apresentação não deveria ser aceita");
    assert(isolatedOneWindowAfterFp.status.revoked === false, "com só 1 janela a credencial ainda não deveria ser confirmada como revogada");
    assert(isolatedOneWindowAfterFp.status.requires_more_windows === true, "com só 1 janela o verifier deveria pedir contraprova");

    console.log("9) O holder entrega as 2 janelas extras e refuta o falso positivo na borda da validade...");
    const isolatedThreeWindowsAfterFpJson = await verifyPresentationRevocationProofV2(
      JSON.stringify(proofSequenceThreeWindowsAfterFp),
      null,
      JSON.stringify(policy)
    );
    const isolatedThreeWindowsAfterFp = parseJsonSafe(isolatedThreeWindowsAfterFpJson, "isolated_three_windows_after_fp");
    assert(isolatedThreeWindowsAfterFp.ok === true, "isolated_three_windows_after_fp deveria retornar ok=true");
    assert(
      isolatedThreeWindowsAfterFp.status.decision === "false_positive_confirmed",
      "as janelas extras deveriam refutar o falso positivo da última janela válida"
    );
    assert(
      isolatedThreeWindowsAfterFp.status.trace.length >= 2 &&
        isolatedThreeWindowsAfterFp.status.trace[0].window_index === PRIMARY_LAST_VALID_WINDOW_INDEX &&
        isolatedThreeWindowsAfterFp.status.trace[0].maybe_present === true &&
        isolatedThreeWindowsAfterFp.status.trace[1].window_index === PRIMARY_LAST_VALID_WINDOW_INDEX + 1 &&
        isolatedThreeWindowsAfterFp.status.trace[1].maybe_present === false,
      "a refutação deveria aparecer como true,false usando a primeira janela extra"
    );
    assert(isolatedThreeWindowsAfterFp.status.accepted === true, "após a refutação a credencial deveria ser aceita");
    assert(isolatedThreeWindowsAfterFp.status.revoked === false, "após a refutação a credencial não deveria ser revogada");

    console.log("10) Confirmando o mesmo comportamento no agregador de apresentação v2...");
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

    const verifyMixedAfterFpJson = await verifyMixedPresentationPackageV2(
      JSON.stringify(presReq),
      presentationPackageV2.presentation_json,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap),
      JSON.stringify([
        {
          credential_id_local: credentialId,
          cred_def_id: credDefIdRev,
          proof_sequence: withManifestOnProofSequence(
            presentationPackageV2.revocation_proof_sequences[0].proof_sequence,
            writeManifestAfterFp.manifest
          ),
        },
      ]),
      null,
      JSON.stringify(policy)
    );
    const mixedAfterFp = parseJsonSafe(verifyMixedAfterFpJson, "mixed_after_fp");
    assert(mixedAfterFp.ok === true, "mixed_after_fp deveria retornar ok=true");
    assert(mixedAfterFp.cryptographic_valid === true, "a apresentação deve continuar criptograficamente válida");
    assert(mixedAfterFp.proofs_verified === true, "as provas devem continuar válidas");
    assert(mixedAfterFp.accepted === true, "a apresentação deveria ser aceita após a refutação do falso positivo");
    assert(mixedAfterFp.revoked === false, "o agregador não deveria marcar revogação");
    assert(mixedAfterFp.requires_more_windows === false, "o agregador não deveria pedir mais janelas");
    assert(
      mixedAfterFp.per_credential_status[0].revocation_status.decision === "false_positive_confirmed",
      "o agregador deveria consolidar false_positive_confirmed"
    );

    console.log("✅ OK: TESTE REVOGAÇÃO 51 passou.");
    console.log("📌 Resumo final:", {
      valid_window_count: VALID_WINDOW_COUNT,
      extra_confirmation_windows: EXTRA_CONFIRMATION_WINDOWS,
      primary_window_index: PRIMARY_LAST_VALID_WINDOW_INDEX,
      false_positive_batches_used: fpBatchesUsed,
      one_window_decision_after_fp: isolatedOneWindowAfterFp.status.decision,
      three_window_decision_after_fp: isolatedThreeWindowsAfterFp.status.decision,
      mixed_decision_after_fp: mixedAfterFp.per_credential_status[0].revocation_status.decision,
      accepted_after_fp_with_one_window: isolatedOneWindowAfterFp.status.accepted,
      accepted_after_fp_with_three_windows: isolatedThreeWindowsAfterFp.status.accepted,
      accepted_mixed_after_fp: mixedAfterFp.accepted,
    });
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
    try { await verifier.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 51:", e && e.stack ? e.stack : e);
  process.exit(1);
});
