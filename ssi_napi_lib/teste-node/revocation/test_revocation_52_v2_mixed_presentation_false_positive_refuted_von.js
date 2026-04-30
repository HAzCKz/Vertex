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
node teste-node/revocation/test_revocation_52_v2_mixed_presentation_false_positive_refuted_von.js

Para subir o bfilter em modo de testes:
cd /home/yugi/programacao/bfilter
BFILTER_ENABLE_TEST_API=1 \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
cargo run
*/

/*
Teste E2E do fluxo v2 em apresentação mista.

Cenário:
- 1 credencial normal;
- 1 credencial revogável com 10 janelas extras disponíveis para confirmação;
- o holder apresenta ambas no mesmo pacote;
- a credencial revogável sofre um falso positivo controlado;
- com só 1 janela da credencial revogável, o pacote misto é rejeitado com needs_next_window;
- com 3 janelas no total para a credencial revogável, o falso positivo é refutado e o pacote volta a ser aceito.
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

const PRIMARY_WINDOW_INDEX = 10;
const REQUIRED_EXTRA_WINDOWS_FOR_FP = 10;
const ADDITIONAL_CONFIRMATION_WINDOWS = 2;
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
      filter_id: `test-mixed-fp-v2-${Date.now()}`,
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
    `dummy-mixed-fp-v2-${Date.now()}-${process.pid}-${idx}-${Math.random()}`
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
      credential_record_id: `dummy-mixed-fp-batch-${Date.now()}`,
      revocation_keys: revocationKeys,
      window_starts: windowStarts,
      reason: "force-false-positive-for-mixed-v2-test",
      requested_by: "teste-node-revocation-52",
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
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_v2_mixed_fp_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_v2_mixed_fp_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_v2_mixed_fp_verifier.db");

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
    console.log("🚀 TESTE REVOGAÇÃO 52: apresentação mista com falso positivo refutado");

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
    const createCredential = fn(issuer, "createCredential", "create_credential");
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

    console.log("4) Registrando 1 Schema/CredDef normal e 1 revogável...");
    const schemaIdNormal = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaNormalMixedV2_${Date.now()}`,
      `1.${nowSec()}`,
      ["nome", "matricula", "curso"]
    );
    const schemaIdRev = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRevMixedV2_${Date.now()}`,
      `1.${nowSec() + 1}`,
      ["nome", "cpf", "idade", ...CONTROL_ATTRS]
    );

    async function registerCredDef(schemaId, tag) {
      const localJson = await creddefSaveLocal(issuerDid, schemaId, tag, false, "prod");
      const local = parseJsonSafe(localJson, `creddef_local_${tag}`);
      const reg = await creddefRegisterFromLocal(genesisAbs, local.id_local, issuerDid);
      return reg.credDefId || reg.cred_def_id;
    }

    const credDefIdNormal = await registerCredDef(schemaIdNormal, `TAG_NORMAL_MIXED_V2_${Date.now()}`);
    const credDefIdRev = await registerCredDef(schemaIdRev, `TAG_REV_MIXED_V2_${Date.now()}`);

    const schemaNormalLedger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdNormal), "schema_normal");
    const schemaRevLedger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdRev), "schema_rev");
    const credDefNormalLedger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdNormal), "creddef_normal");
    const credDefRevLedger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdRev), "creddef_rev");

    try {
      await createLinkSecret("default");
    } catch (_) {}

    console.log("5) Emitindo a credencial normal...");
    const offerNormalJson = await createCredentialOffer(credDefIdNormal, `offer-normal-mixed-v2-${Date.now()}`);
    const requestNormalJson = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefNormalLedger),
      offerNormalJson
    );
    const requestNormalMetadataId = extractNonce(offerNormalJson);
    const normalCredentialJson = await createCredential(
      credDefIdNormal,
      offerNormalJson,
      requestNormalJson,
      JSON.stringify({
        nome: "Alice Normal V2",
        matricula: "2026001",
        curso: "Computacao",
      })
    );
    const normalCredentialId = `cred-normal-mixed-v2-${Date.now()}`;
    await storeCredential(
      normalCredentialId,
      normalCredentialJson,
      requestNormalMetadataId,
      JSON.stringify(credDefNormalLedger),
      null
    );

    console.log("6) Emitindo a credencial revogável...");
    const startTime = nowSec();
    const validityEnd = startTime + 86400 * 29;
    const offerRevJson = await createCredentialOffer(credDefIdRev, `offer-rev-mixed-v2-${Date.now()}`);
    const requestRevJson = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefRevLedger),
      offerRevJson
    );
    const requestRevMetadataId = extractNonce(offerRevJson);

    const issuedRevJson = await issueRevocableCredential(
      genesisAbs,
      `issued-rev-mixed-v2-${Date.now()}`,
      holderDid,
      credDefIdRev,
      schemaIdRev,
      offerRevJson,
      requestRevJson,
      JSON.stringify({
        nome: "Alice Rev V2",
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
    const issuedRev = parseJsonSafe(issuedRevJson, "issued_rev");

    const revCredentialId = `cred-rev-mixed-v2-${Date.now()}`;
    await storeCredential(
      revCredentialId,
      issuedRev.credential_json,
      requestRevMetadataId,
      JSON.stringify(credDefRevLedger),
      null
    );

    const bundleId = `bundle-rev-mixed-v2-${Date.now()}`;
    const storedBundleJson = await storeReceivedRevocableCredential(
      bundleId,
      JSON.stringify(issuedRev.holder_bundle),
      revCredentialId
    );
    const storedBundle = parseJsonSafe(storedBundleJson, "stored_bundle");
    assert(storedBundle.ok === true, "bundle deveria ser armazenado com ok=true");

    const policy = {
      max_consecutive_hits_for_revoke: 11,
      max_windows_to_request: 10,
      allow_post_expiry_confirmation_windows: true,
      holder_must_disprove_with_additional_windows: true,
    };

    const primaryWindowStart = startTime + PRIMARY_WINDOW_INDEX * 86400;
    const schemasMap = {
      [schemaIdNormal]: schemaNormalLedger,
      [schemaIdRev]: schemaRevLedger,
    };
    const credDefsMap = {
      [credDefIdNormal]: credDefNormalLedger,
      [credDefIdRev]: credDefRevLedger,
    };
    let currentManifestAnchor = manifest;

    const presReq = {
      nonce: String(Date.now() * 1000 + 78901),
      name: "ProofReqMixedRevocationV2FalsePositive",
      version: "0.1",
      requested_attributes: {
        attr_normal_nome: { name: "nome", restrictions: [{ cred_def_id: credDefIdNormal }] },
        attr_normal_matricula: { name: "matricula", restrictions: [{ cred_def_id: credDefIdNormal }] },
        attr_normal_curso: { name: "curso", restrictions: [{ cred_def_id: credDefIdNormal }] },
        attr_rev_nome: { name: "nome", restrictions: [{ cred_def_id: credDefIdRev }] },
        attr_rev_cpf: { name: "cpf", restrictions: [{ cred_def_id: credDefIdRev }] },
        attr_rev_seed: { name: "seed", restrictions: [{ cred_def_id: credDefIdRev }] },
        attr_rev_start: { name: "start_time", restrictions: [{ cred_def_id: credDefIdRev }] },
        attr_rev_unit: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefIdRev }] },
        attr_rev_window: { name: "time_window", restrictions: [{ cred_def_id: credDefIdRev }] },
        attr_rev_root: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefIdRev }] },
      },
      requested_predicates: {},
    };
    const reqCreds = {
      requested_attributes: {
        attr_normal_nome: { cred_id: normalCredentialId, revealed: true },
        attr_normal_matricula: { cred_id: normalCredentialId, revealed: true },
        attr_normal_curso: { cred_id: normalCredentialId, revealed: true },
        attr_rev_nome: { cred_id: revCredentialId, revealed: true },
        attr_rev_cpf: { cred_id: revCredentialId, revealed: true },
        attr_rev_seed: { cred_id: revCredentialId, revealed: true },
        attr_rev_start: { cred_id: revCredentialId, revealed: true },
        attr_rev_unit: { cred_id: revCredentialId, revealed: true },
        attr_rev_window: { cred_id: revCredentialId, revealed: true },
        attr_rev_root: { cred_id: revCredentialId, revealed: true },
      },
      requested_predicates: {},
    };

    console.log("7) Baseline: apresentação mista com 3 janelas deve ser aceita...");
    const oneWindowPackageJson = await createPresentationPackageWithRevocationV2(
      JSON.stringify(presReq),
      JSON.stringify(reqCreds),
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap),
      JSON.stringify([
        {
          credential_id_local: revCredentialId,
          primary_window_index: PRIMARY_WINDOW_INDEX,
          additional_window_count: 0,
        },
      ])
    );
    const oneWindowPackage = parseJsonSafe(oneWindowPackageJson, "one_window_package");
    assert(oneWindowPackage.ok === true, "one_window_package deveria retornar ok=true");

    const threeWindowPackageJson = await createPresentationPackageWithRevocationV2(
      JSON.stringify(presReq),
      JSON.stringify(reqCreds),
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap),
      JSON.stringify([
        {
          credential_id_local: revCredentialId,
          primary_window_index: PRIMARY_WINDOW_INDEX,
          additional_window_count: ADDITIONAL_CONFIRMATION_WINDOWS,
        },
      ])
    );
    const threeWindowPackage = parseJsonSafe(threeWindowPackageJson, "three_window_package");
    assert(threeWindowPackage.ok === true, "three_window_package deveria retornar ok=true");
    assert(threeWindowPackage.used_credentials.length === 2, "a apresentação mista deveria usar 2 credenciais");

    const baselineVerifyJson = await verifyMixedPresentationPackageV2(
      JSON.stringify(presReq),
      threeWindowPackage.presentation_json,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap),
      JSON.stringify([
        {
          credential_id_local: revCredentialId,
          cred_def_id: credDefIdRev,
          proof_sequence: threeWindowPackage.revocation_proof_sequences[0].proof_sequence,
        },
      ]),
      null,
      JSON.stringify(policy)
    );
    const baselineVerify = parseJsonSafe(baselineVerifyJson, "baseline_verify");
    assert(baselineVerify.ok === true, "baseline_verify deveria retornar ok=true");
    assert(baselineVerify.accepted === true, "o baseline misto deveria ser aceito");
    assert(baselineVerify.cryptographic_valid === true, "o baseline misto deveria ser criptograficamente válido");
    assert(baselineVerify.proofs_verified === true, "o baseline misto deveria verificar as provas");

    console.log("8) Forçando falso positivo na janela revogável usada na apresentação e capturando a contraprova no pacote misto...");
    let primaryWindowLooksRevoked = false;
    let fpBatchesUsed = 0;
    for (let attempt = 1; attempt <= MAX_FP_BATCHES; attempt++) {
      const oneWindowVerifyJson = await verifyMixedPresentationPackageV2(
        JSON.stringify(presReq),
        oneWindowPackage.presentation_json,
        JSON.stringify(schemasMap),
        JSON.stringify(credDefsMap),
        JSON.stringify([
          {
            credential_id_local: revCredentialId,
            cred_def_id: credDefIdRev,
            proof_sequence: withManifestOnProofSequence(
              oneWindowPackage.revocation_proof_sequences[0].proof_sequence,
              currentManifestAnchor
            ),
          },
        ]),
        null,
        JSON.stringify(policy)
      );
      const oneWindowVerify = parseJsonSafe(oneWindowVerifyJson, `one_window_verify_attempt_${attempt}`);
      if (
        oneWindowVerify.per_credential_status.some(
          (item) => item.revocation_status && item.revocation_status.decision === "needs_next_window"
        )
      ) {
        const threeWindowVerifyJson = await verifyMixedPresentationPackageV2(
          JSON.stringify(presReq),
          threeWindowPackage.presentation_json,
          JSON.stringify(schemasMap),
          JSON.stringify(credDefsMap),
          JSON.stringify([
            {
              credential_id_local: revCredentialId,
              cred_def_id: credDefIdRev,
              proof_sequence: withManifestOnProofSequence(
                threeWindowPackage.revocation_proof_sequences[0].proof_sequence,
                currentManifestAnchor
              ),
            },
          ]),
          null,
          JSON.stringify(policy)
        );
        const threeWindowVerify = parseJsonSafe(
          threeWindowVerifyJson,
          `three_window_verify_attempt_${attempt}`
        );
        if (
          threeWindowVerify.per_credential_status.some(
            (item) =>
              item.revocation_status &&
              item.revocation_status.decision === "false_positive_confirmed"
          )
        ) {
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
    assert(primaryWindowLooksRevoked, "não foi possível induzir falso positivo na credencial revogável do pacote misto");

    const writeManifestAfterFpJson = await revocationWriteManifestAnchorOnLedger(
      genesisAbs,
      issuerDid,
      JSON.stringify(currentManifestAnchor)
    );
    const writeManifestAfterFp = parseJsonSafe(writeManifestAfterFpJson, "write_manifest_after_fp");
    assert(writeManifestAfterFp.ok === true, "reanchor do manifesto após falso positivo falhou");

    console.log("9) Com só 1 janela para a credencial revogável, o pacote misto deve ser rejeitado...");
    const oneWindowVerifyJson = await verifyMixedPresentationPackageV2(
      JSON.stringify(presReq),
      oneWindowPackage.presentation_json,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap),
      JSON.stringify([
        {
          credential_id_local: revCredentialId,
          cred_def_id: credDefIdRev,
          proof_sequence: withManifestOnProofSequence(
            oneWindowPackage.revocation_proof_sequences[0].proof_sequence,
            writeManifestAfterFp.manifest
          ),
        },
      ]),
      null,
      JSON.stringify(policy)
    );
    const oneWindowVerify = parseJsonSafe(oneWindowVerifyJson, "one_window_verify");
    assert(oneWindowVerify.ok === true, "one_window_verify deveria retornar ok=true");
    assert(oneWindowVerify.accepted === false, "o pacote misto deveria ser rejeitado com só 1 janela");
    assert(oneWindowVerify.revoked === false, "o pacote misto não deveria confirmar revogação com só 1 janela");
    assert(oneWindowVerify.requires_more_windows === true, "o pacote misto deveria pedir a próxima janela");
    assert(oneWindowVerify.cryptographic_valid === true, "a prova criptográfica do pacote misto deve continuar válida");

    const oneWindowNormalStatus = oneWindowVerify.per_credential_status.find((item) => item.revocable === false);
    const oneWindowRevStatus = oneWindowVerify.per_credential_status.find((item) => item.revocable === true);
    assert(oneWindowNormalStatus, "o pacote misto deveria incluir status da credencial normal");
    assert(oneWindowNormalStatus.accepted === true, "a credencial normal deveria continuar aceita");
    assert(oneWindowRevStatus, "o pacote misto deveria incluir status da credencial revogável");
    assert(
      oneWindowRevStatus.revocation_status.decision === "needs_next_window",
      "a credencial revogável deveria pedir a próxima janela sem confirmar revogação"
    );

    console.log("10) O holder entrega 3 janelas para a credencial revogável e refuta o falso positivo...");
    const threeWindowVerifyJson = await verifyMixedPresentationPackageV2(
      JSON.stringify(presReq),
      threeWindowPackage.presentation_json,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap),
      JSON.stringify([
        {
          credential_id_local: revCredentialId,
          cred_def_id: credDefIdRev,
          proof_sequence: withManifestOnProofSequence(
            threeWindowPackage.revocation_proof_sequences[0].proof_sequence,
            writeManifestAfterFp.manifest
          ),
        },
      ]),
      null,
      JSON.stringify(policy)
    );
    const threeWindowVerify = parseJsonSafe(threeWindowVerifyJson, "three_window_verify");
    assert(threeWindowVerify.ok === true, "three_window_verify deveria retornar ok=true");
    assert(threeWindowVerify.accepted === true, "o pacote misto deveria voltar a ser aceito");
    assert(threeWindowVerify.revoked === false, "o pacote misto não deveria manter revogação após a refutação");
    assert(threeWindowVerify.cryptographic_valid === true, "a prova criptográfica do pacote misto deve continuar válida");
    assert(threeWindowVerify.proofs_verified === true, "as provas complementares devem continuar válidas");

    const threeWindowNormalStatus = threeWindowVerify.per_credential_status.find((item) => item.revocable === false);
    const threeWindowRevStatus = threeWindowVerify.per_credential_status.find((item) => item.revocable === true);
    assert(threeWindowNormalStatus, "o pacote misto deveria manter o status da credencial normal");
    assert(threeWindowNormalStatus.accepted === true, "a credencial normal deveria continuar aceita");
    assert(threeWindowRevStatus, "o pacote misto deveria manter o status da credencial revogável");
    assert(
      threeWindowRevStatus.revocation_status.decision === "false_positive_confirmed",
      "a credencial revogável deveria ser reclassificada como false_positive_confirmed"
    );
    assert(
      threeWindowRevStatus.revocation_status.trace.length >= 2 &&
        threeWindowRevStatus.revocation_status.trace[0].maybe_present === true &&
        threeWindowRevStatus.revocation_status.trace[1].maybe_present === false,
      "a refutação do falso positivo deveria aparecer como true,false"
    );

    console.log("✅ OK: TESTE REVOGAÇÃO 52 passou.");
    console.log("📌 Resumo final:", {
      primary_window_index: PRIMARY_WINDOW_INDEX,
      false_positive_batches_used: fpBatchesUsed,
      one_window_mixed_accepted: oneWindowVerify.accepted,
      one_window_revocation_decision: oneWindowRevStatus.revocation_status.decision,
      three_window_mixed_accepted: threeWindowVerify.accepted,
      three_window_revocation_decision: threeWindowRevStatus.revocation_status.decision,
      normal_credential_still_accepted: threeWindowNormalStatus.accepted,
    });
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
    try { await verifier.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 52:", e && e.stack ? e.stack : e);
  process.exit(1);
});
