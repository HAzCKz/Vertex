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
node teste-node/revocation/test_revocation_58_v2_default_ten_confirmation_windows_do_not_extend_validity_von.js

Para subir o bfilter em modo de testes:
cd /home/yugi/programacao/bfilter
BFILTER_ENABLE_TEST_API=1 \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
cargo run
*/

/*
Teste E2E do fluxo v2 para provar que:
- uma credencial emitida sem informar extra_windows_for_fp recebe 10 janelas extras por padrão;
- a validade continua sendo definida só por start_time + unit_of_time + time_window;
- as 10 janelas extras ficam depois da última janela válida;
- nenhuma dessas janelas extras pode ser usada como primary_window_index.
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

const VALID_WINDOW_COUNT = 3;
const DEFAULT_EXTRA_CONFIRMATION_WINDOWS = 10;
const PRIMARY_LAST_VALID_WINDOW_INDEX = VALID_WINDOW_COUNT - 1;
const FIRST_CONFIRMATION_ONLY_WINDOW_INDEX = VALID_WINDOW_COUNT;
const TEST_FILTER_M_BITS = Number(process.env.TEST_FILTER_M_BITS || "200000");
const TEST_FILTER_K = Number(process.env.TEST_FILTER_K || "3");

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
      filter_id: `test-v2-default-10-extra-${Date.now()}`,
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

async function expectAsyncThrows(fnAsync, expectedSnippet) {
  try {
    await fnAsync();
  } catch (e) {
    const msg = e?.message || String(e);
    assert(
      msg.includes(expectedSnippet),
      `erro inesperado. Esperava conter '${expectedSnippet}', veio: ${msg}`
    );
    return msg;
  }

  throw new Error(`era esperado erro contendo '${expectedSnippet}', mas a chamada foi aceita`);
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
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_v2_default_10_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_v2_default_10_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_v2_default_10_verifier.db");

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
    console.log("🚀 TESTE REVOGAÇÃO 58: 10 janelas extras padrão sem estender validade");

    console.log("1) Resetando o bfilter para um estado limpo...");
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

    console.log("2) Criando e registrando issuer, holder e verifier...");
    const [trusteeDid] = await importDidFromSeed(TRUSTEE_SEED);
    assert(trusteeDid === TRUSTEE_DID, `Trustee DID inesperado: ${trusteeDid}`);

    const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
    const [holderDid, holderVerkey] = await holder.createOwnDid();
    const [verifierDid, verifierVerkey] = await verifier.createOwnDid();

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

    console.log("4) Emitindo credencial revogável sem informar extra_windows_for_fp...");
    const schemaIdRev = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRevV2Default10Extra_${Date.now()}`,
      `1.${nowSec()}`,
      ["nome", "cpf", "idade", ...CONTROL_ATTRS]
    );

    const localJson = await creddefSaveLocal(
      issuerDid,
      schemaIdRev,
      `TAG_REV_V2_DEFAULT_10_${Date.now()}`,
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
    const offerJson = await createCredentialOffer(credDefIdRev, `offer-v2-default-10-${Date.now()}`);
    const requestJson = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefRevLedger),
      offerJson
    );
    const requestMetadataId = extractNonce(offerJson);

    const issuedJson = await issueRevocableCredential(
      genesisAbs,
      `issued-v2-default-10-${Date.now()}`,
      holderDid,
      credDefIdRev,
      schemaIdRev,
      offerJson,
      requestJson,
      JSON.stringify({
        nome: "Alice Default 10",
        cpf: "12345678900",
        idade: "29",
      }),
      startTime,
      validityEnd,
      "days",
      1,
      null,
      JSON.stringify(manifest),
      null,
      null
    );
    const issued = parseJsonSafe(issuedJson, "issued_revocable_v2_default_10");

    const expectedValidWindowCount = Math.floor((validityEnd - startTime) / 86400) + 1;
    assert(expectedValidWindowCount === VALID_WINDOW_COUNT, "cálculo esperado de janelas válidas inválido");
    assert(issued.control_values.start_time === startTime, "start_time inválido");
    assert(issued.control_values.validity_end === validityEnd, "validity_end inválido");
    assert(issued.control_values.unit_of_time === "days", "unit_of_time inválido");
    assert(issued.control_values.time_window === 1, "time_window inválido");
    assert(issued.control_values.base_window_count === expectedValidWindowCount, "base_window_count inválido");
    assert(issued.control_values.extra_windows_for_fp === DEFAULT_EXTRA_CONFIRMATION_WINDOWS, "extra_windows_for_fp deveria assumir o default 10");
    assert(issued.control_values.confirmation_window_count === DEFAULT_EXTRA_CONFIRMATION_WINDOWS, "confirmation_window_count inválido");
    assert(
      issued.control_values.window_count === expectedValidWindowCount + DEFAULT_EXTRA_CONFIRMATION_WINDOWS,
      "window_count total inválido"
    );
    assert(
      issued.control_values.last_valid_window_index === PRIMARY_LAST_VALID_WINDOW_INDEX,
      "last_valid_window_index inválido"
    );
    assert(
      issued.control_values.last_confirmation_window_index ===
        expectedValidWindowCount + DEFAULT_EXTRA_CONFIRMATION_WINDOWS - 1,
      "last_confirmation_window_index inválido"
    );

    const credentialId = `cred-v2-default-10-${Date.now()}`;
    await storeCredential(
      credentialId,
      issued.credential_json,
      requestMetadataId,
      JSON.stringify(credDefRevLedger),
      null
    );

    const bundleId = `bundle-v2-default-10-${Date.now()}`;
    const storedBundleJson = await storeReceivedRevocableCredential(
      bundleId,
      JSON.stringify(issued.holder_bundle),
      credentialId
    );
    const storedBundle = parseJsonSafe(storedBundleJson, "stored_bundle");
    assert(storedBundle.ok === true, "bundle deveria ser armazenado com ok=true");
    assert(
      storedBundle.holder_bundle.control.confirmation_window_count === DEFAULT_EXTRA_CONFIRMATION_WINDOWS,
      "bundle salvo com confirmation_window_count inválido"
    );

    console.log("5) Holder montando sequência válida: última janela válida + 10 extras...");
    const proofSequenceJson = await buildPresentationRevocationProofV2(
      bundleId,
      PRIMARY_LAST_VALID_WINDOW_INDEX,
      DEFAULT_EXTRA_CONFIRMATION_WINDOWS,
      credentialId
    );
    const proofSequenceResponse = parseJsonSafe(proofSequenceJson, "proof_sequence");
    assert(proofSequenceResponse.ok === true, "proof_sequence deveria retornar ok=true");
    assert(
      proofSequenceResponse.proof_sequence.primary_proof.window_index === PRIMARY_LAST_VALID_WINDOW_INDEX,
      "a prova principal deveria ficar na última janela válida"
    );
    assert(
      proofSequenceResponse.proof_sequence.confirmation_proofs.length === DEFAULT_EXTRA_CONFIRMATION_WINDOWS,
      "a sequência deveria conter exatamente 10 janelas extras"
    );

    const expectedConfirmationIndices = Array.from(
      { length: DEFAULT_EXTRA_CONFIRMATION_WINDOWS },
      (_, idx) => FIRST_CONFIRMATION_ONLY_WINDOW_INDEX + idx
    );
    assert(
      JSON.stringify(
        proofSequenceResponse.proof_sequence.confirmation_proofs.map((proof) => proof.window_index)
      ) === JSON.stringify(expectedConfirmationIndices),
      "as janelas extras deveriam ficar imediatamente após a última janela válida"
    );

    const builtConfirmationIndices = proofSequenceResponse.proof_sequence.confirmation_proofs.map(
      (proof) => proof.window_index
    );
    const builtConfirmationWindowCount = builtConfirmationIndices.length;

    console.log("6) A sequência válida continua verificável, mas a validade termina na última janela do emissor...");
    const policy = {
      max_consecutive_hits_for_revoke: 11,
      max_windows_to_request: 10,
      allow_post_expiry_confirmation_windows: true,
      holder_must_disprove_with_additional_windows: true,
    };
    const verifyValidJson = await verifyPresentationRevocationProofV2(
      JSON.stringify(proofSequenceResponse.proof_sequence),
      null,
      JSON.stringify(policy)
    );
    const verifyValid = parseJsonSafe(verifyValidJson, "verify_valid_sequence");
    assert(verifyValid.ok === true, "verify_valid_sequence deveria retornar ok=true");
    assert(verifyValid.status.decision === "valid_not_revoked", "a sequência válida deveria ser aceita");
    assert(verifyValid.status.primary_window_index === PRIMARY_LAST_VALID_WINDOW_INDEX, "primary_window_index inválido na decisão");

    console.log("7) Tentando usar a 1ª janela extra como janela principal: o holder deve ser bloqueado...");
    const holderBuildError = await expectAsyncThrows(
      () =>
        buildPresentationRevocationProofV2(
          bundleId,
          FIRST_CONFIRMATION_ONLY_WINDOW_INDEX,
          0,
          credentialId
        ),
      "janela exclusiva de confirmação"
    );

    console.log("8) O mesmo bloqueio deve acontecer na API de pacote de apresentação...");
    const presReq = {
      nonce: String(Date.now() * 1000 + 88888),
      name: "ProofReqRevocationV2Default10NoValidityExtension",
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
    const createPackageError = await expectAsyncThrows(
      () =>
        createPresentationPackageWithRevocationV2(
          JSON.stringify(presReq),
          JSON.stringify(reqCreds),
          JSON.stringify({ [schemaIdRev]: schemaRevLedger }),
          JSON.stringify({ [credDefIdRev]: credDefRevLedger }),
          JSON.stringify([
            {
              credential_id_local: credentialId,
              primary_window_index: FIRST_CONFIRMATION_ONLY_WINDOW_INDEX,
              additional_window_count: 0,
            },
          ])
        ),
      "janela exclusiva de confirmação"
    );

    console.log("9) Mesmo se alguém adulterar a sequência manualmente, o verifier deve rejeitar...");
    const tamperedSequence = {
      ...proofSequenceResponse.proof_sequence,
      primary_proof: proofSequenceResponse.proof_sequence.confirmation_proofs[0],
      confirmation_proofs: proofSequenceResponse.proof_sequence.confirmation_proofs.slice(1),
    };
    const verifierTamperError = await expectAsyncThrows(
      () =>
        verifyPresentationRevocationProofV2(
          JSON.stringify(tamperedSequence),
          null,
          JSON.stringify(policy)
        ),
      "excede last_valid_window_index"
    );

    console.log("✅ OK: TESTE REVOGAÇÃO 58 passou.");
    console.log("📌 Resumo final:", {
      valid_window_count: VALID_WINDOW_COUNT,
      default_extra_confirmation_windows: DEFAULT_EXTRA_CONFIRMATION_WINDOWS,
      base_window_count: issued.control_values.base_window_count,
      confirmation_window_count: issued.control_values.confirmation_window_count,
      total_window_count: issued.control_values.window_count,
      last_valid_window_index: issued.control_values.last_valid_window_index,
      first_confirmation_only_window_index: FIRST_CONFIRMATION_ONLY_WINDOW_INDEX,
      last_confirmation_window_index: issued.control_values.last_confirmation_window_index,
      built_confirmation_window_count: builtConfirmationWindowCount,
      built_confirmation_window_indices: builtConfirmationIndices,
      holder_block_message: holderBuildError,
      package_block_message: createPackageError,
      verifier_tamper_block_message: verifierTamperError,
    });
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
    try { await verifier.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 58:", e && e.stack ? e.stack : e);
  process.exit(1);
});
