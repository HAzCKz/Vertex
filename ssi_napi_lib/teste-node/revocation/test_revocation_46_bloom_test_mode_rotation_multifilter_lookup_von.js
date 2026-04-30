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
node teste-node/revocation/test_revocation_46_bloom_test_mode_rotation_multifilter_lookup_von.js

Para subir o bfilter em modo de testes:
cd /home/yugi/programacao/bfilter
BFILTER_ENABLE_TEST_API=1 \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
cargo run
*/

/*
Teste E2E de rotação automática do Bloom Filter em modo de testes,
com verificação cruzada entre filtro fechado e filtro novo.

Fluxo:
- reseta o bfilter real via /test/reset com filtro pequeno;
- cria e registra os atores SSI: issuer, holder e verifier;
- ancora o manifesto do serviço Bloom no ledger;
- emite 2 credenciais revogáveis para o holder, cada uma com janelas extras de confirmação;
- holder entrega ao verifier somente a janela 10 das 2 credenciais;
- verifier valida a apresentação mista antes de qualquer revogação;
- o emissor simula muitas outras revogações dummy na mesma janela,
  até o bfilter fechar o filtro antigo e abrir um novo automaticamente;
- verifier valida de novo e confirma que a consulta já percorre os 2 filtros;
- no novo filtro o emissor revoga uma das credenciais reais a partir da janela 10;
- verifier revalida a mesma apresentação e conclui:
  - assinatura criptográfica continua válida;
  - a apresentação deixa de ser aceita porque uma credencial foi revogada;
  - a busca foi feita em mais de um filtro.

Foco:
validar que a ssi_napi_lib funciona corretamente com a rotação automática
do bfilter e consulta múltiplos filtros sem o Electron precisar decidir qual usar.

Como o manifesto muda na rotação e na revogação real, o teste reancora
o manifesto atualizado antes de cada revalidação.
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

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function sha256Base64(input) {
  return crypto.createHash("sha256").update(input).digest("base64");
}

function thresholdAt95(capacityLimit) {
  return Math.ceil((Number(capacityLimit || 0) * 95) / 100);
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

async function resetBfilterForTests(baseUrl, adminToken) {
  let resp;
  try {
    resp = await fetch(`${baseUrl}/test/reset`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${adminToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        filter_id: `test-rotation-${Date.now()}`,
        m_bits: 8192,
      }),
    });
  } catch (e) {
    throw new Error(
      `Não foi possível acessar o bfilter em ${baseUrl}. ` +
      `Suba o serviço com BFILTER_ENABLE_TEST_API=1 e BFILTER_ADMIN_TOKEN configurado. ` +
      `Erro original: ${e?.message || e}`
    );
  }

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

async function writeDummyRevocations({ baseUrl, adminToken, issuerDid, targetWindowStart, count }) {
  const revocationKeys = Array.from({ length: count }, (_, idx) =>
    `dummy-rotation-${Date.now()}-${process.pid}-${idx}`
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
      credential_record_id: `dummy-batch-${Date.now()}`,
      revocation_keys: revocationKeys,
      window_starts: windowStarts,
      reason: "trigger-automatic-rotation-for-test",
      requested_by: "teste-node-revocation-46",
    }),
  });

  const bodyText = await resp.text();
  assert(resp.ok, `Falha POST /admin/revocations/v2: ${resp.status} ${bodyText}`);
  const body = JSON.parse(bodyText);
  assert(body.ok === true, "escrita dummy no Bloom deveria retornar ok=true");
  return body;
}

function buildDailyWindowStarts(startTime, startIndex, count) {
  return Array.from({ length: count }, (_, offset) => startTime + (startIndex + offset) * 86400);
}

async function writeRealRevocations({
  baseUrl,
  adminToken,
  issuerDid,
  credentialRecordId,
  revocationKeys,
  windowStarts,
  reason,
  requestedBy,
}) {
  const resp = await fetch(`${baseUrl}/admin/revocations/v2`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${adminToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      issuer_did: issuerDid,
      credential_record_id: credentialRecordId,
      revocation_keys: revocationKeys,
      window_starts: windowStarts,
      reason,
      requested_by: requestedBy,
    }),
  });

  const bodyText = await resp.text();
  assert(resp.ok, `Falha POST /admin/revocations/v2: ${resp.status} ${bodyText}`);
  const body = JSON.parse(bodyText);
  assert(body.ok === true, "escrita real no Bloom deveria retornar ok=true");
  return body;
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
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_rotation_lookup_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_rotation_lookup_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_rotation_lookup_verifier.db");

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
    console.log("🚀 TESTE REVOGAÇÃO 46: rotação automática + lookup em múltiplos filtros");

    console.log("1) Resetando o bfilter em modo de testes...");
    await resetBfilterForTests(BFILTER_BASE_URL, BFILTER_ADMIN_TOKEN);
    const manifestAfterReset = await fetchManifestEnvelope(BFILTER_BASE_URL);
    const initialFilter = manifestAfterReset.manifest.filters.find(
      (item) => item.filter_id === manifestAfterReset.manifest.active_filter_id
    );
    assert(initialFilter, "filtro ativo inicial ausente após reset");
    const rotateThreshold = thresholdAt95(initialFilter.capacity_limit);
    assert(rotateThreshold > 0, "rotateThreshold deveria ser > 0");

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
    const revocationBuildManifestAnchor = fn(issuer, "revocationBuildManifestAnchor", "revocation_build_manifest_anchor");
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
    const createPresentationPackageWithRevocation = fn(
      holder,
      "createPresentationPackageWithRevocation",
      "create_presentation_package_with_revocation"
    );
    const verifyMixedPresentationPackage = fn(
      verifier,
      "verifyMixedPresentationPackage",
      "verify_mixed_presentation_package"
    );
    const revokeIssuedCredentialFromWindow = fn(
      issuer,
      "revokeIssuedCredentialFromWindow",
      "revoke_issued_credential_from_window"
    );

    console.log("2) Criando e registrando os 3 atores SSI...");
    const [trusteeDid] = await importDidFromSeed(TRUSTEE_SEED);
    assert(trusteeDid === TRUSTEE_DID, `Trustee DID inesperado: ${trusteeDid}`);

    const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
    const [holderDid, holderVerkey] = await holder.createOwnDid();
    const [verifierDid, verifierVerkey] = await verifier.createOwnDid();

    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, issuerDid, issuerVerkey, "ENDORSER");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, holderDid, holderVerkey, "ENDORSER");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, verifierDid, verifierVerkey, "ENDORSER");

    console.log("3) Ancorando o manifesto do Bloom no ledger...");
    const manifestHash = manifestAfterReset.manifest_hash_body;
    const manifestJson = await revocationBuildManifestAnchor(
      issuerDid,
      `${BFILTER_BASE_URL}/manifest`,
      manifestHash,
      String(manifestAfterReset.manifest.version || 1)
    );
    const manifest = parseJsonSafe(manifestJson, "manifest_anchor");
    const writeManifestJson = await revocationWriteManifestAnchorOnLedger(
      genesisAbs,
      issuerDid,
      JSON.stringify(manifest)
    );
    const writeManifest = parseJsonSafe(writeManifestJson, "write_manifest");
    assert(writeManifest.ok === true, "write manifesto falhou");

    console.log("4) Registrando 2 Schemas/CredDefs revogáveis...");
    const schemaIdRev1 = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRotationRev1_${Date.now()}`,
      `1.${nowSec()}`,
      ["nome", "cpf", "idade", ...CONTROL_ATTRS]
    );
    const schemaIdRev2 = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRotationRev2_${Date.now()}`,
      `1.${nowSec() + 1}`,
      ["email", "telefone", ...CONTROL_ATTRS]
    );

    async function registerCredDef(schemaId, tag) {
      const localJson = await creddefSaveLocal(issuerDid, schemaId, tag, false, "prod");
      const local = parseJsonSafe(localJson, `creddef_local_${tag}`);
      const reg = await creddefRegisterFromLocal(genesisAbs, local.id_local, issuerDid);
      return reg.credDefId || reg.cred_def_id;
    }

    const credDefIdRev1 = await registerCredDef(schemaIdRev1, `TAG_ROT_REV1_${Date.now()}`);
    const credDefIdRev2 = await registerCredDef(schemaIdRev2, `TAG_ROT_REV2_${Date.now()}`);

    const schemaRev1Ledger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdRev1), "schema_rev1");
    const schemaRev2Ledger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdRev2), "schema_rev2");
    const credDefRev1Ledger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdRev1), "creddef_rev1");
    const credDefRev2Ledger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdRev2), "creddef_rev2");

    try {
      await createLinkSecret("default");
    } catch (_) {}

    console.log("5) Emitindo 2 credenciais revogáveis com 365 janelas diárias...");
    const startTime = nowSec();
    const validityEnd = startTime + 86400 * 364;

    async function issueAndStoreRevocable({
      issuerLocalCredentialId,
      credentialId,
      bundleId,
      credDefId,
      schemaId,
      credDefLedger,
      values,
    }) {
      const offerJson = await createCredentialOffer(credDefId, `offer-${issuerLocalCredentialId}`);
      const requestJson = await createCredentialRequest(
        "default",
        holderDid,
        JSON.stringify(credDefLedger),
        offerJson
      );
      const requestMetadataId = extractNonce(offerJson);

      const issuedJson = await issueRevocableCredential(
        genesisAbs,
        issuerLocalCredentialId,
        holderDid,
        credDefId,
        schemaId,
        offerJson,
        requestJson,
        JSON.stringify(values),
        startTime,
        validityEnd,
        "days",
        1,
        10,
        JSON.stringify(manifest),
        null,
        null
      );
      const issued = parseJsonSafe(issuedJson, `issued_${issuerLocalCredentialId}`);

      const storedCredentialId = await storeCredential(
        credentialId,
        issued.credential_json,
        requestMetadataId,
        JSON.stringify(credDefLedger),
        null
      );
      assert(storedCredentialId === credentialId, "credential revogável não armazenada corretamente");

      const storeBundleJson = await storeReceivedRevocableCredential(
        bundleId,
        JSON.stringify(issued.holder_bundle),
        credentialId
      );
      const storeBundle = parseJsonSafe(storeBundleJson, `store_bundle_${issuerLocalCredentialId}`);
      assert(storeBundle.ok === true, "bundle revogável não armazenado");
      return issued;
    }

    const credentialIdRev1 = `cred-rotation-rev1-${Date.now()}`;
    const credentialIdRev2 = `cred-rotation-rev2-${Date.now()}`;
    const bundleIdRev1 = `bundle-rotation-rev1-${Date.now()}`;
    const bundleIdRev2 = `bundle-rotation-rev2-${Date.now()}`;
    const issuerLocalIdRev1 = `issued-rotation-rev1-${Date.now()}`;
    const issuerLocalIdRev2 = `issued-rotation-rev2-${Date.now()}`;

    const issuedRev1 = await issueAndStoreRevocable({
      issuerLocalCredentialId: issuerLocalIdRev1,
      credentialId: credentialIdRev1,
      bundleId: bundleIdRev1,
      credDefId: credDefIdRev1,
      schemaId: schemaIdRev1,
      credDefLedger: credDefRev1Ledger,
      values: {
        nome: "Alice Rotation One",
        cpf: "12345678900",
        idade: "29",
      },
    });

    const issuedRev2 = await issueAndStoreRevocable({
      issuerLocalCredentialId: issuerLocalIdRev2,
      credentialId: credentialIdRev2,
      bundleId: bundleIdRev2,
      credDefId: credDefIdRev2,
      schemaId: schemaIdRev2,
      credDefLedger: credDefRev2Ledger,
      values: {
        email: "alice.rotation@example.org",
        telefone: "+5511988887777",
      },
    });

    console.log("6) Holder criando uma apresentação com 2 credenciais revogáveis e só a janela 10...");
    const windowIndex = 10;
    const presReq = {
      nonce: String(Date.now() * 1000 + 98765),
      name: "ProofReqBloomRotationMultiFilter",
      version: "0.1",
      requested_attributes: {
        attr_cpf: { name: "cpf", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_email: { name: "email", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_seed_rev1: { name: "seed", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_start_rev1: { name: "start_time", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_unit_rev1: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_window_rev1: { name: "time_window", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_root_rev1: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_seed_rev2: { name: "seed", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_start_rev2: { name: "start_time", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_unit_rev2: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_window_rev2: { name: "time_window", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_root_rev2: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefIdRev2 }] },
      },
      requested_predicates: {},
    };

    const reqCreds = {
      requested_attributes: {
        attr_cpf: { cred_id: credentialIdRev1, revealed: true },
        attr_email: { cred_id: credentialIdRev2, revealed: true },
        attr_seed_rev1: { cred_id: credentialIdRev1, revealed: true },
        attr_start_rev1: { cred_id: credentialIdRev1, revealed: true },
        attr_unit_rev1: { cred_id: credentialIdRev1, revealed: true },
        attr_window_rev1: { cred_id: credentialIdRev1, revealed: true },
        attr_root_rev1: { cred_id: credentialIdRev1, revealed: true },
        attr_seed_rev2: { cred_id: credentialIdRev2, revealed: true },
        attr_start_rev2: { cred_id: credentialIdRev2, revealed: true },
        attr_unit_rev2: { cred_id: credentialIdRev2, revealed: true },
        attr_window_rev2: { cred_id: credentialIdRev2, revealed: true },
        attr_root_rev2: { cred_id: credentialIdRev2, revealed: true },
      },
      requested_predicates: {},
    };

    const schemasMap = {
      [schemaIdRev1]: schemaRev1Ledger,
      [schemaIdRev2]: schemaRev2Ledger,
    };
    const credDefsMap = {
      [credDefIdRev1]: credDefRev1Ledger,
      [credDefIdRev2]: credDefRev2Ledger,
    };

    const presentationPackageJson = await createPresentationPackageWithRevocation(
      JSON.stringify(presReq),
      JSON.stringify(reqCreds),
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap),
      JSON.stringify([
        { credential_id_local: credentialIdRev1, window_index: windowIndex },
        { credential_id_local: credentialIdRev2, window_index: windowIndex },
      ])
    );
    const presentationPackage = parseJsonSafe(presentationPackageJson, "presentation_package");
    assert(presentationPackage.ok === true, "presentation package deveria retornar ok=true");
    assert(presentationPackage.revocation_proofs.length === 2, "o pacote deveria conter 2 provas");

    const targetWindowStart = Number(presentationPackage.revocation_proofs[0].proof.window_start);
    assert(Number.isFinite(targetWindowStart), "window_start alvo inválido");

    console.log("7) Verifier validando a apresentação antes de qualquer revogação...");
    const verifyBeforeJson = await verifyMixedPresentationPackage(
      JSON.stringify(presReq),
      presentationPackage.presentation_json,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap),
      JSON.stringify(
        presentationPackage.revocation_proofs.map((item) => ({
          credential_id_local: item.credential_id_local,
          proof: item.proof,
        }))
      ),
      null
    );
    const before = parseJsonSafe(verifyBeforeJson, "verify_before");
    assert(before.ok === true, "verify before deveria retornar ok=true");
    assert(before.cryptographic_valid === true, "a apresentação deveria ser criptograficamente válida");
    assert(before.proofs_verified === true, "as provas complementares deveriam verificar");
    assert(before.revoked === false, "antes de revogar nenhuma credencial deveria estar revogada");
    assert(before.accepted === true, "antes de revogar a apresentação deveria ser aceita");

    console.log("8) Forçando a rotação automática do bfilter com revogações dummy...");
    const dummyWrite = await writeDummyRevocations({
      baseUrl: BFILTER_BASE_URL,
      adminToken: BFILTER_ADMIN_TOKEN,
      issuerDid,
      targetWindowStart,
      count: rotateThreshold,
    });
    assert(dummyWrite.inserted === rotateThreshold, "a escrita dummy deveria inserir rotateThreshold chaves");

    const manifestAfterRotation = await fetchManifestEnvelope(BFILTER_BASE_URL);
    assert(
      Array.isArray(manifestAfterRotation.manifest.filters) &&
        manifestAfterRotation.manifest.filters.length >= 2,
      "após a rotação o manifesto deveria conter pelo menos 2 filtros"
    );
    const oldFilter = manifestAfterRotation.manifest.filters.find(
      (item) => item.filter_id === initialFilter.filter_id
    );
    const newFilter = manifestAfterRotation.manifest.filters.find(
      (item) => item.filter_id === manifestAfterRotation.manifest.active_filter_id
    );
    assert(oldFilter && oldFilter.status === "closed", "o filtro antigo deveria estar fechado");
    assert(newFilter && newFilter.filter_id !== oldFilter.filter_id, "deveria existir um novo filtro ativo");

    const manifestAfterRotationJson = await revocationBuildManifestAnchor(
      issuerDid,
      `${BFILTER_BASE_URL}/manifest`,
      manifestAfterRotation.manifest_hash_body,
      String(manifestAfterRotation.manifest.version || 1)
    );
    const writeManifestAfterRotation = parseJsonSafe(
      await revocationWriteManifestAnchorOnLedger(genesisAbs, issuerDid, manifestAfterRotationJson),
      "write_manifest_after_rotation"
    );
    assert(writeManifestAfterRotation.ok === true, "reanchor do manifesto após rotação falhou");
    const revocationProofsAfterRotationJson = JSON.stringify(
      presentationPackage.revocation_proofs.map((item) => ({
        credential_id_local: item.credential_id_local,
        proof: {
          ...item.proof,
          manifest: writeManifestAfterRotation.manifest,
        },
      }))
    );

    console.log("9) Verifier validando de novo após a rotação, mas ainda sem revogação real...");
    const verifyAfterRotationJson = await verifyMixedPresentationPackage(
      JSON.stringify(presReq),
      presentationPackage.presentation_json,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap),
      revocationProofsAfterRotationJson,
      null
    );
    const afterRotation = parseJsonSafe(verifyAfterRotationJson, "verify_after_rotation");
    assert(afterRotation.ok === true, "verify after rotation deveria retornar ok=true");
    assert(afterRotation.accepted === true, "sem revogação real a apresentação deveria continuar aceita");

    const detailsAfterRotationBeforeRevoke = afterRotation.per_credential_status
      .filter((item) => item.revocable === true)
      .map((item) => item.details || "");
    assert(
      detailsAfterRotationBeforeRevoke.every(
        (details) =>
          details.includes(oldFilter.filter_id) &&
          !details.includes(newFilter.filter_id) &&
          details.includes("Bloom filter")
      ),
      "antes da revogação real apenas o filtro antigo deveria ser candidato para essa janela"
    );

    console.log("10) Revogando uma das credenciais reais no novo filtro a partir da janela 10...");
    const realRevocationKeys = issuedRev1.issuer_record.revocation_keys_by_window.slice(windowIndex);
    const realWindowStarts = buildDailyWindowStarts(startTime, windowIndex, realRevocationKeys.length);
    const revoke = await writeRealRevocations({
      baseUrl: BFILTER_BASE_URL,
      adminToken: BFILTER_ADMIN_TOKEN,
      issuerDid,
      credentialRecordId: issuedRev1.issuer_record.issuer_local_credential_id,
      revocationKeys: realRevocationKeys,
      windowStarts: realWindowStarts,
      reason: "revogacao-real-apos-rotacao",
      requestedBy: "teste-node-revocation-46",
    });
    assert(Number(revoke.inserted || 0) > 0, "a revogação real deveria gravar pelo menos uma chave");

    const manifestAfterRevoke = await fetchManifestEnvelope(BFILTER_BASE_URL);
    const manifestAfterRevokeJson = await revocationBuildManifestAnchor(
      issuerDid,
      `${BFILTER_BASE_URL}/manifest`,
      manifestAfterRevoke.manifest_hash_body,
      String(manifestAfterRevoke.manifest.version || 1)
    );
    const writeManifestAfterRevoke = parseJsonSafe(
      await revocationWriteManifestAnchorOnLedger(genesisAbs, issuerDid, manifestAfterRevokeJson),
      "write_manifest_after_revoke"
    );
    assert(writeManifestAfterRevoke.ok === true, "reanchor do manifesto após revogação real falhou");
    const revocationProofsAfterRevokeJson = JSON.stringify(
      presentationPackage.revocation_proofs.map((item) => ({
        credential_id_local: item.credential_id_local,
        proof: {
          ...item.proof,
          manifest: writeManifestAfterRevoke.manifest,
        },
      }))
    );

    console.log("11) Verifier revalidando a mesma apresentação após a revogação real...");
    const verifyAfterRevokeJson = await verifyMixedPresentationPackage(
      JSON.stringify(presReq),
      presentationPackage.presentation_json,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap),
      revocationProofsAfterRevokeJson,
      null
    );
    const afterRevoke = parseJsonSafe(verifyAfterRevokeJson, "verify_after_revoke");
    assert(afterRevoke.ok === true, "verify after revoke deveria retornar ok=true");
    assert(afterRevoke.cryptographic_valid === true, "criptograficamente a apresentação deve continuar válida");
    assert(afterRevoke.proofs_verified === true, "as provas complementares devem continuar verificando");
    assert(afterRevoke.revoked === true, "o consolidado deveria indicar revogação");
    assert(afterRevoke.accepted === false, "a apresentação não deve mais ser aceita");

    const revokedStatuses = afterRevoke.per_credential_status.filter(
      (item) => item.revocable === true && item.revoked === true
    );
    assert(revokedStatuses.length === 1, "exatamente uma das duas credenciais deveria estar revogada");
    assert(
      revokedStatuses[0].credential_id_local === credentialIdRev1,
      "a credencial revogada deveria ser a primeira credencial emitida"
    );
    assert(
      revokedStatuses[0].details.includes(oldFilter.filter_id) &&
        revokedStatuses[0].details.includes(newFilter.filter_id),
      "o status da credencial revogada deveria mostrar lookup em múltiplos filtros após a revogação no filtro novo"
    );

    const nonRevokedStatuses = afterRevoke.per_credential_status.filter(
      (item) => item.revocable === true && item.revoked === false
    );
    assert(nonRevokedStatuses.length === 1, "a outra credencial revogável deveria continuar válida");
    assert(
      nonRevokedStatuses[0].credential_id_local === credentialIdRev2,
      "a credencial não revogada deveria ser a segunda emitida"
    );
    assert(
      nonRevokedStatuses[0].details.includes(oldFilter.filter_id) &&
        nonRevokedStatuses[0].details.includes(newFilter.filter_id),
      "mesmo a credencial não revogada deveria ser consultada em múltiplos filtros candidatos"
    );

    console.log("✅ OK: TESTE REVOGAÇÃO 46 passou.");
    console.log("📌 Resumo final:", {
      rotate_threshold: rotateThreshold,
      old_filter_id: oldFilter.filter_id,
      new_filter_id: newFilter.filter_id,
      target_window_index: windowIndex,
      target_window_start: targetWindowStart,
      cryptographic_valid: afterRevoke.cryptographic_valid,
      revoked: afterRevoke.revoked,
      accepted: afterRevoke.accepted,
    });
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
    try { await verifier.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 46:", e && e.stack ? e.stack : e);
  process.exit(1);
});
