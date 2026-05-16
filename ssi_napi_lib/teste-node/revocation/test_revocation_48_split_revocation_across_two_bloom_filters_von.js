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
node teste-node/revocation/test_revocation_48_split_revocation_across_two_bloom_filters_von.js

Para subir o bfilter em modo de testes:
cd /home/yugi/programacao/bfilter
BFILTER_ENABLE_TEST_API=1 \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
cargo run
*/

/*
Teste E2E de revogação fatiada da mesma credencial em dois Bloom Filters.

Fluxo:
- reseta o bfilter real via /test/reset com filtro pequeno, porém controlado;
- cria issuer, holder e verifier;
- ancora o manifesto do Bloom no ledger;
- emite 2 credenciais revogáveis com 365 janelas válidas diárias e 10 extras de confirmação;
- holder armazena credenciais e bundles e monta apresentações com as 2 credenciais;
- verifica que as 10 primeiras janelas ainda são válidas;
- grava no filtro inicial as chaves reais da credencial 1 para as janelas 11..300;
- completa o filtro com revogações dummy até forçar a rotação automática;
- grava no filtro novo as chaves reais da mesma credencial para as janelas 301..365;
- verifica a apresentação nas janelas 250 e 320, provando que a API consulta
  filtros diferentes e detecta a revogação da mesma credencial.

Observação importante:
o endpoint do emissor hoje revoga "da janela X até o fim". Para testar a divisão
real 11..300 em um filtro e 301..365 em outro, este teste usa as
revocation_keys_by_window da credencial emitida e grava explicitamente as duas
faixas via endpoint administrativo do Bloom, simulando a distribuição real dos
elementos entre filtros.

Depois das escritas reais e da rotação, o teste reancora o manifesto
atualizado antes de revalidar as janelas.
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

const WINDOW_COUNT = 365;
const REQUIRED_EXTRA_WINDOWS_FOR_FP = 10;
const TOTAL_WINDOW_COUNT = WINDOW_COUNT + REQUIRED_EXTRA_WINDOWS_FOR_FP;
const TEST_FILTER_M_BITS = 32768;

// Conversão da descrição humana para índices zero-based usados pela API.
const FIRST_TEN_WINDOW_INDICES = Array.from({ length: 10 }, (_, idx) => idx);
const REVOKE_OLD_FILTER_START_INDEX = 10; // janela humana 11
const REVOKE_OLD_FILTER_END_INDEX = 299; // janela humana 300
const REVOKE_NEW_FILTER_START_INDEX = 300; // janela humana 301
const REVOKE_NEW_FILTER_END_INDEX = 364; // janela humana 365
const CHECK_OLD_FILTER_WINDOW_INDEX = 249; // janela humana 250
const CHECK_NEW_FILTER_WINDOW_INDEX = 319; // janela humana 320
const OLD_FILTER_REAL_KEY_COUNT = REVOKE_NEW_FILTER_START_INDEX - REVOKE_OLD_FILTER_START_INDEX;
const NEW_FILTER_REAL_KEY_COUNT = REVOKE_NEW_FILTER_END_INDEX - REVOKE_NEW_FILTER_START_INDEX + 1;
const MAX_ROTATION_ATTEMPTS = 8;

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function sha256Base64(input) {
  return crypto.createHash("sha256").update(input).digest("base64");
}

function thresholdAt95(capacityLimit) {
  return Math.ceil((Number(capacityLimit || 0) * 95) / 100);
}

function windowIndexToStart(startTime, windowIndex) {
  return Number(startTime) + Number(windowIndex) * 86400;
}

function buildWindowStartsRange(startTime, startIndex, endIndexInclusive) {
  const items = [];
  for (let idx = startIndex; idx <= endIndexInclusive; idx++) {
    items.push(windowIndexToStart(startTime, idx));
  }
  return items;
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

function getActiveFilter(manifestEnvelope) {
  const manifest = manifestEnvelope.manifest || {};
  const filters = Array.isArray(manifest.filters) ? manifest.filters : [];
  return filters.find((item) => item.filter_id === manifest.active_filter_id) || null;
}

async function resetBfilterForTests(baseUrl, adminToken, mBits) {
  let resp;
  try {
    resp = await fetch(`${baseUrl}/test/reset`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${adminToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        filter_id: `test-split-multifilter-${Date.now()}`,
        m_bits: mBits,
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

async function writeRevocations({
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
  assert(body.ok === true, "escrita no Bloom deveria retornar ok=true");
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
    `dummy-split-multifilter-${Date.now()}-${process.pid}-${idx}`
  );
  const windowStarts = Array.from({ length: count }, () => targetWindowStart);

  return writeRevocations({
    baseUrl,
    adminToken,
    issuerDid,
    credentialRecordId: `dummy-batch-${Date.now()}`,
    revocationKeys,
    windowStarts,
    reason: "trigger-automatic-rotation-for-split-test",
    requestedBy: "teste-node-revocation-48-dummy",
  });
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
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_split_multifilter_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_split_multifilter_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_split_multifilter_verifier.db");

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
    console.log("🚀 TESTE REVOGAÇÃO 48: revogação da mesma credencial distribuída em 2 Bloom Filters");

    console.log("1) Resetando o bfilter em modo de testes...");
    await resetBfilterForTests(BFILTER_BASE_URL, BFILTER_ADMIN_TOKEN, TEST_FILTER_M_BITS);
    const manifestAfterReset = await fetchManifestEnvelope(BFILTER_BASE_URL);
    const initialFilter = getActiveFilter(manifestAfterReset);
    assert(initialFilter, "filtro ativo inicial ausente após reset");
    const rotateThreshold = thresholdAt95(initialFilter.capacity_limit);
    assert(rotateThreshold > OLD_FILTER_REAL_KEY_COUNT, `rotateThreshold deveria ser > ${OLD_FILTER_REAL_KEY_COUNT}, recebido ${rotateThreshold}`);

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
    const getIssuedRevocableCredentialSummary = fn(
      issuer,
      "getIssuedRevocableCredentialSummary",
      "get_issued_revocable_credential_summary"
    );
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

    console.log("2) Criando e registrando issuer, holder e verifier...");
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
      `SchemaSplitBloomRev1_${Date.now()}`,
      `1.${nowSec()}`,
      ["nome", "cpf", "idade", ...CONTROL_ATTRS]
    );
    const schemaIdRev2 = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaSplitBloomRev2_${Date.now()}`,
      `1.${nowSec() + 1}`,
      ["email", "telefone", ...CONTROL_ATTRS]
    );

    async function registerCredDef(schemaId, tag) {
      const localJson = await creddefSaveLocal(issuerDid, schemaId, tag, false, "prod");
      const local = parseJsonSafe(localJson, `creddef_local_${tag}`);
      const reg = await creddefRegisterFromLocal(genesisAbs, local.id_local, issuerDid);
      return reg.credDefId || reg.cred_def_id;
    }

    const credDefIdRev1 = await registerCredDef(schemaIdRev1, `TAG_SPLIT_REV1_${Date.now()}`);
    const credDefIdRev2 = await registerCredDef(schemaIdRev2, `TAG_SPLIT_REV2_${Date.now()}`);

    const schemaRev1Ledger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdRev1), "schema_rev1");
    const schemaRev2Ledger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdRev2), "schema_rev2");
    const credDefRev1Ledger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdRev1), "creddef_rev1");
    const credDefRev2Ledger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdRev2), "creddef_rev2");

    try {
      await createLinkSecret("default");
    } catch (_) {}

    console.log("5) Emitindo 2 credenciais revogáveis com 365 janelas diárias...");
    const startTime = nowSec();
    const validityEnd = startTime + 86400 * (WINDOW_COUNT - 1);

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
        REQUIRED_EXTRA_WINDOWS_FOR_FP,
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

      const summaryJson = await getIssuedRevocableCredentialSummary(issuerLocalCredentialId);
      const summary = parseJsonSafe(summaryJson, `summary_${issuerLocalCredentialId}`);
      assert(summary.ok === true, "summary deveria retornar ok=true");
      assert(summary.revocation_summary.window_count === TOTAL_WINDOW_COUNT, `window_count deveria ser ${TOTAL_WINDOW_COUNT}`);

      return issued;
    }

    const credentialIdRev1 = `cred-split-rev1-${Date.now()}`;
    const credentialIdRev2 = `cred-split-rev2-${Date.now()}`;
    const bundleIdRev1 = `bundle-split-rev1-${Date.now()}`;
    const bundleIdRev2 = `bundle-split-rev2-${Date.now()}`;
    const issuerLocalIdRev1 = `issued-split-rev1-${Date.now()}`;
    const issuerLocalIdRev2 = `issued-split-rev2-${Date.now()}`;

    const issuedRev1 = await issueAndStoreRevocable({
      issuerLocalCredentialId: issuerLocalIdRev1,
      credentialId: credentialIdRev1,
      bundleId: bundleIdRev1,
      credDefId: credDefIdRev1,
      schemaId: schemaIdRev1,
      credDefLedger: credDefRev1Ledger,
      values: {
        nome: "Alice Split Bloom",
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
        email: "alice.split@example.org",
        telefone: "+5511988887777",
      },
    });

    assert(
      issuedRev1.issuer_record.revocation_keys_by_window.length === TOTAL_WINDOW_COUNT,
      `credencial 1 deveria possuir ${TOTAL_WINDOW_COUNT} revocation_keys`
    );
    assert(
      issuedRev2.issuer_record.revocation_keys_by_window.length === TOTAL_WINDOW_COUNT,
      `credencial 2 deveria possuir ${TOTAL_WINDOW_COUNT} revocation_keys`
    );

    console.log("6) Holder montando apresentações com as 2 credenciais...");
    const presReq = {
      nonce: String(Date.now() * 1000 + 48123),
      name: "ProofReqSplitRevocationAcrossTwoBloomFilters",
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

    async function buildAndVerifyForWindow(windowIndex, manifestOverride = null) {
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
      const presentationPackage = parseJsonSafe(
        presentationPackageJson,
        `presentation_package_window_${windowIndex}`
      );
      assert(presentationPackage.ok === true, "presentation package deveria retornar ok=true");
      assert(presentationPackage.revocation_proofs.length === 2, "o pacote deveria conter 2 provas");
      const revocationProofsForVerification = presentationPackage.revocation_proofs.map((item) => ({
        credential_id_local: item.credential_id_local,
        proof: manifestOverride
          ? {
              ...item.proof,
              manifest: manifestOverride,
            }
          : item.proof,
      }));

      const verifyJson = await verifyMixedPresentationPackage(
        JSON.stringify(presReq),
        presentationPackage.presentation_json,
        JSON.stringify(schemasMap),
        JSON.stringify(credDefsMap),
        JSON.stringify(revocationProofsForVerification),
        null
      );

      return {
        presentationPackage,
        verification: parseJsonSafe(verifyJson, `verify_window_${windowIndex}`),
      };
    }

    function assertStatusResolvesOnlyToFilter(status, expectedFilterId, forbiddenFilterId, label) {
      assert(status, `${label} deveria existir`);
      assert(
        typeof status.details === "string" && status.details.includes(expectedFilterId),
        `${label} deveria resolver no filtro ${expectedFilterId}`
      );
      assert(
        !status.details.includes(forbiddenFilterId),
        `${label} não deveria resolver no filtro ${forbiddenFilterId}`
      );
    }

    function assertSingleCredentialRevoked({
      verification,
      expectedRevokedCredentialId,
      expectedValidCredentialId,
      expectedFilterId,
      forbiddenFilterId,
      humanWindowLabel,
    }) {
      const revokedStatuses = verification.per_credential_status.filter(
        (item) => item.revocable === true && item.revoked === true
      );
      const validStatuses = verification.per_credential_status.filter(
        (item) => item.revocable === true && item.revoked === false
      );

      assert(revokedStatuses.length === 1, `na janela ${humanWindowLabel} deveria existir exatamente 1 credencial revogada`);
      assert(validStatuses.length === 1, `na janela ${humanWindowLabel} deveria existir exatamente 1 credencial válida`);
      assert(
        revokedStatuses[0].credential_id_local === expectedRevokedCredentialId,
        `na janela ${humanWindowLabel} a credencial revogada deveria ser ${expectedRevokedCredentialId}`
      );
      assert(
        validStatuses[0].credential_id_local === expectedValidCredentialId,
        `na janela ${humanWindowLabel} a credencial válida deveria ser ${expectedValidCredentialId}`
      );

      assertStatusResolvesOnlyToFilter(
        revokedStatuses[0],
        expectedFilterId,
        forbiddenFilterId,
        `credencial revogada na janela ${humanWindowLabel}`
      );
      assertStatusResolvesOnlyToFilter(
        validStatuses[0],
        expectedFilterId,
        forbiddenFilterId,
        `credencial válida na janela ${humanWindowLabel}`
      );

      return {
        revokedStatus: revokedStatuses[0],
        validStatus: validStatuses[0],
      };
    }

    function extractResolvedFilterId(details) {
      const match = String(details || "").match(/Bloom filter\s+([^\s]+)/);
      return match ? match[1] : null;
    }

    console.log("7) Validando que as 10 primeiras janelas continuam válidas...");
    for (const windowIndex of FIRST_TEN_WINDOW_INDICES) {
      const { verification } = await buildAndVerifyForWindow(windowIndex);
      assert(verification.ok === true, `verify deveria retornar ok=true na janela ${windowIndex}`);
      assert(verification.cryptographic_valid === true, `janela ${windowIndex} deveria ser criptograficamente válida`);
      assert(verification.proofs_verified === true, `janela ${windowIndex} deveria verificar`);
      assert(verification.revoked === false, `janela ${windowIndex} não deveria estar revogada`);
      assert(verification.accepted === true, `janela ${windowIndex} deveria ser aceita`);
    }

    console.log("8) Gravando a faixa real da credencial 1 nas janelas humanas 11..300...");
    const oldFilterRevocationKeys = issuedRev1.issuer_record.revocation_keys_by_window.slice(
      REVOKE_OLD_FILTER_START_INDEX,
      REVOKE_NEW_FILTER_START_INDEX
    );
    const oldFilterWindowStarts = buildWindowStartsRange(
      startTime,
      REVOKE_OLD_FILTER_START_INDEX,
      REVOKE_OLD_FILTER_END_INDEX
    );
    assert(oldFilterRevocationKeys.length === OLD_FILTER_REAL_KEY_COUNT, `a faixa antiga deveria possuir ${OLD_FILTER_REAL_KEY_COUNT} chaves`);
    assert(oldFilterWindowStarts.length === OLD_FILTER_REAL_KEY_COUNT, `a faixa antiga deveria possuir ${OLD_FILTER_REAL_KEY_COUNT} window_starts`);

    const firstRealWrite = await writeRevocations({
      baseUrl: BFILTER_BASE_URL,
      adminToken: BFILTER_ADMIN_TOKEN,
      issuerDid,
      credentialRecordId: issuedRev1.issuer_record.issuer_local_credential_id,
      revocationKeys: oldFilterRevocationKeys,
      windowStarts: oldFilterWindowStarts,
      reason: "split-real-revocation-old-filter",
      requestedBy: "teste-node-revocation-48-old-filter",
    });
    assert(firstRealWrite.inserted === OLD_FILTER_REAL_KEY_COUNT, `a escrita real inicial deveria inserir ${OLD_FILTER_REAL_KEY_COUNT} chaves`);

    const manifestAfterFirstRealWrite = await fetchManifestEnvelope(BFILTER_BASE_URL);
    const activeAfterFirstRealWrite = getActiveFilter(manifestAfterFirstRealWrite);
    assert(activeAfterFirstRealWrite, "filtro ativo deveria existir após a escrita real inicial");
    assert(
      activeAfterFirstRealWrite.filter_id === initialFilter.filter_id,
      "a primeira faixa real ainda deveria estar no filtro inicial"
    );

    console.log("9) Preenchendo o filtro com revogações dummy até forçar a rotação...");
    const dummyWindowStart = windowIndexToStart(startTime, CHECK_OLD_FILTER_WINDOW_INDEX);
    let dummyInsertedTotal = 0;
    let manifestAfterRotation = manifestAfterFirstRealWrite;
    let activeAfterRotation = activeAfterFirstRealWrite;
    let rotationAttempt = 0;
    while (activeAfterRotation && activeAfterRotation.filter_id === initialFilter.filter_id) {
      rotationAttempt += 1;
      assert(rotationAttempt <= MAX_ROTATION_ATTEMPTS, "rotação do Bloom não aconteceu dentro do limite esperado");
      const remainingUntilThreshold = Math.max(
        rotateThreshold - Number(activeAfterRotation.inserted_count || 0),
        1
      );
      const dummyWrite = await writeDummyRevocations({
        baseUrl: BFILTER_BASE_URL,
        adminToken: BFILTER_ADMIN_TOKEN,
        issuerDid,
        targetWindowStart: dummyWindowStart,
        count: remainingUntilThreshold,
      });
      dummyInsertedTotal += Number(dummyWrite.inserted || 0);
      manifestAfterRotation = await fetchManifestEnvelope(BFILTER_BASE_URL);
      activeAfterRotation = getActiveFilter(manifestAfterRotation);
    }

    const oldFilter = (manifestAfterRotation.manifest.filters || []).find(
      (item) => item.filter_id === initialFilter.filter_id
    );
    const newFilter = getActiveFilter(manifestAfterRotation);
    assert(dummyInsertedTotal > 0, "deveria ter sido necessário inserir revogações dummy");
    assert(oldFilter && oldFilter.status === "closed", "o filtro antigo deveria estar fechado");
    assert(newFilter && newFilter.filter_id !== oldFilter.filter_id, "deveria existir um novo filtro ativo");

    console.log("10) Gravando a faixa real restante da credencial 1 no filtro novo (janelas humanas 301..365)...");
    const newFilterRevocationKeys = issuedRev1.issuer_record.revocation_keys_by_window.slice(
      REVOKE_NEW_FILTER_START_INDEX,
      REVOKE_NEW_FILTER_END_INDEX + 1
    );
    const newFilterWindowStarts = buildWindowStartsRange(
      startTime,
      REVOKE_NEW_FILTER_START_INDEX,
      REVOKE_NEW_FILTER_END_INDEX
    );
    assert(newFilterRevocationKeys.length === NEW_FILTER_REAL_KEY_COUNT, `a faixa nova deveria possuir ${NEW_FILTER_REAL_KEY_COUNT} chaves`);
    assert(newFilterWindowStarts.length === NEW_FILTER_REAL_KEY_COUNT, `a faixa nova deveria possuir ${NEW_FILTER_REAL_KEY_COUNT} window_starts`);

    const secondRealWrite = await writeRevocations({
      baseUrl: BFILTER_BASE_URL,
      adminToken: BFILTER_ADMIN_TOKEN,
      issuerDid,
      credentialRecordId: issuedRev1.issuer_record.issuer_local_credential_id,
      revocationKeys: newFilterRevocationKeys,
      windowStarts: newFilterWindowStarts,
      reason: "split-real-revocation-new-filter",
      requestedBy: "teste-node-revocation-48-new-filter",
    });
    assert(secondRealWrite.inserted === NEW_FILTER_REAL_KEY_COUNT, `a escrita real final deveria inserir ${NEW_FILTER_REAL_KEY_COUNT} chaves`);
    assert(
      secondRealWrite.filter_id === newFilter.filter_id,
      "a faixa 301..365 deveria ser gravada no filtro novo"
    );

    const manifestAfterSecondRealWrite = await fetchManifestEnvelope(BFILTER_BASE_URL);
    const manifestAfterSecondWriteJson = await revocationBuildManifestAnchor(
      issuerDid,
      `${BFILTER_BASE_URL}/manifest`,
      manifestAfterSecondRealWrite.manifest_hash_body,
      String(manifestAfterSecondRealWrite.manifest.version || 1)
    );
    const writeManifestAfterSecond = parseJsonSafe(
      await revocationWriteManifestAnchorOnLedger(genesisAbs, issuerDid, manifestAfterSecondWriteJson),
      "write_manifest_after_second_real_write"
    );
    assert(writeManifestAfterSecond.ok === true, "reanchor do manifesto após escrita real final falhou");

    console.log("11) Verificando a apresentação na janela humana 250 (filtro antigo)...");
    const resultOldFilterWindow = await buildAndVerifyForWindow(
      CHECK_OLD_FILTER_WINDOW_INDEX,
      writeManifestAfterSecond.manifest
    );
    const verificationOldFilterWindow = resultOldFilterWindow.verification;
    assert(verificationOldFilterWindow.ok === true, "verify da janela 250 deveria retornar ok=true");
    assert(verificationOldFilterWindow.cryptographic_valid === true, "janela 250 deveria continuar criptograficamente válida");
    assert(verificationOldFilterWindow.proofs_verified === true, "janela 250 deveria manter provas válidas");
    assert(verificationOldFilterWindow.revoked === true, "janela 250 deveria indicar revogação");
    assert(verificationOldFilterWindow.accepted === false, "janela 250 não deveria ser aceita");

    const revokedAt250 = verificationOldFilterWindow.per_credential_status.find(
      (item) => item.credential_id_local === credentialIdRev1
    );
    const validAt250 = verificationOldFilterWindow.per_credential_status.find(
      (item) => item.credential_id_local === credentialIdRev2
    );
    assert(revokedAt250 && revokedAt250.revoked === true, "credencial 1 deveria estar revogada na janela 250");
    assert(validAt250 && validAt250.revoked === false, "credencial 2 deveria continuar válida na janela 250");
    assert(
      revokedAt250.details.includes(oldFilter.filter_id),
      "a consulta da janela 250 deveria apontar para o filtro antigo"
    );
    assert(
      !revokedAt250.details.includes(newFilter.filter_id),
      "a consulta da janela 250 não deveria apontar para o filtro novo"
    );
    const explicitCheck250 = assertSingleCredentialRevoked({
      verification: verificationOldFilterWindow,
      expectedRevokedCredentialId: credentialIdRev1,
      expectedValidCredentialId: credentialIdRev2,
      expectedFilterId: oldFilter.filter_id,
      forbiddenFilterId: newFilter.filter_id,
      humanWindowLabel: 250,
    });
    assert(
      explicitCheck250.validStatus.revoked === false,
      "a segunda credencial deveria permanecer válida na janela 250"
    );

    console.log("12) Verificando a apresentação na janela humana 320 (filtro novo)...");
    const resultNewFilterWindow = await buildAndVerifyForWindow(
      CHECK_NEW_FILTER_WINDOW_INDEX,
      writeManifestAfterSecond.manifest
    );
    const verificationNewFilterWindow = resultNewFilterWindow.verification;
    assert(verificationNewFilterWindow.ok === true, "verify da janela 320 deveria retornar ok=true");
    assert(verificationNewFilterWindow.cryptographic_valid === true, "janela 320 deveria continuar criptograficamente válida");
    assert(verificationNewFilterWindow.proofs_verified === true, "janela 320 deveria manter provas válidas");
    assert(verificationNewFilterWindow.revoked === true, "janela 320 deveria indicar revogação");
    assert(verificationNewFilterWindow.accepted === false, "janela 320 não deveria ser aceita");

    const revokedAt320 = verificationNewFilterWindow.per_credential_status.find(
      (item) => item.credential_id_local === credentialIdRev1
    );
    const validAt320 = verificationNewFilterWindow.per_credential_status.find(
      (item) => item.credential_id_local === credentialIdRev2
    );
    assert(revokedAt320 && revokedAt320.revoked === true, "credencial 1 deveria estar revogada na janela 320");
    assert(validAt320 && validAt320.revoked === false, "credencial 2 deveria continuar válida na janela 320");
    assert(
      revokedAt320.details.includes(newFilter.filter_id),
      "a consulta da janela 320 deveria apontar para o filtro novo"
    );
    assert(
      !revokedAt320.details.includes(oldFilter.filter_id),
      "a consulta da janela 320 não deveria apontar para o filtro antigo"
    );
    const explicitCheck320 = assertSingleCredentialRevoked({
      verification: verificationNewFilterWindow,
      expectedRevokedCredentialId: credentialIdRev1,
      expectedValidCredentialId: credentialIdRev2,
      expectedFilterId: newFilter.filter_id,
      forbiddenFilterId: oldFilter.filter_id,
      humanWindowLabel: 320,
    });
    assert(
      explicitCheck320.validStatus.revoked === false,
      "a segunda credencial deveria permanecer válida na janela 320"
    );

    console.log("✅ OK: TESTE REVOGAÇÃO 48 passou.");
    console.log("📌 Resumo final:", {
      old_filter_id: oldFilter.filter_id,
      new_filter_id: newFilter.filter_id,
      real_keys_old_filter: oldFilterRevocationKeys.length,
      real_keys_new_filter: newFilterRevocationKeys.length,
      dummy_inserted_total: dummyInsertedTotal,
      check_window_old_filter_human: 250,
      check_window_new_filter_human: 320,
      revoked_250: revokedAt250.revoked,
      revoked_320: revokedAt320.revoked,
      valid_cred_250: explicitCheck250.validStatus.credential_id_local,
      valid_cred_320: explicitCheck320.validStatus.credential_id_local,
      valid_cred_filter_250: extractResolvedFilterId(explicitCheck250.validStatus.details),
      valid_cred_filter_320: extractResolvedFilterId(explicitCheck320.validStatus.details),
      accepted_250: verificationOldFilterWindow.accepted,
      accepted_320: verificationNewFilterWindow.accepted,
    });
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
    try { await verifier.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 48:", e && e.stack ? e.stack : e);
  process.exit(1);
});
