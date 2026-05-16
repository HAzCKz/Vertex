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
node teste-node/revocation/test_revocation_38_all_time_units_revocation_von.js

Para subir o bfilter:
cd /home/yugi/programacao/bfilter
BFILTER_ADMIN_TOKEN="dev-admin-token" cargo run
*/

/*
Teste E2E de apresentação única com credenciais revogáveis
em todas as unidades de tempo suportadas.

O fluxo:
- cria/abre wallets de issuer, holder e verifier;
- conecta ao ledger e registra os DIDs;
- lê e ancora o manifesto do serviço Bloom no ledger;
- cria 1 Schema/CredDef revogável para cada unit_of_time;
- emite e armazena uma credencial revogável por unidade;
- holder monta uma apresentação única com todas as credenciais;
- verifier valida a apresentação e as provas complementares;
- emissor revoga apenas a credencial da unidade "months";
- verifier revalida tudo após a revogação.

Depois valida:
- existe uma credencial para cada unidade de tempo suportada;
- antes da revogação, a apresentação é aceita;
- após a revogação, a apresentação continua válida criptograficamente;
- após a revogação, o manifesto atualizado do Bloom é reancorado no ledger;
- todas as provas complementares continuam verificando;
- apenas a credencial da unidade "months" aparece como revogada;
- a apresentação final deixa de ser aceita porque uma credencial foi revogada.

Foco do teste:
validar o fluxo E2E de revogação para todas as unidades
de unit_of_time em uma única apresentação agregada.
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

const UNITS = [
  "seconds",
  "minutes",
  "hours",
  "days",
  "weeks",
  "months",
  "years",
  "decades",
];

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function sha256Base64(input) {
  return crypto.createHash("sha256").update(input).digest("base64");
}

function lastDayOfMonthUtc(year, month1) {
  return new Date(Date.UTC(year, month1, 0)).getUTCDate();
}

function addMonthsUtc(ts, monthsToAdd) {
  const d = new Date(ts * 1000);
  const year = d.getUTCFullYear();
  const month0 = d.getUTCMonth();
  const day = d.getUTCDate();
  const hour = d.getUTCHours();
  const minute = d.getUTCMinutes();
  const second = d.getUTCSeconds();

  const totalMonth0 = year * 12 + month0 + monthsToAdd;
  const nextYear = Math.floor(totalMonth0 / 12);
  const nextMonth0 = ((totalMonth0 % 12) + 12) % 12;
  const nextMonth1 = nextMonth0 + 1;
  const clampedDay = Math.min(day, lastDayOfMonthUtc(nextYear, nextMonth1));
  return Math.floor(
    Date.UTC(nextYear, nextMonth0, clampedDay, hour, minute, second) / 1000
  );
}

function addWindowUtc(startTs, unit, timeWindow, steps) {
  const totalUnits = timeWindow * steps;
  switch (unit) {
    case "seconds":
      return startTs + totalUnits;
    case "minutes":
      return startTs + totalUnits * 60;
    case "hours":
      return startTs + totalUnits * 3600;
    case "days":
      return startTs + totalUnits * 86400;
    case "weeks":
      return startTs + totalUnits * 604800;
    case "months":
      return addMonthsUtc(startTs, totalUnits);
    case "years":
      return addMonthsUtc(startTs, totalUnits * 12);
    case "decades":
      return addMonthsUtc(startTs, totalUnits * 120);
    default:
      throw new Error(`Unidade não suportada no helper JS: ${unit}`);
  }
}

function startTimeForUnit(unit) {
  switch (unit) {
    case "months":
      return 1706664000; // 2024-01-31T01:20:00Z
    case "years":
    case "decades":
      return 1709208000; // 2024-02-29T12:00:00Z
    default:
      return 1710000000; // UTC fixo para unidades constantes
  }
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

function aggregatePresentationStatus(cryptographicValid, proofStatuses) {
  const proofsVerified = proofStatuses.every((item) => item.verified === true);
  const revoked = proofStatuses.some((item) => item.revoked === true);
  return {
    cryptographic_valid: cryptographicValid === true,
    proofs_verified: proofsVerified,
    revoked,
    accepted: cryptographicValid === true && proofsVerified === true && revoked === false,
  };
}

function rootFromPresentation(presentationObj, attrName) {
  const raw = presentationObj?.requested_proof?.revealed_attrs?.[attrName]?.raw;
  if (!raw) {
    throw new Error(`A apresentação não revelou ${attrName}`);
  }
  return raw;
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
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_all_units_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_all_units_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_all_units_verifier.db");

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
    const issueRevocableCredential = fn(issuer, "issueRevocableCredential", "issue_revocable_credential");
    const createLinkSecret = fn(holder, "createLinkSecret", "create_link_secret");
    const createCredentialRequest = fn(holder, "createCredentialRequest", "create_credential_request");
    const storeCredential = fn(holder, "storeCredential", "store_credential");
    const createPresentation = fn(holder, "createPresentation", "create_presentation");
    const verifyPresentation = fn(verifier, "verifyPresentation", "verify_presentation");
    const revocationBuildManifestAnchor = fn(issuer, "revocationBuildManifestAnchor", "revocation_build_manifest_anchor");
    const revocationWriteManifestAnchorOnLedger = fn(issuer, "revocationWriteManifestAnchorOnLedger", "revocation_write_manifest_anchor_on_ledger");
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
    const verifyPresentationRevocationProofWithExpectedRoot = fn(
      verifier,
      "verifyPresentationRevocationProofWithExpectedRoot",
      "verify_presentation_revocation_proof_with_expected_root"
    );
    const revokeIssuedCredential = fn(issuer, "revokeIssuedCredential", "revoke_issued_credential");

    console.log("🚀 TESTE REVOGAÇÃO 38: apresentação única com todas as unidades de unit_of_time");

    console.log("1) Importando trustee e criando DIDs reais...");
    const [trusteeDid] = await importDidFromSeed(TRUSTEE_SEED);
    assert(trusteeDid === TRUSTEE_DID, `Trustee DID inesperado: ${trusteeDid}`);

    const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
    const [holderDid, holderVerkey] = await holder.createOwnDid();
    const [verifierDid, verifierVerkey] = await verifier.createOwnDid();

    assert(typeof issuerDid === "string" && issuerDid.length > 10, "issuerDid inválido");
    assert(typeof holderDid === "string" && holderDid.length > 10, "holderDid inválido");
    assert(typeof verifierDid === "string" && verifierDid.length > 10, "verifierDid inválido");

    console.log("2) Registrando emissor, holder e verifier na VON...");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, issuerDid, issuerVerkey, "ENDORSER");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, holderDid, holderVerkey, null);
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, verifierDid, verifierVerkey, null);

    console.log("3) Lendo e ancorando manifesto do serviço Bloom...");
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

    console.log("4) Holder criando link secret...");
    try {
      await createLinkSecret("default");
    } catch (_) {}

    console.log("5) Criando Schema, CredDef e Credencial para cada unidade...");
    const issuedByUnit = [];
    const schemasMap = {};
    const credDefsMap = {};

    for (const unit of UNITS) {
      const schemaId = await createAndRegisterSchema(
        genesisAbs,
        issuerDid,
        `SchemaRevocable_${unit}_${Date.now()}`,
        `1.${nowSec()}`,
        ["nome", "identificador", ...CONTROL_ATTRS]
      );

      const localCredDefJson = await creddefSaveLocal(
        issuerDid,
        schemaId,
        `TAG_REV_${unit.toUpperCase()}_${Date.now()}`,
        false,
        "prod"
      );
      const localCredDef = parseJsonSafe(localCredDefJson, `creddef_local_${unit}`);
      const credDefRegObj = await creddefRegisterFromLocal(genesisAbs, localCredDef.id_local, issuerDid);
      const credDefId = credDefRegObj.credDefId || credDefRegObj.cred_def_id;

      const schemaLedger = parseJsonSafe(
        await fetchSchemaFromLedger(genesisAbs, schemaId),
        `schema_${unit}`
      );
      const credDefLedger = parseJsonSafe(
        await fetchCredDefFromLedger(genesisAbs, credDefId),
        `creddef_${unit}`
      );
      schemasMap[schemaId] = schemaLedger;
      credDefsMap[credDefId] = credDefLedger;

      const startTime = startTimeForUnit(unit);
      const timeWindow = 1;
      const validityEnd = addWindowUtc(startTime, unit, timeWindow, 2);

      const offerJson = await createCredentialOffer(
        credDefId,
        `offer-all-units-${unit}-${Date.now()}`
      );
      const requestJson = await createCredentialRequest(
        "default",
        holderDid,
        JSON.stringify(credDefLedger),
        offerJson
      );
      const requestMetadataId = extractNonce(offerJson);

      const issue = parseJsonSafe(
        await issueRevocableCredential(
          genesisAbs,
          `issued-all-units-${unit}-${Date.now()}`,
          holderDid,
          credDefId,
          schemaId,
          offerJson,
          requestJson,
          JSON.stringify({
            nome: `Alice ${unit}`,
            identificador: `ID-${unit}-${Date.now()}`,
          }),
          startTime,
          validityEnd,
          unit,
          timeWindow,
          10,
          JSON.stringify(manifest),
          null,
          null
        ),
        `issue_${unit}`
      );

      const credentialId = `cred-all-units-${unit}-${Date.now()}`;
      await storeCredential(
        credentialId,
        issue.credential_json,
        requestMetadataId,
        JSON.stringify(credDefLedger),
        null
      );

      const bundleId = `bundle-all-units-${unit}-${Date.now()}`;
      parseJsonSafe(
        await storeReceivedRevocableCredential(
          bundleId,
          JSON.stringify(issue.holder_bundle),
          credentialId
        ),
        `store_bundle_${unit}`
      );

      issuedByUnit.push({
        unit,
        schemaId,
        credDefId,
        schemaLedger,
        credDefLedger,
        issue,
        credentialId,
        bundleId,
      });
    }

    assert(issuedByUnit.length === UNITS.length, "deveria haver uma credencial por unidade");

    console.log("6) Holder criando apresentação única com todas as credenciais...");
    const presReq = {
      nonce: String(Date.now() * 1000 + 54321),
      name: "ProofReqAllTimeUnitsRevocation",
      version: "0.1",
      requested_attributes: {},
      requested_predicates: {},
    };
    const reqCreds = {
      requested_attributes: {},
      requested_predicates: {},
    };

    for (const item of issuedByUnit) {
      presReq.requested_attributes[`attr_nome_${item.unit}`] = {
        name: "nome",
        restrictions: [{ cred_def_id: item.credDefId }],
      };
      presReq.requested_attributes[`attr_identificador_${item.unit}`] = {
        name: "identificador",
        restrictions: [{ cred_def_id: item.credDefId }],
      };
      presReq.requested_attributes[`attr_seed_${item.unit}`] = {
        name: "seed",
        restrictions: [{ cred_def_id: item.credDefId }],
      };
      presReq.requested_attributes[`attr_start_time_${item.unit}`] = {
        name: "start_time",
        restrictions: [{ cred_def_id: item.credDefId }],
      };
      presReq.requested_attributes[`attr_unit_of_time_${item.unit}`] = {
        name: "unit_of_time",
        restrictions: [{ cred_def_id: item.credDefId }],
      };
      presReq.requested_attributes[`attr_time_window_${item.unit}`] = {
        name: "time_window",
        restrictions: [{ cred_def_id: item.credDefId }],
      };
      presReq.requested_attributes[`attr_root_merkle_${item.unit}`] = {
        name: "root_merkle_L",
        restrictions: [{ cred_def_id: item.credDefId }],
      };

      reqCreds.requested_attributes[`attr_nome_${item.unit}`] = {
        cred_id: item.credentialId,
        revealed: true,
      };
      reqCreds.requested_attributes[`attr_identificador_${item.unit}`] = {
        cred_id: item.credentialId,
        revealed: true,
      };
      reqCreds.requested_attributes[`attr_seed_${item.unit}`] = {
        cred_id: item.credentialId,
        revealed: true,
      };
      reqCreds.requested_attributes[`attr_start_time_${item.unit}`] = {
        cred_id: item.credentialId,
        revealed: true,
      };
      reqCreds.requested_attributes[`attr_unit_of_time_${item.unit}`] = {
        cred_id: item.credentialId,
        revealed: true,
      };
      reqCreds.requested_attributes[`attr_time_window_${item.unit}`] = {
        cred_id: item.credentialId,
        revealed: true,
      };
      reqCreds.requested_attributes[`attr_root_merkle_${item.unit}`] = {
        cred_id: item.credentialId,
        revealed: true,
      };
    }

    const presentationJson = await createPresentation(
      JSON.stringify(presReq),
      JSON.stringify(reqCreds),
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap)
    );
    const presentation = parseJsonSafe(presentationJson, "presentation_all_units");
    assert(
      Array.isArray(presentation.identifiers) && presentation.identifiers.length >= UNITS.length,
      "a apresentação deveria usar todas as credenciais emitidas"
    );

    console.log("7) Verifier validando a apresentação criptograficamente...");
    const cryptoBefore = await verifyPresentation(
      JSON.stringify(presReq),
      presentationJson,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap)
    );
    assert(cryptoBefore === true, "a apresentação deveria ser criptograficamente válida");

    console.log("8) Verifier validando as provas complementares de todas as credenciais...");
    const beforeProofStatuses = [];
    const proofPayloads = {};

    for (const item of issuedByUnit) {
      const proofResponse = parseJsonSafe(
        await buildPresentationRevocationProof(item.bundleId, 0, item.credentialId),
        `proof_${item.unit}`
      );
      proofPayloads[item.unit] = proofResponse.proof;
      const expectedRoot = rootFromPresentation(
        presentation,
        `attr_root_merkle_${item.unit}`
      );
      const verifyProof = parseJsonSafe(
        await verifyPresentationRevocationProofWithExpectedRoot(
          JSON.stringify(proofResponse.proof),
          expectedRoot
        ),
        `verify_proof_before_${item.unit}`
      );
      beforeProofStatuses.push(verifyProof.status);
      assert(
        verifyProof.status.verified === true,
        `a prova complementar deveria verificar para ${item.unit}`
      );
      assert(
        verifyProof.status.revoked === false,
        `antes da revogação nenhuma credencial deveria estar revogada (${item.unit})`
      );
    }

    const beforeAggregate = aggregatePresentationStatus(cryptoBefore, beforeProofStatuses);
    assert(beforeAggregate.accepted === true, "antes da revogação a apresentação deveria ser aceita");

    console.log("9) Emissor revogando apenas a credencial da unidade 'months'...");
    const revokedUnit = "months";
    const revokedItem = issuedByUnit.find((item) => item.unit === revokedUnit);
    assert(revokedItem, "credencial da unidade months deveria existir");

    const revokeJson = await revokeIssuedCredential(
      revokedItem.issue.issuer_record.issuer_local_credential_id,
      BFILTER_ADMIN_TOKEN,
      0,
      "revogacao-de-uma-unidade-especifica",
      "teste-node"
    );
    const revokeResponse = parseJsonSafe(revokeJson, "revoke_months");
    assert(revokeResponse.ok === true, "revokeIssuedCredential deveria retornar ok=true");
    assert(revokeResponse.bloom.ok === true, "o Bloom deveria aceitar a revogação");

    console.log("10) Reancorando o manifesto atualizado e revalidando a mesma apresentação...");
    const cryptoAfter = await verifyPresentation(
      JSON.stringify(presReq),
      presentationJson,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap)
    );
    assert(
      cryptoAfter === true,
      "criptograficamente a apresentação deveria continuar válida após a revogação"
    );

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
    const writeManifestAfterJson = await revocationWriteManifestAnchorOnLedger(
      genesisAbs,
      issuerDid,
      manifestAfterJson
    );
    const writeManifestAfter = parseJsonSafe(writeManifestAfterJson, "write_manifest_after");
    assert(writeManifestAfter.ok === true, "reanchor do manifesto após revogação falhou");

    const afterProofStatuses = [];
    for (const item of issuedByUnit) {
      const expectedRoot = rootFromPresentation(
        presentation,
        `attr_root_merkle_${item.unit}`
      );
      const proofAfter = {
        ...proofPayloads[item.unit],
        manifest: writeManifestAfter.manifest,
      };
      const verifyProof = parseJsonSafe(
        await verifyPresentationRevocationProofWithExpectedRoot(
          JSON.stringify(proofAfter),
          expectedRoot
        ),
        `verify_proof_after_${item.unit}`
      );
      afterProofStatuses.push({ unit: item.unit, ...verifyProof.status });
      assert(
        verifyProof.status.verified === true,
        `a prova complementar deveria continuar criptograficamente válida para ${item.unit}`
      );
    }

    const revokedStatuses = afterProofStatuses.filter((item) => item.revoked === true);
    assert(revokedStatuses.length === 1, "apenas uma credencial deveria aparecer como revogada");
    assert(
      revokedStatuses[0].unit === revokedUnit,
      "a única credencial revogada deveria ser a da unidade months"
    );

    const afterAggregate = aggregatePresentationStatus(
      cryptoAfter,
      afterProofStatuses
    );
    assert(afterAggregate.cryptographic_valid === true, "a apresentação deveria continuar criptograficamente correta");
    assert(afterAggregate.proofs_verified === true, "todas as provas complementares deveriam verificar");
    assert(afterAggregate.revoked === true, "a apresentação deve ser considerada revogada");
    assert(afterAggregate.accepted === false, "a apresentação não deve ser aceita quando uma credencial foi revogada");

    console.log("✅ OK: TESTE REVOGAÇÃO 38 passou.");
    console.log("📌 Resumo final:", {
      units: UNITS.length,
      revoked_unit: revokedUnit,
      cryptographic_valid: afterAggregate.cryptographic_valid,
      proofs_verified: afterAggregate.proofs_verified,
      revoked: afterAggregate.revoked,
      accepted: afterAggregate.accepted,
    });
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
    try { await verifier.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 38:", e && e.stack ? e.stack : e);
  process.exit(1);
});
