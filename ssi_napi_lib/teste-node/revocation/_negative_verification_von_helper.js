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

async function createNegativeVerificationContext(label) {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER || path.join(walletDir, `test_wallet_${label}_issuer.db`);
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, `test_wallet_${label}_holder.db`);
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, `test_wallet_${label}_verifier.db`);

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
  const revocationReadKVectorFromLedger = fn(
    issuer,
    "revocationReadKVectorFromLedger",
    "revocation_read_k_vector_from_ledger"
  );
  const createLinkSecret = fn(holder, "createLinkSecret", "create_link_secret");
  const createDidV2 = fn(holder, "createDidV2", "create_did_v2");
  const createCredentialRequest = fn(holder, "createCredentialRequest", "create_credential_request");
  const storeCredential = fn(holder, "storeCredential", "store_credential");
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

  const [trusteeDid] = await importDidFromSeed(
    process.env.TRUSTEE_SEED || NETWORK_CONFIG.trusteeSeed
  );
  assert(
    trusteeDid === (process.env.TRUSTEE_DID || NETWORK_CONFIG.trusteeDid),
    `Trustee DID inesperado: ${trusteeDid}`
  );

  const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
  await tryRegisterDid(
    issuer,
    genesisAbs,
    process.env.TRUSTEE_DID || NETWORK_CONFIG.trusteeDid,
    issuerDid,
    issuerVerkey,
    "ENDORSER"
  );

  const schemaName = `SchemaNegativeVerify_${label}_${Date.now()}`;
  const schemaVersion = `1.${nowSec()}`;
  const businessAttrs = ["nome", "cpf", "idade"];
  const schemaAttrs = [...businessAttrs, ...CONTROL_ATTRS];

  const schemaId = await createAndRegisterSchema(
    genesisAbs,
    issuerDid,
    schemaName,
    schemaVersion,
    schemaAttrs
  );
  const localCredDefJson = await creddefSaveLocal(
    issuerDid,
    schemaId,
    `TAG_NEG_VERIFY_${label}_${nowSec()}`,
    false,
    "prod"
  );
  const localCredDef = parseJsonSafe(localCredDefJson, "creddef_local");
  const credDefRegObj = await creddefRegisterFromLocal(genesisAbs, localCredDef.id_local, issuerDid);
  const credDefId = credDefRegObj.credDefId || credDefRegObj.cred_def_id;
  assert(typeof credDefId === "string" && credDefId.includes(":3:CL:"), "credDefId inválido");

  const credDefLedgerObj = parseJsonSafe(
    await fetchCredDefFromLedger(genesisAbs, credDefId),
    "creddef_ledger"
  );
  await fetchSchemaFromLedger(genesisAbs, schemaId);

  try {
    await createLinkSecret("default");
  } catch (_) {}

  const didRaw = await createDidV2("{}");
  const didObj = typeof didRaw === "string" ? JSON.parse(didRaw) : didRaw;
  const holderDid = didObj.did || didObj.myDid || didObj.id;
  assert(typeof holderDid === "string" && holderDid.length > 10, "holderDid inválido");

  const offerJson = await createCredentialOffer(credDefId, `offer-neg-${label}-${Date.now()}`);
  const requestJson = await createCredentialRequest(
    "default",
    holderDid,
    JSON.stringify(credDefLedgerObj),
    offerJson
  );
  const requestMetadataId = extractNonce(offerJson);

  const startTime = nowSec();
  const validityEnd = startTime + 86400 * 30;
  const issue = parseJsonSafe(
    await issueRevocableCredential(
      genesisAbs,
      `issued-neg-${label}-${Date.now()}`,
      holderDid,
      credDefId,
      schemaId,
      offerJson,
      requestJson,
      JSON.stringify({
        nome: `Alice ${label}`,
        cpf: String(10000000000 + Math.floor(Math.random() * 89999999999)),
        idade: "29",
      }),
      startTime,
      validityEnd,
      "days",
      1,
      10,
      "",
      null,
      null
    ),
    "issue_revocable"
  );

  const credentialId = `cred-neg-${label}-${Date.now()}`;
  await storeCredential(
    credentialId,
    issue.credential_json,
    requestMetadataId,
    JSON.stringify(credDefLedgerObj),
    null
  );

  const bundleId = `bundle-neg-${label}-${Date.now()}`;
  parseJsonSafe(
    await storeReceivedRevocableCredential(
      bundleId,
      JSON.stringify(issue.holder_bundle),
      credentialId
    ),
    "store_bundle"
  );

  const proofResponse = parseJsonSafe(
    await buildPresentationRevocationProof(bundleId, 0, credentialId),
    "proof_response"
  );
  proofResponse.proof.manifest = null;

  const anchor = proofResponse.proof.k_ledger_anchor;
  assert(anchor && anchor.k_vector_id, "a prova deveria carregar k_ledger_anchor");

  const readK = parseJsonSafe(
    await revocationReadKVectorFromLedger(genesisAbs, anchor.issuer_did, anchor.k_vector_id),
    "read_k"
  );

  return {
    genesisAbs,
    issuerDid,
    holderDid,
    credentialId,
    bundleId,
    issue,
    proof: proofResponse.proof,
    kVectorValues: readK.k_vector.values,
    verifyPresentationRevocationProof,
    async close() {
      try { await issuer.walletClose(); } catch {}
      try { await holder.walletClose(); } catch {}
      try { await verifier.walletClose(); } catch {}
    },
  };
}

module.exports = {
  createNegativeVerificationContext,
};
