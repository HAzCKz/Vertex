/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
node teste-node/revocation/test_revocation_32_presentation_root_merkle_must_match_proof_von.js
*/

/*
Teste E2E de consistência entre a apresentação SSI
e a prova complementar de revogação pelo root Merkle.

O fluxo:
- cria/abre wallets de issuer, holder e verifier;
- conecta ao ledger e registra Schema/CredDef revogáveis;
- emite 2 credenciais revogáveis diferentes para o holder;
- holder armazena as 2 credenciais e seus bundles;
- cria uma apresentação usando apenas a primeira credencial;
- verifier valida a apresentação SSI normalmente;
- gera a prova complementar da credencial correta;
- testa também a prova da outra credencial, que possui root diferente.

Depois valida:
- a apresentação revela o root_merkle_L da credencial usada;
- a prova correta é aceita quando seu root coincide com o da apresentação;
- uma prova de outra credencial ainda pode ser válida isoladamente,
  mas deve ser rejeitada quando o root não bate com o da apresentação;
- a mensagem de erro indica divergência de root_merkle.

Foco do teste:
validar que o verifier deve comparar o root_merkle_L revelado
na apresentação com o root_merkle_l da prova complementar.
*/
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

function extractRevealedRootMerkkleFromPresentation(presentationObj) {
  const raw =
    presentationObj?.requested_proof?.revealed_attrs?.attr_root_merkle_L?.raw;
  if (!raw) {
    throw new Error("A apresentação não revelou root_merkle_L em attr_root_merkle_L");
  }
  return raw;
}

(async () => {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_root_match_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_root_match_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_root_match_verifier.db");

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
    const createDidV2 = fn(holder, "createDidV2", "create_did_v2");
    const createCredentialRequest = fn(holder, "createCredentialRequest", "create_credential_request");
    const storeCredential = fn(holder, "storeCredential", "store_credential");
    const createPresentation = fn(holder, "createPresentation", "create_presentation");
    const verifyPresentation = fn(verifier, "verifyPresentation", "verify_presentation");
    const issueRevocableCredential = fn(issuer, "issueRevocableCredential", "issue_revocable_credential");
    const storeReceivedRevocableCredential = fn(holder, "storeReceivedRevocableCredential", "store_received_revocable_credential");
    const buildPresentationRevocationProof = fn(holder, "buildPresentationRevocationProof", "build_presentation_revocation_proof");
    const verifyPresentationRevocationProof = fn(verifier, "verifyPresentationRevocationProof", "verify_presentation_revocation_proof");
    const verifyPresentationRevocationProofWithExpectedRoot = fn(
      verifier,
      "verifyPresentationRevocationProofWithExpectedRoot",
      "verify_presentation_revocation_proof_with_expected_root"
    );

    console.log("🚀 TESTE REVOGAÇÃO 32: root_merkle_L da apresentação deve coincidir com a prova");

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

    const schemaName = `SchemaRevocableRootMatch_${Date.now()}`;
    const schemaVersion = `1.${nowSec()}`;
    const businessAttrs = ["nome", "cpf", "idade"];
    const schemaAttrs = [...businessAttrs, ...CONTROL_ATTRS];

    console.log("1) Registrando Schema/CredDef revogáveis...");
    const schemaId = await createAndRegisterSchema(genesisAbs, issuerDid, schemaName, schemaVersion, schemaAttrs);
    const localCredDefJson = await creddefSaveLocal(
      issuerDid,
      schemaId,
      `TAG_REV_ROOT_MATCH_${nowSec()}`,
      false,
      "prod"
    );
    const localCredDef = parseJsonSafe(localCredDefJson, "creddef_local");
    const credDefRegObj = await creddefRegisterFromLocal(genesisAbs, localCredDef.id_local, issuerDid);
    const credDefId = credDefRegObj.credDefId || credDefRegObj.cred_def_id;
    assert(typeof credDefId === "string" && credDefId.includes(":3:CL:"), "credDefId inválido");

    const schemaLedgerObj = parseJsonSafe(
      await fetchSchemaFromLedger(genesisAbs, schemaId),
      "schema_ledger"
    );
    const credDefLedgerObj = parseJsonSafe(
      await fetchCredDefFromLedger(genesisAbs, credDefId),
      "creddef_ledger"
    );

    console.log("2) Holder criando DID e request...");
    try {
      await createLinkSecret("default");
    } catch (_) {}

    const didRaw = await createDidV2("{}");
    const didObj = typeof didRaw === "string" ? JSON.parse(didRaw) : didRaw;
    const holderDid = didObj.did || didObj.myDid || didObj.id;
    assert(typeof holderDid === "string" && holderDid.length > 10, "holderDid inválido");

    const offer1Json = await createCredentialOffer(credDefId, `offer-root-match-1-${Date.now()}`);
    const offer2Json = await createCredentialOffer(credDefId, `offer-root-match-2-${Date.now()}`);

    const request1Json = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefLedgerObj),
      offer1Json
    );
    const request2Json = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefLedgerObj),
      offer2Json
    );
    const request1MetadataId = extractNonce(offer1Json);
    const request2MetadataId = extractNonce(offer2Json);

    console.log("3) Emitindo duas credenciais revogáveis diferentes...");
    const startTime = nowSec();
    const validityEnd = startTime + 86400 * 30;

    const issue1 = parseJsonSafe(
      await issueRevocableCredential(
        genesisAbs,
        `issued-root-match-1-${Date.now()}`,
        holderDid,
        credDefId,
        schemaId,
        offer1Json,
        request1Json,
        JSON.stringify({
          nome: "Alice Root One",
          cpf: "12345678900",
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
      "issue1"
    );

    const issue2 = parseJsonSafe(
      await issueRevocableCredential(
        genesisAbs,
        `issued-root-match-2-${Date.now()}`,
        holderDid,
        credDefId,
        schemaId,
        offer2Json,
        request2Json,
        JSON.stringify({
          nome: "Alice Root Two",
          cpf: "12345678901",
          idade: "30",
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
      "issue2"
    );

    assert(
      issue1.control_values.root_merkle_l !== issue2.control_values.root_merkle_l,
      "as duas credenciais deveriam ter roots de Merkle diferentes"
    );

    console.log("4) Holder armazenando as duas credenciais e seus bundles...");
    const credential1Id = `cred-root-match-1-${Date.now()}`;
    const credential2Id = `cred-root-match-2-${Date.now()}`;
    await storeCredential(
      credential1Id,
      issue1.credential_json,
      request1MetadataId,
      JSON.stringify(credDefLedgerObj),
      null
    );
    await storeCredential(
      credential2Id,
      issue2.credential_json,
      request2MetadataId,
      JSON.stringify(credDefLedgerObj),
      null
    );

    const bundle1Id = `bundle-root-match-1-${Date.now()}`;
    const bundle2Id = `bundle-root-match-2-${Date.now()}`;
    parseJsonSafe(
      await storeReceivedRevocableCredential(
        bundle1Id,
        JSON.stringify(issue1.holder_bundle),
        credential1Id
      ),
      "store_bundle_1"
    );
    parseJsonSafe(
      await storeReceivedRevocableCredential(
        bundle2Id,
        JSON.stringify(issue2.holder_bundle),
        credential2Id
      ),
      "store_bundle_2"
    );

    console.log("5) Criando apresentação a partir da primeira credencial...");
    const presReq = {
      nonce: String(Date.now() * 1000 + 12345),
      name: "ProofReqRootMerkleMatch",
      version: "0.1",
      requested_attributes: {
        attr_nome: { name: "nome" },
        attr_seed: { name: "seed" },
        attr_start_time: { name: "start_time" },
        attr_unit_of_time: { name: "unit_of_time" },
        attr_time_window: { name: "time_window" },
        attr_root_merkle_L: { name: "root_merkle_L" },
      },
      requested_predicates: {},
    };

    const reqCreds = {
      requested_attributes: {
        attr_nome: { cred_id: credential1Id, revealed: true },
        attr_seed: { cred_id: credential1Id, revealed: true },
        attr_start_time: { cred_id: credential1Id, revealed: true },
        attr_unit_of_time: { cred_id: credential1Id, revealed: true },
        attr_time_window: { cred_id: credential1Id, revealed: true },
        attr_root_merkle_L: { cred_id: credential1Id, revealed: true },
      },
      requested_predicates: {},
    };

    const schemasMap = { [schemaId]: schemaLedgerObj };
    const credDefsMap = { [credDefId]: credDefLedgerObj };
    const presentationJson = await createPresentation(
      JSON.stringify(presReq),
      JSON.stringify(reqCreds),
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap)
    );
    const presentation = parseJsonSafe(presentationJson, "presentation");
    const presentationRoot = extractRevealedRootMerkkleFromPresentation(presentation);
    assert(
      presentationRoot === issue1.control_values.root_merkle_l,
      "a apresentação deveria revelar o root_merkle_L da primeira credencial"
    );

    const verifiedPresentation = await verifyPresentation(
      JSON.stringify(presReq),
      presentationJson,
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap)
    );
    assert(verifiedPresentation === true, "a apresentação deveria ser criptograficamente válida");

    console.log("6) Verificação positiva: prova da mesma credencial...");
    const proof1Response = parseJsonSafe(
      await buildPresentationRevocationProof(bundle1Id, 0, credential1Id),
      "proof1"
    );
    proof1Response.proof.manifest = null;

    const verify1 = parseJsonSafe(
      await verifyPresentationRevocationProof(JSON.stringify(proof1Response.proof)),
      "verify1"
    );
    assert(verify1.status.verified === true, "a prova 1 deveria validar localmente");
    const verify1WithRoot = parseJsonSafe(
      await verifyPresentationRevocationProofWithExpectedRoot(
        JSON.stringify(proof1Response.proof),
        presentationRoot
      ),
      "verify1_with_root"
    );
    assert(
      verify1WithRoot.status.verified === true,
      "a prova correta deveria validar nativamente quando o root da apresentação coincide"
    );
    assert(
      presentationRoot === proof1Response.proof.control.root_merkle_l,
      "o root_merkle_L da apresentação deveria coincidir com o da prova correta"
    );

    console.log("7) Verificação negativa: prova de outra credencial com root diferente...");
    const proof2Response = parseJsonSafe(
      await buildPresentationRevocationProof(bundle2Id, 0, credential2Id),
      "proof2"
    );
    proof2Response.proof.manifest = null;

    const verify2 = parseJsonSafe(
      await verifyPresentationRevocationProof(JSON.stringify(proof2Response.proof)),
      "verify2"
    );
    assert(
      verify2.status.verified === true,
      "a prova 2 sozinha ainda deveria validar localmente"
    );
    assert(
      presentationRoot !== proof2Response.proof.control.root_merkle_l,
      "o root_merkle_L da apresentação deveria divergir do root da prova errada"
    );
    const verify2WithRoot = parseJsonSafe(
      await verifyPresentationRevocationProofWithExpectedRoot(
        JSON.stringify(proof2Response.proof),
        presentationRoot
      ),
      "verify2_with_root"
    );
    assert(
      verify2WithRoot.status.verified === false,
      "a lib deveria rejeitar nativamente a prova cujo root não coincide com a apresentação"
    );
    assert(
      /root_merkle/i.test(verify2WithRoot.status.details),
      "a mensagem de erro deveria indicar divergência de root_merkle"
    );

    console.log("✅ OK: TESTE REVOGAÇÃO 32 passou.");
    console.log("📌 Regra confirmada: o verifier deve comparar o root_merkle_L revelado na apresentação com o root_merkle_l da prova complementar.");
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
    try { await verifier.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 32:", e && e.stack ? e.stack : e);
  process.exit(1);
});
