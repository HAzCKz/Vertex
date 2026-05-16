/*
PARA RODAR ESTE TESTE:
cd /home/yugi/programacao/ssi_napi_lib
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
node teste-node/presentations/teste_tres_credenciais_revogaveis_envelope_exchange_zkp18_strict_files.js

BFILTER_ENABLE_TEST_API=1 BFILTER_ADMIN_TOKEN="dev-admin-token" cargo run

O QUE ESTE TESTE FAZ:
- Replica a ideia do teste strict files de 3 credenciais + ZKP idade>=18;
- Mas agora as 3 credenciais são revogáveis;
- O emissor envia ao holder, por envelope authcrypt, o pacote completo revogável:
  credential_json + holder_bundle;
- O holder armazena o bundle completo (com todas as janelas possíveis);
- Quando o verifier pede a prova, o holder envia somente as janelas necessárias
  para a consulta de revogação;
- Os pacotes trocados entre stores SSI são cifrados para o DID do destinatário
  e autenticados pelo DID do remetente.

Arquivos gerados em:
- teste-node/presentations/exchange_3revocable_creds_zkp18_envelope_strict_files
*/

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const { IndyAgent } = require(path.join(__dirname, "..", "..", "index.node"));

const CONTROL_ATTRS = [
  "seed",
  "start_time",
  "unit_of_time",
  "time_window",
  "root_merkle_L",
];
const DEFAULT_EXTRA_WINDOWS_FOR_FP = 10;

function rmIfExists(walletDbPath) {
  const sidecar = `${walletDbPath}.kdf.json`;
  try { fs.unlinkSync(walletDbPath); } catch (_) {}
  try { fs.unlinkSync(sidecar); } catch (_) {}
  try { fs.unlinkSync(`${sidecar}.tmp`); } catch (_) {}
  try { fs.unlinkSync(`${walletDbPath}-shm`); } catch (_) {}
  try { fs.unlinkSync(`${walletDbPath}-wal`); } catch (_) {}
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || "assert falhou");
}

function mustEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Env ${name} não definida.`);
  return v;
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function sha256Base64(input) {
  return crypto.createHash("sha256").update(input).digest("base64");
}

function writeFileAtomic(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, data, "utf8");
}

function readFileUtf8(filePath) {
  return fs.readFileSync(filePath, "utf8");
}

function pExchange(exchangeDir, name) {
  return path.join(exchangeDir, name);
}

function writeJson(filePath, obj) {
  writeFileAtomic(filePath, JSON.stringify(obj, null, 2));
}

function readJson(filePath) {
  return JSON.parse(readFileUtf8(filePath));
}

function parseJsonSafe(raw, label) {
  try {
    return typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch (e) {
    throw new Error(`${label}: JSON inválido: ${e.message}`);
  }
}

function call(agent, camel, snake) {
  if (typeof agent[camel] === "function") return agent[camel].bind(agent);
  if (snake && typeof agent[snake] === "function") return agent[snake].bind(agent);
  throw new Error(`Método não encontrado: ${camel}${snake ? ` / ${snake}` : ""}`);
}

function withManifestOnProof(proof, manifestAnchor) {
  return {
    ...proof,
    manifest: manifestAnchor,
  };
}

async function packEnvelopeToFile(
  senderAgent,
  senderDid,
  recipientVerkey,
  kind,
  threadIdOpt,
  plaintext,
  expiresAtMsOpt,
  metaObjOpt,
  filePath
) {
  const envelopeJson = await senderAgent.envelopePackAuthcrypt(
    senderDid,
    recipientVerkey,
    kind,
    threadIdOpt ?? null,
    plaintext,
    expiresAtMsOpt ?? null,
    metaObjOpt ? JSON.stringify(metaObjOpt) : null
  );
  writeFileAtomic(filePath, envelopeJson);
}

async function unpackEnvelopeFromFile(receiverAgent, receiverDid, filePath) {
  const envelopeJson = readFileUtf8(filePath);
  return receiverAgent.envelopeUnpackAuto(receiverDid, envelopeJson);
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

async function resetBfilterToDefault(baseUrl, adminToken) {
  let resp;
  try {
    resp = await fetch(`${baseUrl}/test/reset`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${adminToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({}),
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

(async () => {
  const GENESIS_FILE = mustEnv("GENESIS_FILE");
  const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
  const TRUSTEE_SEED = mustEnv("TRUSTEE_SEED");
  const TRUSTEE_DID = mustEnv("TRUSTEE_DID");
  const BFILTER_BASE_URL = mustEnv("BFILTER_BASE_URL");
  const BFILTER_ADMIN_TOKEN = mustEnv("BFILTER_ADMIN_TOKEN");

  const walletsDir = path.join(__dirname, "..", "wallets");
  fs.mkdirSync(walletsDir, { recursive: true });

  const exchangeDir = path.join(
    __dirname,
    "exchange_3revocable_creds_zkp18_envelope_strict_files"
  );
  fs.mkdirSync(exchangeDir, { recursive: true });

  const issuerWalletPath = path.join(walletsDir, "issuer_3revocable_creds_zkp18_envelope.db");
  const holderWalletPath = path.join(walletsDir, "holder_3revocable_creds_zkp18_envelope.db");
  const verifierWalletPath = path.join(walletsDir, "verifier_3revocable_creds_zkp18_envelope.db");
  rmIfExists(issuerWalletPath);
  rmIfExists(holderWalletPath);
  rmIfExists(verifierWalletPath);

  const issuer = new IndyAgent();
  const holder = new IndyAgent();
  const verifier = new IndyAgent();

  const issuerPubFile = pExchange(exchangeDir, "pub_issuer.json");
  const holderPubFile = pExchange(exchangeDir, "pub_holder.json");
  const verifierPubFile = pExchange(exchangeDir, "pub_verifier.json");
  const ledgerIdsFile = pExchange(exchangeDir, "ledger_ids.json");

  try {
    const createAndRegisterSchema = call(issuer, "createAndRegisterSchema", "create_and_register_schema");
    const creddefSaveLocal = call(issuer, "creddefSaveLocal", "creddef_save_local");
    const creddefRegisterFromLocal = call(issuer, "creddefRegisterFromLocal", "creddef_register_from_local");
    const createCredentialOffer = call(issuer, "createCredentialOffer", "create_credential_offer");
    const createCredentialRequest = call(holder, "createCredentialRequest", "create_credential_request");
    const createLinkSecret = call(holder, "createLinkSecret", "create_link_secret");
    const storeCredential = call(holder, "storeCredential", "store_credential");
    const createPresentationPackageWithRevocation = call(
      holder,
      "createPresentationPackageWithRevocation",
      "create_presentation_package_with_revocation"
    );
    const verifyMixedPresentationPackage = call(
      verifier,
      "verifyMixedPresentationPackage",
      "verify_mixed_presentation_package"
    );
    const revocationBuildManifestAnchor = call(
      issuer,
      "revocationBuildManifestAnchor",
      "revocation_build_manifest_anchor"
    );
    const revocationWriteManifestAnchorOnLedger = call(
      issuer,
      "revocationWriteManifestAnchorOnLedger",
      "revocation_write_manifest_anchor_on_ledger"
    );
    const issueRevocableCredential = call(issuer, "issueRevocableCredential", "issue_revocable_credential");
    const storeReceivedRevocableCredential = call(
      holder,
      "storeReceivedRevocableCredential",
      "store_received_revocable_credential"
    );
    const revokeIssuedCredential = call(issuer, "revokeIssuedCredential", "revoke_issued_credential");

    async function fetchCurrentManifestAnchor() {
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
      return parseJsonSafe(manifestJson, "current_manifest_anchor");
    }

    console.log("1) Resetando o bfilter para um estado limpo...");
    await resetBfilterToDefault(BFILTER_BASE_URL, BFILTER_ADMIN_TOKEN);

    console.log("2) Criando wallets...");
    await issuer.walletCreate(issuerWalletPath, WALLET_PASS);
    await holder.walletCreate(holderWalletPath, WALLET_PASS);
    await verifier.walletCreate(verifierWalletPath, WALLET_PASS);

    console.log("3) Abrindo wallets...");
    await issuer.walletOpen(issuerWalletPath, WALLET_PASS);
    await holder.walletOpen(holderWalletPath, WALLET_PASS);
    await verifier.walletOpen(verifierWalletPath, WALLET_PASS);

    console.log("4) Conectando na rede...");
    await issuer.connectNetwork(GENESIS_FILE);
    await holder.connectNetwork(GENESIS_FILE);
    await verifier.connectNetwork(GENESIS_FILE);

    console.log("5) Importando Trustee DID no issuer...");
    await issuer.importDidFromSeed(TRUSTEE_SEED);

    console.log("6) Criando DIDs e publicando bootstrap dos 3 atores...");
    const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
    const [holderDid, holderVerkey] = await holder.createOwnDid();
    const [verifierDid, verifierVerkey] = await verifier.createOwnDid();
    writeJson(issuerPubFile, { did: issuerDid, verkey: issuerVerkey });
    writeJson(holderPubFile, { did: holderDid, verkey: holderVerkey });
    writeJson(verifierPubFile, { did: verifierDid, verkey: verifierVerkey });

    console.log("7) Registrando DIDs no ledger...");
    await tryRegisterDid(issuer, GENESIS_FILE, TRUSTEE_DID, issuerDid, issuerVerkey, "ENDORSER");
    await tryRegisterDid(issuer, GENESIS_FILE, TRUSTEE_DID, holderDid, holderVerkey, null);
    await tryRegisterDid(issuer, GENESIS_FILE, TRUSTEE_DID, verifierDid, verifierVerkey, null);

    console.log("8) Lendo manifesto do Bloom e ancorando no ledger...");
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
      GENESIS_FILE,
      issuerDid,
      JSON.stringify(manifest)
    );
    const writeManifest = parseJsonSafe(writeManifestJson, "write_manifest");
    assert(writeManifest.ok === true, "write manifesto falhou");

    console.log("9) Criando 3 Schemas revogáveis...");
    const schemaCpfId = await createAndRegisterSchema(
      GENESIS_FILE,
      issuerDid,
      `cpf_revogavel_strict`,
      `1.0.${Date.now()}`,
      ["nome", "cpf", "idade", ...CONTROL_ATTRS]
    );
    const schemaEndId = await createAndRegisterSchema(
      GENESIS_FILE,
      issuerDid,
      `endereco_revogavel_strict`,
      `1.0.${Date.now() + 1}`,
      ["nome", "endereco", "cidade", "estado", ...CONTROL_ATTRS]
    );
    const schemaContatoId = await createAndRegisterSchema(
      GENESIS_FILE,
      issuerDid,
      `contato_revogavel_strict`,
      `1.0.${Date.now() + 2}`,
      ["nome", "email", "telefone", ...CONTROL_ATTRS]
    );

    async function registerRevocableCredDef(schemaId, tag) {
      const localJson = await creddefSaveLocal(issuerDid, schemaId, tag, false, "prod");
      const local = parseJsonSafe(localJson, `creddef_local_${tag}`);
      const reg = await creddefRegisterFromLocal(GENESIS_FILE, local.id_local, issuerDid);
      return reg.credDefId || reg.cred_def_id;
    }

    console.log("10) Criando 3 CredDefs revogáveis...");
    const credDefCpfId = await registerRevocableCredDef(schemaCpfId, `TAG_CPF_REV_STRICT_${Date.now()}`);
    const credDefEndId = await registerRevocableCredDef(schemaEndId, `TAG_END_REV_STRICT_${Date.now()}`);
    const credDefContatoId = await registerRevocableCredDef(schemaContatoId, `TAG_CONTATO_REV_STRICT_${Date.now()}`);

    writeJson(ledgerIdsFile, {
      schemaCpfId,
      schemaEndId,
      schemaContatoId,
      credDefCpfId,
      credDefEndId,
      credDefContatoId,
    });

    console.log("11) Garantindo Link Secret no holder...");
    try { await createLinkSecret("default"); } catch (_) {}

    async function issueRevocableCredentialViaEnvelope({
      kind,
      schemaId,
      credDefId,
      businessValues,
      credentialIdInWallet,
      bundleId,
      issuedId,
    }) {
      const offerId = `offer-${kind}-${Date.now()}`;
      const offerJson = await createCredentialOffer(credDefId, offerId);
      const offerFile = pExchange(exchangeDir, `${kind}_01_offer.env.json`);
      await packEnvelopeToFile(
        issuer,
        issuerDid,
        holderVerkey,
        "ssi/cred/offer",
        null,
        offerJson,
        null,
        { step: `${kind}.offer` },
        offerFile
      );

      const offerPlain = await unpackEnvelopeFromFile(holder, holderDid, offerFile);
      const offerObj = JSON.parse(offerPlain);
      const reqMetaId = offerObj?.nonce;
      assert(reqMetaId, `${kind}: offer sem nonce`);

      const credDefJsonLedger = await holder.fetchCredDefFromLedger(GENESIS_FILE, credDefId);
      const requestJson = await createCredentialRequest(
        "default",
        holderDid,
        credDefJsonLedger,
        offerPlain
      );

      const reqFile = pExchange(exchangeDir, `${kind}_02_request.env.json`);
      await packEnvelopeToFile(
        holder,
        holderDid,
        issuerVerkey,
        "ssi/cred/request",
        null,
        requestJson,
        null,
        { step: `${kind}.request` },
        reqFile
      );

      const reqPlain = await unpackEnvelopeFromFile(issuer, issuerDid, reqFile);

      const startTime = nowSec();
      const validityEnd = startTime + 86400 * 30;
      const issuePackageJson = await issueRevocableCredential(
        GENESIS_FILE,
        issuedId,
        holderDid,
        credDefId,
        schemaId,
        offerJson,
        reqPlain,
        JSON.stringify(businessValues),
        startTime,
        validityEnd,
        "days",
        1,
        DEFAULT_EXTRA_WINDOWS_FOR_FP,
        JSON.stringify(manifest),
        null,
        null
      );
      const issuedPkg = parseJsonSafe(issuePackageJson, `issued_pkg_${kind}`);

      const credentialPackageFile = pExchange(exchangeDir, `${kind}_03_revocable_package.env.json`);
      await packEnvelopeToFile(
        issuer,
        issuerDid,
        holderVerkey,
        "ssi/revocation/credential_package",
        null,
        JSON.stringify(issuedPkg),
        null,
        {
          step: `${kind}.credential_package`,
          note: "issuer->holder envia credential_json + holder_bundle completo",
        },
        credentialPackageFile
      );

      const pkgPlain = await unpackEnvelopeFromFile(holder, holderDid, credentialPackageFile);
      const receivedPkg = parseJsonSafe(pkgPlain, `received_pkg_${kind}`);

      await storeCredential(
        credentialIdInWallet,
        receivedPkg.credential_json,
        reqMetaId,
        credDefJsonLedger,
        null
      );

      const storedBundleJson = await storeReceivedRevocableCredential(
        bundleId,
        JSON.stringify(receivedPkg.holder_bundle),
        credentialIdInWallet
      );
      const storedBundle = parseJsonSafe(storedBundleJson, `store_bundle_${kind}`);
      assert(storedBundle.ok === true, `${kind}: bundle não armazenado`);
      assert(
        storedBundle.holder_bundle.control.confirmation_window_count === DEFAULT_EXTRA_WINDOWS_FOR_FP,
        `${kind}: confirmation_window_count deveria ser ${DEFAULT_EXTRA_WINDOWS_FOR_FP}`
      );
      assert(
        storedBundle.holder_bundle.control.window_count > 1,
        `${kind}: bundle deveria conter múltiplas janelas possíveis`
      );
      assert(
        storedBundle.holder_bundle.l_values.length === storedBundle.holder_bundle.control.window_count,
        `${kind}: holder_bundle deveria carregar todos os L-values`
      );

      const receiptFile = pExchange(exchangeDir, `${kind}_04_store_receipt.env.json`);
      await packEnvelopeToFile(
        holder,
        holderDid,
        issuerVerkey,
        "ssi/cred/store_receipt",
        null,
        JSON.stringify({
          ok: true,
          kind,
          credential_id: credentialIdInWallet,
          bundle_id: bundleId,
          window_count_received: storedBundle.holder_bundle.control.window_count,
        }),
        null,
        { step: `${kind}.store_receipt` },
        receiptFile
      );

      const receiptPlain = await unpackEnvelopeFromFile(issuer, issuerDid, receiptFile);
      assert(JSON.parse(receiptPlain).ok === true, `${kind}: receipt inválido`);

      return {
        issuedPkg: receivedPkg,
        credentialIdInWallet,
        bundleId,
        credDefJsonLedger,
      };
    }

    console.log("12) Emitindo 3 credenciais revogáveis via envelopes...");
    const cpfFlow = await issueRevocableCredentialViaEnvelope({
      kind: "cpf",
      schemaId: schemaCpfId,
      credDefId: credDefCpfId,
      businessValues: { nome: "Edimar Verissimo", cpf: "12345678909", idade: "35" },
      credentialIdInWallet: "cred-cpf-rev-envelope-strict",
      bundleId: "bundle-cpf-rev-envelope-strict",
      issuedId: `issued-cpf-strict-${Date.now()}`,
    });
    const endFlow = await issueRevocableCredentialViaEnvelope({
      kind: "end",
      schemaId: schemaEndId,
      credDefId: credDefEndId,
      businessValues: {
        nome: "Edimar Verissimo",
        endereco: "Rua Exemplo, 123",
        cidade: "Sao Paulo",
        estado: "SP",
      },
      credentialIdInWallet: "cred-end-rev-envelope-strict",
      bundleId: "bundle-end-rev-envelope-strict",
      issuedId: `issued-end-strict-${Date.now()}`,
    });
    const contatoFlow = await issueRevocableCredentialViaEnvelope({
      kind: "contato",
      schemaId: schemaContatoId,
      credDefId: credDefContatoId,
      businessValues: {
        nome: "Edimar Verissimo",
        email: "edimar@example.com",
        telefone: "+5511999999999",
      },
      credentialIdInWallet: "cred-contato-rev-envelope-strict",
      bundleId: "bundle-contato-rev-envelope-strict",
      issuedId: `issued-contato-strict-${Date.now()}`,
    });

    console.log("13) Verifier criando Proof Request e gravando envelope...");
    const proofRequest = {
      nonce: String(Date.now()),
      name: "proof-3creds-revogaveis-zkp18-strict-files",
      version: "1.0",
      requested_attributes: {
        attr_nome: { name: "nome", restrictions: [{ cred_def_id: credDefCpfId }] },
        attr_cpf: { name: "cpf", restrictions: [{ cred_def_id: credDefCpfId }] },
        attr_endereco: { name: "endereco", restrictions: [{ cred_def_id: credDefEndId }] },
        attr_email: { name: "email", restrictions: [{ cred_def_id: credDefContatoId }] },
        attr_telefone: { name: "telefone", restrictions: [{ cred_def_id: credDefContatoId }] },
        attr_seed_cpf: { name: "seed", restrictions: [{ cred_def_id: credDefCpfId }] },
        attr_start_cpf: { name: "start_time", restrictions: [{ cred_def_id: credDefCpfId }] },
        attr_unit_cpf: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefCpfId }] },
        attr_window_cpf: { name: "time_window", restrictions: [{ cred_def_id: credDefCpfId }] },
        attr_root_cpf: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefCpfId }] },
        attr_seed_end: { name: "seed", restrictions: [{ cred_def_id: credDefEndId }] },
        attr_start_end: { name: "start_time", restrictions: [{ cred_def_id: credDefEndId }] },
        attr_unit_end: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefEndId }] },
        attr_window_end: { name: "time_window", restrictions: [{ cred_def_id: credDefEndId }] },
        attr_root_end: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefEndId }] },
        attr_seed_contato: { name: "seed", restrictions: [{ cred_def_id: credDefContatoId }] },
        attr_start_contato: { name: "start_time", restrictions: [{ cred_def_id: credDefContatoId }] },
        attr_unit_contato: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefContatoId }] },
        attr_window_contato: { name: "time_window", restrictions: [{ cred_def_id: credDefContatoId }] },
        attr_root_contato: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefContatoId }] },
      },
      requested_predicates: {
        pred_idade_ge_18: {
          name: "idade",
          p_type: ">=",
          p_value: 18,
          restrictions: [{ cred_def_id: credDefCpfId }],
        },
      },
    };

    const proofReqFile = pExchange(exchangeDir, "proof_01_request.env.json");
    await packEnvelopeToFile(
      verifier,
      verifierDid,
      holderVerkey,
      "ssi/proof/request",
      null,
      JSON.stringify(proofRequest),
      null,
      { step: "proof_request" },
      proofReqFile
    );

    console.log("14) Holder lendo Proof Request e montando Presentation Package com só as janelas necessárias...");
    const proofReqPlain = await unpackEnvelopeFromFile(holder, holderDid, proofReqFile);
    const proofReqObj = JSON.parse(proofReqPlain);

    const requestedCreds = {
      requested_attributes: {
        attr_nome: { cred_id: cpfFlow.credentialIdInWallet, revealed: true },
        attr_cpf: { cred_id: cpfFlow.credentialIdInWallet, revealed: true },
        attr_endereco: { cred_id: endFlow.credentialIdInWallet, revealed: true },
        attr_email: { cred_id: contatoFlow.credentialIdInWallet, revealed: true },
        attr_telefone: { cred_id: contatoFlow.credentialIdInWallet, revealed: true },
        attr_seed_cpf: { cred_id: cpfFlow.credentialIdInWallet, revealed: true },
        attr_start_cpf: { cred_id: cpfFlow.credentialIdInWallet, revealed: true },
        attr_unit_cpf: { cred_id: cpfFlow.credentialIdInWallet, revealed: true },
        attr_window_cpf: { cred_id: cpfFlow.credentialIdInWallet, revealed: true },
        attr_root_cpf: { cred_id: cpfFlow.credentialIdInWallet, revealed: true },
        attr_seed_end: { cred_id: endFlow.credentialIdInWallet, revealed: true },
        attr_start_end: { cred_id: endFlow.credentialIdInWallet, revealed: true },
        attr_unit_end: { cred_id: endFlow.credentialIdInWallet, revealed: true },
        attr_window_end: { cred_id: endFlow.credentialIdInWallet, revealed: true },
        attr_root_end: { cred_id: endFlow.credentialIdInWallet, revealed: true },
        attr_seed_contato: { cred_id: contatoFlow.credentialIdInWallet, revealed: true },
        attr_start_contato: { cred_id: contatoFlow.credentialIdInWallet, revealed: true },
        attr_unit_contato: { cred_id: contatoFlow.credentialIdInWallet, revealed: true },
        attr_window_contato: { cred_id: contatoFlow.credentialIdInWallet, revealed: true },
        attr_root_contato: { cred_id: contatoFlow.credentialIdInWallet, revealed: true },
      },
      requested_predicates: {
        pred_idade_ge_18: { cred_id: cpfFlow.credentialIdInWallet },
      },
    };

    const ids = readJson(ledgerIdsFile);
    const schemaCpfJsonLedger = await holder.fetchSchemaFromLedger(GENESIS_FILE, ids.schemaCpfId);
    const schemaEndJsonLedger = await holder.fetchSchemaFromLedger(GENESIS_FILE, ids.schemaEndId);
    const schemaContatoJsonLedger = await holder.fetchSchemaFromLedger(GENESIS_FILE, ids.schemaContatoId);
    const credDefCpfJsonLedger = await holder.fetchCredDefFromLedger(GENESIS_FILE, ids.credDefCpfId);
    const credDefEndJsonLedger = await holder.fetchCredDefFromLedger(GENESIS_FILE, ids.credDefEndId);
    const credDefContatoJsonLedger = await holder.fetchCredDefFromLedger(GENESIS_FILE, ids.credDefContatoId);

    const schemasMap = JSON.stringify({
      [ids.schemaCpfId]: JSON.parse(schemaCpfJsonLedger),
      [ids.schemaEndId]: JSON.parse(schemaEndJsonLedger),
      [ids.schemaContatoId]: JSON.parse(schemaContatoJsonLedger),
    });
    const credDefsMap = JSON.stringify({
      [ids.credDefCpfId]: JSON.parse(credDefCpfJsonLedger),
      [ids.credDefEndId]: JSON.parse(credDefEndJsonLedger),
      [ids.credDefContatoId]: JSON.parse(credDefContatoJsonLedger),
    });

    const presentationPackageJson = await createPresentationPackageWithRevocation(
      JSON.stringify(proofReqObj),
      JSON.stringify(requestedCreds),
      schemasMap,
      credDefsMap,
      JSON.stringify([
        { credential_id_local: cpfFlow.credentialIdInWallet, window_index: 0 },
        { credential_id_local: endFlow.credentialIdInWallet, window_index: 0 },
        { credential_id_local: contatoFlow.credentialIdInWallet, window_index: 0 },
      ])
    );
    const presentationPackage = parseJsonSafe(presentationPackageJson, "presentation_package");
    assert(presentationPackage.ok === true, "presentation package deveria retornar ok=true");
    assert(presentationPackage.revocation_proofs.length === 3, "holder deveria enviar só 3 provas complementares");
    assert(
      presentationPackage.revocation_proofs.every((item) => item.window_index === 0),
      "o holder deveria enviar apenas a janela necessária para cada credencial"
    );
    assert(
      cpfFlow.issuedPkg.holder_bundle.control.window_count > presentationPackage.revocation_proofs.length,
      "o holder deveria ter recebido mais janelas do que enviou ao verifier"
    );

    const packageEnvelopeFile = pExchange(exchangeDir, "proof_02_presentation_package.env.json");
    await packEnvelopeToFile(
      holder,
      holderDid,
      verifierVerkey,
      "ssi/proof/presentation_package_revocation",
      null,
      JSON.stringify(presentationPackage),
      null,
      {
        step: "proof.presentation_package",
        note: "holder->verifier envia só presentation_json + revocation_proofs necessários",
      },
      packageEnvelopeFile
    );

    console.log("15) Verifier lendo Presentation Package via envelope e verificando antes da revogação...");
    const packagePlain = await unpackEnvelopeFromFile(verifier, verifierDid, packageEnvelopeFile);
    const packageReceived = parseJsonSafe(packagePlain, "package_received");

    const verifierSchemasMap = JSON.stringify({
      [ids.schemaCpfId]: JSON.parse(await verifier.fetchSchemaFromLedger(GENESIS_FILE, ids.schemaCpfId)),
      [ids.schemaEndId]: JSON.parse(await verifier.fetchSchemaFromLedger(GENESIS_FILE, ids.schemaEndId)),
      [ids.schemaContatoId]: JSON.parse(await verifier.fetchSchemaFromLedger(GENESIS_FILE, ids.schemaContatoId)),
    });
    const verifierCredDefsMap = JSON.stringify({
      [ids.credDefCpfId]: JSON.parse(await verifier.fetchCredDefFromLedger(GENESIS_FILE, ids.credDefCpfId)),
      [ids.credDefEndId]: JSON.parse(await verifier.fetchCredDefFromLedger(GENESIS_FILE, ids.credDefEndId)),
      [ids.credDefContatoId]: JSON.parse(await verifier.fetchCredDefFromLedger(GENESIS_FILE, ids.credDefContatoId)),
    });

    const beforeJson = await verifyMixedPresentationPackage(
      JSON.stringify(proofReqObj),
      packageReceived.presentation_json,
      verifierSchemasMap,
      verifierCredDefsMap,
      JSON.stringify(
        packageReceived.revocation_proofs.map((item) => ({
          credential_id_local: item.credential_id_local,
          proof: item.proof,
        }))
      ),
      null
    );
    const before = parseJsonSafe(beforeJson, "verify_before");
    assert(before.ok === true, "verify before deveria retornar ok=true");
    assert(before.cryptographic_valid === true, "a apresentação deveria ser criptograficamente válida");
    assert(before.proofs_verified === true, "as provas complementares deveriam verificar");
    assert(before.revoked === false, "antes da revogação nenhuma credencial deveria estar revogada");
    assert(before.accepted === true, "antes da revogação a apresentação deveria ser aceita");

    console.log("16) Issuer revogando apenas a credencial CPF...");
    const revokeJson = await revokeIssuedCredential(
      cpfFlow.issuedPkg.issuer_record.issuer_local_credential_id,
      BFILTER_ADMIN_TOKEN,
      0,
      "revogacao-do-cpf-no-teste-strict-files",
      "teste-node"
    );
    const revoke = parseJsonSafe(revokeJson, "revoke_cpf");
    assert(revoke.ok === true, "revokeIssuedCredential deveria retornar ok=true");

    const currentManifest = await fetchCurrentManifestAnchor();
    const writeManifestAfterJson = await revocationWriteManifestAnchorOnLedger(
      GENESIS_FILE,
      issuerDid,
      JSON.stringify(currentManifest)
    );
    const writeManifestAfter = parseJsonSafe(writeManifestAfterJson, "write_manifest_after");
    assert(writeManifestAfter.ok === true, "write manifesto after revocation falhou");

    console.log("17) Verifier revalidando o mesmo pacote após a revogação...");
    const afterJson = await verifyMixedPresentationPackage(
      JSON.stringify(proofReqObj),
      packageReceived.presentation_json,
      verifierSchemasMap,
      verifierCredDefsMap,
      JSON.stringify(
        packageReceived.revocation_proofs.map((item) => ({
          credential_id_local: item.credential_id_local,
          proof: withManifestOnProof(item.proof, writeManifestAfter.manifest),
        }))
      ),
      null
    );
    const after = parseJsonSafe(afterJson, "verify_after");
    assert(after.ok === true, "verify after deveria retornar ok=true");
    assert(after.cryptographic_valid === true, "a apresentação deve continuar criptograficamente válida");
    assert(after.proofs_verified === true, "as provas complementares devem continuar válidas");
    assert(after.revoked === true, "após a revogação uma credencial deveria aparecer como revogada");
    assert(after.accepted === false, "após a revogação o pacote deveria ser rejeitado");

    const cpfStatusAfter = after.per_credential_status.find(
      (item) => item.credential_id_local === cpfFlow.credentialIdInWallet
    );
    const endStatusAfter = after.per_credential_status.find(
      (item) => item.credential_id_local === endFlow.credentialIdInWallet
    );
    const contatoStatusAfter = after.per_credential_status.find(
      (item) => item.credential_id_local === contatoFlow.credentialIdInWallet
    );
    assert(cpfStatusAfter, "o consolidado deveria conter o status do CPF");
    assert(endStatusAfter, "o consolidado deveria conter o status do endereço");
    assert(contatoStatusAfter, "o consolidado deveria conter o status do contato");
    assert(cpfStatusAfter.revoked === true, "a credencial CPF deveria ficar revogada");
    assert(endStatusAfter.revoked === false, "a credencial de endereço não deveria ficar revogada");
    assert(contatoStatusAfter.revoked === false, "a credencial de contato não deveria ficar revogada");

    const revokedStatuses = after.per_credential_status.filter(
      (item) => item.revocable === true && item.revoked === true
    );
    assert(
      revokedStatuses.length === 1,
      `somente uma credencial revogável deveria ficar revogada: ${JSON.stringify(revokedStatuses)}`
    );

    console.log("✅ OK: teste com 3 credenciais revogáveis + envelopes strict files passou.");
    console.log("📌 Resumo final:", {
      issuer_to_holder_window_count_cpf: cpfFlow.issuedPkg.holder_bundle.control.window_count,
      issuer_to_holder_window_count_end: endFlow.issuedPkg.holder_bundle.control.window_count,
      issuer_to_holder_window_count_contato: contatoFlow.issuedPkg.holder_bundle.control.window_count,
      holder_to_verifier_revocation_proofs: packageReceived.revocation_proofs.length,
      proofs_window_indexes: packageReceived.revocation_proofs.map((item) => item.window_index),
      accepted_before: before.accepted,
      accepted_after: after.accepted,
      revoked_after: after.revoked,
    });
    console.log(`📁 Arquivos gerados em: ${exchangeDir}`);
  } finally {
    try { await issuer.walletClose(); } catch (_) {}
    try { await holder.walletClose(); } catch (_) {}
    try { await verifier.walletClose(); } catch (_) {}
  }
})().catch((e) => {
  console.error("FALHA NO TESTE:", e?.message || e);
  console.error(e?.stack || "");
  process.exit(1);
});
