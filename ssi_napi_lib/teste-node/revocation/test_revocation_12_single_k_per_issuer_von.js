/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
node teste-node/revocation/test_revocation_12_single_k_per_issuer_von.js
*/
/*
Teste de garantia de vetor K único por DID do emissor.

O fluxo:
- cria/abre a wallet do emissor;
- conecta à von-network;
- importa o DID Trustee;
- cria e registra um DID do emissor no ledger;
- cria e publica o primeiro vetor K;
- repete a escrita do mesmo K para validar idempotência;
- tenta publicar um segundo K diferente para o mesmo DID;
- lê novamente o primeiro K no ledger.

Depois valida:
- a primeira publicação do K funciona normalmente;
- a reescrita do mesmo K é aceita como reuse/idempotência;
- a publicação de um segundo K diferente é bloqueada;
- o primeiro K continua sendo o único vetor K ativo no ledger;
- o segundo K não pode ser lido porque não foi publicado.

Foco do teste:
validar a regra de que cada DID do emissor pode ter
apenas um vetor K ativo no ledger.
*/
/* eslint-disable no-console */
const fs = require("fs");
const path = require("path");
const { IndyAgent } = require(path.join(__dirname, "..", "..", "index.node"));

function rmIfExists(walletDbPath) {
  const sidecar = `${walletDbPath}.kdf.json`;
  try { fs.unlinkSync(walletDbPath); } catch (_) {}
  try { fs.unlinkSync(sidecar); } catch (_) {}
  try { fs.unlinkSync(`${sidecar}.tmp`); } catch (_) {}
  try { fs.unlinkSync(`${walletDbPath}-shm`); } catch (_) {}
  try { fs.unlinkSync(`${walletDbPath}-wal`); } catch (_) {}
}

function mustEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Env ${name} não definida.`);
  return v;
}

function safeJsonParse(s, label = "json") {
  try {
    return JSON.parse(s);
  } catch (e) {
    throw new Error(`Falha parse ${label}: ${e.message}\nConteúdo: ${String(s).slice(0, 500)}`);
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

(async () => {
  const GENESIS_FILE = mustEnv("GENESIS_FILE");
  const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET_WALLET = String(process.env.RESET_WALLET || "0") === "1";
  const TRUSTEE_SEED = process.env.TRUSTEE_SEED || "000000000000000000000000Trustee1";
  const TRUSTEE_DID = process.env.TRUSTEE_DID || "V4SGRU86Z58d6TV7PBUe6f";

  const walletsDir = path.join(__dirname, "..", "wallets");
  fs.mkdirSync(walletsDir, { recursive: true });

  const issuerWalletPath = path.join(walletsDir, "issuer_revocation_single_k_12.db");
  if (RESET_WALLET) rmIfExists(issuerWalletPath);

  const issuer = new IndyAgent();

  try {
    console.log("🚀 TESTE REVOGAÇÃO 12: um único vetor K por DID do emissor");

    await issuer.walletCreate(issuerWalletPath, WALLET_PASS);
    await issuer.walletOpen(issuerWalletPath, WALLET_PASS);
    await issuer.connectNetwork(GENESIS_FILE);
    await issuer.importDidFromSeed(TRUSTEE_SEED);

    const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
    await issuer.registerDidOnLedger(
      GENESIS_FILE,
      TRUSTEE_DID,
      issuerDid,
      issuerVerkey,
      "ENDORSER"
    );

    const firstKVectorId = `k-vector-first-${Date.now()}`;
    const secondKVectorId = `k-vector-second-${Date.now()}`;

    console.log("1) Criando e publicando o primeiro K...");
    const setup1 = safeJsonParse(
      await issuer.revocationSetupCreateK(issuerDid, firstKVectorId),
      "setup_first_k"
    );
    const write1 = safeJsonParse(
      await issuer.revocationWriteKVectorOnLedger(
        GENESIS_FILE,
        issuerDid,
        JSON.stringify(setup1.k_vector)
      ),
      "write_first_k"
    );
    assert(write1.ok === true, "primeira escrita do K deveria funcionar");
    assert(write1.reused_existing === false, "primeira escrita não deveria ser reuse");
    assert(write1.k_vector_id === firstKVectorId, "primeira escrita retornou k_vector_id errado");

    console.log("2) Repetindo a escrita do mesmo K (idempotência segura)...");
    const writeSame = safeJsonParse(
      await issuer.revocationWriteKVectorOnLedger(
        GENESIS_FILE,
        issuerDid,
        JSON.stringify(setup1.k_vector)
      ),
      "write_same_k"
    );
    assert(writeSame.ok === true, "reescrita idempotente do mesmo K deveria funcionar");
    assert(writeSame.reused_existing === true, "reescrita do mesmo K deveria reutilizar o K ativo");
    assert(
      writeSame.ledger_anchor.k_vector_id === firstKVectorId,
      "reescrita do mesmo K deveria manter o k_vector_id original"
    );

    console.log("3) Tentando publicar um segundo K diferente para o mesmo DID...");
    const setup2 = safeJsonParse(
      await issuer.revocationSetupCreateK(issuerDid, secondKVectorId),
      "setup_second_k"
    );

    let blocked = false;
    try {
      await issuer.revocationWriteKVectorOnLedger(
        GENESIS_FILE,
        issuerDid,
        JSON.stringify(setup2.k_vector)
      );
    } catch (e) {
      blocked = true;
      const msg = e?.message || String(e);
      console.log(`✅ Segunda publicação bloqueada como esperado: ${msg}`);
      assert(
        /único vetor K|ja possui um vetor K ativo|já possui um vetor K ativo/i.test(msg),
        "mensagem de erro deveria indicar que já existe K ativo"
      );
    }
    assert(blocked === true, "a segunda publicação de K diferente deveria ser bloqueada");

    await sleep(350);

    console.log("4) Confirmando que o K original continua sendo o único lido do ledger...");
    const readFirst = safeJsonParse(
      await issuer.revocationReadKVectorFromLedger(GENESIS_FILE, issuerDid, firstKVectorId),
      "read_first_k"
    );
    assert(readFirst.ok === true, "leitura do primeiro K deveria continuar funcionando");
    assert(
      readFirst.k_vector.vector_hash === setup1.k_vector.vector_hash,
      "o primeiro K deveria continuar intacto após a tentativa bloqueada"
    );

    let secondReadFailed = false;
    try {
      await issuer.revocationReadKVectorFromLedger(GENESIS_FILE, issuerDid, secondKVectorId);
    } catch (e) {
      secondReadFailed = true;
      console.log(`✅ Segundo K não foi publicado no ledger: ${e?.message || e}`);
    }
    assert(secondReadFailed === true, "não deveria existir segundo K publicado para o emissor");

    console.log("✅ OK: TESTE REVOGAÇÃO 12 passou.");
  } finally {
    try { await issuer.walletClose(); } catch (_) {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 12:", e && e.stack ? e.stack : e);
  process.exit(1);
});
