/*
PARA RODAR:

WALLET_PASS="minha_senha_teste" RESET_WALLET=1 \
node teste-node/creddef/test_creddef_catalog_local_03_update_env_and_list.js
*/

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

function must(cond, msg) {
  if (!cond) throw new Error(msg);
}

(async () => {
  const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET_WALLET = process.env.RESET_WALLET === "1";

  const walletsDir = path.join(__dirname, "..", "wallets");
  fs.mkdirSync(walletsDir, { recursive: true });

  const walletPath = path.join(walletsDir, "creddef_cat_03.db");
  if (RESET_WALLET) rmIfExists(walletPath);

  const a = new IndyAgent();

  try {
    console.log("1) Criando wallet...");
    await a.walletCreate(walletPath, WALLET_PASS);

    console.log("2) Abrindo wallet...");
    await a.walletOpen(walletPath, WALLET_PASS);

    console.log("3) Criando template local (env=test)...");
    const issuerDid = "did:local:issuer";
    const schemaId = "schema:local:cpf-v1";
    const tag = "TAG1";
    const env = "test";

    const savedJson = await a.creddefSaveLocal(issuerDid, schemaId, tag, false, env);
    const saved = JSON.parse(savedJson);
    must(saved.id_local, "save não retornou id_local");

    console.log("4) List env=test -> deve conter 1...");
    const l1 = await a.creddefListLocal(null, "test", issuerDid, schemaId, tag);
    must(Array.isArray(l1) && l1.length === 1, "list env=test deveria retornar 1");

    console.log("5) Update env: test -> prod...");
    const updatedJson = await a.creddefSetEnvLocal(saved.id_local, "prod");
    const updated = JSON.parse(updatedJson);
    must(updated.env === "prod", "env não foi atualizado para prod");

    console.log("6) List env=test -> deve conter 0...");
    const l2 = await a.creddefListLocal(null, "test", issuerDid, schemaId, tag);
    must(Array.isArray(l2) && l2.length === 0, "list env=test deveria retornar 0");

    console.log("7) List env=prod -> deve conter 1...");
    const l3 = await a.creddefListLocal(null, "prod", issuerDid, schemaId, tag);
    must(Array.isArray(l3) && l3.length === 1, "list env=prod deveria retornar 1");

    console.log("✅ OK: TESTE CREDDEF CAT 03 passou.");
  } finally {
    try { await a.walletClose(); } catch (_) {}
  }
})().catch((e) => {
  console.error("❌ FALHA:", e?.message || e);
  console.error(e?.stack || "");
  process.exit(1);
});
