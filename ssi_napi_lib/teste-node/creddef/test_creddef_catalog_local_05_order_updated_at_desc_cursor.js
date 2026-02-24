/*
PARA RODAR:
WALLET_PASS="minha_senha_teste" RESET_WALLET=1 \
node teste-node/creddef/test_creddef_catalog_local_05_order_updated_at_desc_cursor.js
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

function must(cond, msg) {
  if (!cond) throw new Error(msg);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

(async () => {
  const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET_WALLET = process.env.RESET_WALLET === "1";

  const walletsDir = path.join(__dirname, "..", "wallets");
  fs.mkdirSync(walletsDir, { recursive: true });

  const walletPath = path.join(walletsDir, "creddef_cat_05.db");
  if (RESET_WALLET) rmIfExists(walletPath);

  const a = new IndyAgent();

  try {
    console.log("1) Criando wallet...");
    await a.walletCreate(walletPath, WALLET_PASS);

    console.log("2) Abrindo wallet...");
    await a.walletOpen(walletPath, WALLET_PASS);

    console.log("3) Criando 5 templates locais (env=test)...");
    const issuerDid = "did:local:issuer";
    const schemaId = "schema:local:cpf-v1";
    const env = "test";

    const locals = [];
    for (let i = 0; i < 5; i++) {
      const tag = `TAG_${i}`;
      const j = await a.creddefSaveLocal(issuerDid, schemaId, tag, false, env);
      locals.push(JSON.parse(j));
    }

    // Garante timestamps diferentes mesmo se now_ts for em segundos
    console.log("4) Forçando mudanças de updated_at com set_env_local...");
    await sleep(1100);
    const u1 = JSON.parse(await a.creddefSetEnvLocal(locals[0].id_local, "prod"));
    await sleep(1100);
    const u2 = JSON.parse(await a.creddefSetEnvLocal(locals[1].id_local, "prod"));

    must(u2.updated_at >= u1.updated_at, "updated_at não evoluiu como esperado");

    console.log("5) Listar por updated_at_desc com paginação limit=2...");
    let cursor = null;
    const got = [];

    for (let page = 0; page < 10; page++) {
      const outJson = await a.creddefListLocalViewCursorV2(
        "compact",
        cursor,
        2,
        null,     // on_ledger
        null,     // env (sem filtro)
        issuerDid,
        schemaId,
        null,     // tag
        "updated_at_desc"
      );

      const out = JSON.parse(outJson);
      must(out.ok === true, "ok=false");
      must(out.order_by === "updated_at_desc", "order_by inesperado");
      must(Array.isArray(out.items), "items não é array");

      // cursor composto deve vir como "ts|id_local"
      if (out.next_cursor) {
        must(String(out.next_cursor).includes("|"), "next_cursor não é composto (ts|id_local)");
      }

      for (const it of out.items) got.push(it.id_local);

      cursor = out.next_cursor;
      if (!cursor || out.items.length === 0) break;
    }

    must(got.length === 5, `esperado 5 itens, veio ${got.length}`);
    must(new Set(got).size === 5, "retornou duplicados");

    console.log("6) Sanity check: o primeiro item deve ser um dos mais recentemente atualizados...");
    const firstId = got[0];
    must(
      firstId === locals[1].id_local || firstId === locals[0].id_local,
      `primeiro item inesperado em updated_at_desc: ${firstId}`
    );

    console.log("✅ OK: TESTE CREDDEF CAT 05 passou.");
  } finally {
    try { await a.walletClose(); } catch (_) {}
  }
})().catch((e) => {
  console.error("❌ FALHA:", e?.message || e);
  console.error(e?.stack || "");
  process.exit(1);
});
