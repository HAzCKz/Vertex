/*
PARA RODAR:
WALLET_PASS="minha_senha_teste" RESET_WALLET=1 \
node teste-node/creddef/test_creddef_catalog_local_04_list_cursor_and_lookup.js
*/

/* eslint-disable no-console */
const fs = require("fs");
const path = require("path");
const { IndyAgent } = require(path.join(__dirname, "..", "..", "index.node"));

function rmIfExists(walletDbPath) {
    const sidecar = `${walletDbPath}.kdf.json`;
    try { fs.unlinkSync(walletDbPath); } catch (_) { }
    try { fs.unlinkSync(sidecar); } catch (_) { }
    try { fs.unlinkSync(`${sidecar}.tmp`); } catch (_) { }
    try { fs.unlinkSync(`${walletDbPath}-shm`); } catch (_) { }
    try { fs.unlinkSync(`${walletDbPath}-wal`); } catch (_) { }
}

function must(cond, msg) {
    if (!cond) throw new Error(msg);
}

(async () => {
    const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
    const RESET_WALLET = process.env.RESET_WALLET === "1";

    const walletsDir = path.join(__dirname, "..", "wallets");
    fs.mkdirSync(walletsDir, { recursive: true });

    const walletPath = path.join(walletsDir, "creddef_cat_04.db");
    if (RESET_WALLET) rmIfExists(walletPath);

    const a = new IndyAgent();

    try {
        console.log("1) Criando wallet...");
        await a.walletCreate(walletPath, WALLET_PASS);

        console.log("2) Abrindo wallet...");
        await a.walletOpen(walletPath, WALLET_PASS);

        // cria 5 templates (env=test) com tags diferentes
        console.log("3) Criando 5 templates locais...");
        const issuerDid = "did:local:issuer";
        const schemaId = "schema:local:cpf-v1";
        const env = "test";

        const locals = [];
        for (let i = 0; i < 5; i++) {
            const tag = `TAG_${i}`;
            const j = await a.creddefSaveLocal(issuerDid, schemaId, tag, false, env);
            locals.push(JSON.parse(j));
        }

        // Marca um deles como on_ledger com cred_def_id fake (offline)
        console.log("4) Mark on_ledger em 1 registro...");
        const target = locals[2];
        const fakeCredDefId = `did:fake:3:CL:99:TAG_X`;
        const upd = JSON.parse(await a.creddefMarkOnLedgerLocal(target.id_local, fakeCredDefId));
        must(upd.on_ledger === true, "mark_on_ledger não setou on_ledger=true");
        must(upd.cred_def_id === fakeCredDefId, "mark_on_ledger não setou cred_def_id");

        console.log("5) Lookup por cred_def_id...");
        const foundJson = await a.creddefGetLocalByCredDefId(fakeCredDefId);
        const found = JSON.parse(foundJson);
        must(found.id_local === target.id_local, "lookup retornou id_local errado");

        console.log("6) Paginação (compact) limit=2 sem filtro env -> deve dar 5...");
        {
            let cursor = null;
            const all = [];

            for (let page = 0; page < 10; page++) {
                const outJson = await a.creddefListLocalViewCursor(
                    "compact",
                    cursor,
                    2,
                    null,
                    null,        // <<< sem env
                    issuerDid,
                    schemaId,
                    null
                );

                const out = JSON.parse(outJson);
                must(out.ok === true, "list_local_view_cursor ok=false");
                must(Array.isArray(out.items), "items não é array");

                out.items.forEach((it) => all.push(it.id_local));
                cursor = out.next_cursor;

                if (!cursor || out.items.length === 0) break;
            }

            must(all.length === 5, `esperado 5 itens paginados (sem env), veio ${all.length}`);
            must(new Set(all).size === 5, "paginação (sem env) retornou duplicados");
        }

        console.log("7) Paginação (compact) limit=2 com env=test -> deve dar 4...");
        {
            let cursor = null;
            const all = [];

            for (let page = 0; page < 10; page++) {
                const outJson = await a.creddefListLocalViewCursor(
                    "compact",
                    cursor,
                    2,
                    null,
                    "test",      // <<< agora filtra env=test
                    issuerDid,
                    schemaId,
                    null
                );

                const out = JSON.parse(outJson);
                must(out.ok === true, "list_local_view_cursor ok=false");
                must(Array.isArray(out.items), "items não é array");

                out.items.forEach((it) => all.push(it.id_local));
                cursor = out.next_cursor;

                if (!cursor || out.items.length === 0) break;
            }

            must(all.length === 4, `esperado 4 itens paginados (env=test), veio ${all.length}`);
            must(new Set(all).size === 4, "paginação (env=test) retornou duplicados");
        }

        console.log("✅ OK: TESTE CREDDEF CAT 04 passou.");
    } finally {
        try { await a.walletClose(); } catch (_) { }
    }
})().catch((e) => {
    console.error("❌ FALHA:", e?.message || e);
    console.error(e?.stack || "");
    process.exit(1);
});
