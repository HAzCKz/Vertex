/*
PARA RODAR (VON-NETWORK):
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
WALLET_PASS="minha_senha_teste" RESET_WALLET=1 GENESIS_FILE=./genesis.txn \
node teste-node/did/test_did_rotate_01_prepare_commit_von.js

Requisitos:
- von-network rodando e genesis.txn existente (GENESIS_FILE).
- Métodos novos:
  - rotateDidVerkeyPrepare(did, opts_json?)
  - rotateDidVerkeyCommit(genesis_file, did, opts_json)
- Índice did_vk (getDidByVerkey deve achar verkey antiga).
*/

/* eslint-disable no-console */
const fs = require("fs");
const path = require("path");

const { IndyAgent } = require(path.join(__dirname, "..", "..", "index.node"));

// -----------------------
// Helpers
// -----------------------
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

function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
}

async function retry(label, fn, attempts = 12, baseDelayMs = 800) {
    let lastErr;
    for (let i = 1; i <= attempts; i++) {
        try {
            return await fn();
        } catch (e) {
            lastErr = e;
            const wait = Math.min(baseDelayMs * i, 6000);
            console.log(`⏳ retry(${label}) ${i}/${attempts} falhou; aguardando ${wait}ms...`);
            await sleep(wait);
        }
    }
    throw lastErr;
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

// Resolve: na sua lib resolveDidOnLedger* recebe APENAS (did)
async function resolveDidJson(agent, _genesisFile, did) {
    try {
        return await agent.resolveDidOnLedgerV2(did);
    } catch (_) {
        return await agent.resolveDidOnLedger(did);
    }
}

function extractVerkeyFromResolve(raw) {
    try {
        const obj = JSON.parse(raw);

        // caso venha no formato {result:{data:"{...json...}"}}
        let data = obj?.result?.data;
        if (typeof data === "string") {
            try { data = JSON.parse(data); } catch (_) { }
        }

        return (
            obj?.verkey ||
            obj?.data?.verkey ||
            data?.verkey ||
            null
        );
    } catch (_) {
        return null;
    }
}

// -----------------------
// MAIN
// -----------------------
(async () => {
    const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
    const RESET_WALLET = String(process.env.RESET_WALLET || "0") === "1";

    const TRUSTEE_SEED = process.env.TRUSTEE_SEED || "000000000000000000000000Trustee1";
    const TRUSTEE_DID = process.env.TRUSTEE_DID || "V4SGRU86Z58d6TV7PBUe6f";
    const GENESIS_FILE = process.env.GENESIS_FILE || "./genesis.txn";

    must(fs.existsSync(GENESIS_FILE), `GENESIS_FILE não encontrado: ${GENESIS_FILE}`);

    const walletsDir = path.join(__dirname, "..", "wallets");
    fs.mkdirSync(walletsDir, { recursive: true });

    const trusteeWalletPath = path.join(walletsDir, "did_rotate_von_trustee.db");
    const holderWalletPath = path.join(walletsDir, "did_rotate_von_holder.db");

    if (RESET_WALLET) {
        console.log("🧹 RESET_WALLET=1: removendo wallet artifacts...");
        rmIfExists(trusteeWalletPath);
        rmIfExists(holderWalletPath);
    }

    const trustee = new IndyAgent();
    const holder = new IndyAgent();

    try {
        console.log("1) Criando wallets...");
        await trustee.walletCreate(trusteeWalletPath, WALLET_PASS);
        await holder.walletCreate(holderWalletPath, WALLET_PASS);

        console.log("2) Abrindo wallets...");
        await trustee.walletOpen(trusteeWalletPath, WALLET_PASS);
        await holder.walletOpen(holderWalletPath, WALLET_PASS);

        console.log("3) Conectando na rede (von-network)...");
        await trustee.connectNetwork(GENESIS_FILE);
        await holder.connectNetwork(GENESIS_FILE);

        console.log("4) Importando TRUSTEE DID no trustee wallet...");
        await trustee.importDidFromSeed(TRUSTEE_SEED);

        const trusteeDidJson = await trustee.getDid(TRUSTEE_DID);
        const trusteeDidObj = JSON.parse(trusteeDidJson);
        const trusteeVerkey = trusteeDidObj?.verkey;
        must(trusteeVerkey, "Não consegui obter verkey do TRUSTEE via getDid() no trustee wallet.");

        // console.log("5) Importando TRUSTEE DID também no holder wallet (para assinar o commit)...");
        // await holder.importDidFromSeed(TRUSTEE_SEED);

        console.log("6) Criando DID do holder...");
        const [holderDid, holderVerkey] = await holder.createOwnDid();
        must(holderDid && holderVerkey, "createOwnDid não retornou did/verkey.");

        console.log("7) Registrando DID do holder no ledger via TRUSTEE...");
        await tryRegisterDid(trustee, GENESIS_FILE, TRUSTEE_DID, holderDid, holderVerkey, null);

        console.log("8) Aguardando consistência do ledger após NYM inicial...");
        await sleep(2500);

        console.log("9) Resolvendo DID no ledger para validar verkey inicial...");
        const raw0 = await retry("resolve0", () => resolveDidJson(holder, GENESIS_FILE, holderDid), 12, 800);
        const ledgerVk0 = extractVerkeyFromResolve(raw0);
        must(ledgerVk0, `Não consegui extrair verkey do resolve. raw=${raw0}`);
        must(
            ledgerVk0.includes(holderVerkey.slice(0, 10)),
            `Ledger verkey inicial inesperada. ledgerVk0=${ledgerVk0} holderVerkey=${holderVerkey}`
        );

        // ------------------------------------------------------------
        // ROTATE PREPARE (holder)
        // ------------------------------------------------------------
        console.log("10) rotateDidVerkeyPrepare (holder)...");
        const prepOutJson = await holder.rotateDidVerkeyPrepare(
            holderDid,
            JSON.stringify({ reason: "scheduled", keepOldKeys: true })
        );

        const prepOut = JSON.parse(prepOutJson);
        must(prepOut.ok === true, "prepare não retornou ok=true");
        const pendingVerkey = prepOut.pendingVerkey;
        must(pendingVerkey && typeof pendingVerkey === "string", "prepare não retornou pendingVerkey");

        console.log("   currentVerkey:", prepOut.currentVerkey);
        console.log("   pendingVerkey:", pendingVerkey);

        console.log("11) Validando did_vk para pendingVerkey (getDidByVerkey)...");
        const byPendingJson = await holder.getDidByVerkey(pendingVerkey);
        const byPending = JSON.parse(byPendingJson);
        must(byPending.did === holderDid, "getDidByVerkey(pending) não retornou o DID correto");

        // ------------------------------------------------------------
        // ROTATE COMMIT (holder assina como TRUSTEE) — force=true porque isPublic=false
        // ------------------------------------------------------------
        console.log("12) rotateDidVerkeyCommit (holder -> ledger), assinando como o PRÓPRIO DID (owner)...");
        const commitOutJson = await holder.rotateDidVerkeyCommit(
            GENESIS_FILE,
            holderDid,
            JSON.stringify({
                submitterDid: holderDid, // ✅ owner
                role: null,
                force: true
            })
        );

        const commitOut = JSON.parse(commitOutJson);
        must(commitOut.ok === true, "commit não retornou ok=true");
        const newVerkey = commitOut.newVerkey;
        const oldVerkey = commitOut.oldVerkey;
        must(newVerkey && oldVerkey, "commit não retornou oldVerkey/newVerkey");
        must(newVerkey === pendingVerkey, "newVerkey != pendingVerkey (inconsistência)");

        console.log("   oldVerkey:", oldVerkey);
        console.log("   newVerkey:", newVerkey);

        console.log("13) Aguardando consistência do ledger após rotação...");
        await sleep(3000);

        console.log("14) Resolvendo no ledger (deve refletir newVerkey)...");
        const raw1 = await retry("resolve1", () => resolveDidJson(holder, GENESIS_FILE, holderDid), 14, 900);
        const ledgerVk1 = extractVerkeyFromResolve(raw1);
        must(ledgerVk1, `Não consegui extrair verkey do resolve pós-rotação. raw=${raw1}`);
        must(
            ledgerVk1.includes(newVerkey.slice(0, 10)),
            `Ledger ainda não refletiu rotação. ledgerVk1=${ledgerVk1} newVerkey=${newVerkey}`
        );

        console.log("15) Validando que holder getDid retorna verkey nova...");
        const holderDidJson2 = await holder.getDid(holderDid);
        const holderDidObj2 = JSON.parse(holderDidJson2);
        must(holderDidObj2?.verkey === newVerkey, "getDid(holderDid) não atualizou para verkey nova");

        console.log("16) Validando did_vk para verkey antiga (getDidByVerkey)...");
        const byOldJson = await holder.getDidByVerkey(oldVerkey);
        const byOld = JSON.parse(byOldJson);
        must(byOld.did === holderDid, "getDidByVerkey(old) não retornou DID correto");

        console.log("✅ OK: rotação de verkey passou (von-network) — prepare+commit + ledger + did_vk.");
    } finally {
        try { await trustee.walletClose(); } catch (_) { }
        try { await holder.walletClose(); } catch (_) { }
    }
})().catch((e) => {
    console.error("❌ FALHA NO TESTE:", e?.message || e);
    console.error(e?.stack || "");
    process.exit(1);
});
