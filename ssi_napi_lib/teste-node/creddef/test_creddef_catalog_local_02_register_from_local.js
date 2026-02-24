/*
PARA RODAR ESTE TESTE:

TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./genesis.txn \
RESET_WALLET=1 \
node teste-node/creddef/test_creddef_catalog_local_02_register_from_local.js

Observações:
- Este teste exige ledger disponível (von-network / pool rodando) e genesis.txn válido.
- Se sua lib exportar snake_case ao invés de camelCase, ajuste os nomes.
*/

function rmIfExists(p) {
    try {
        if (fs.existsSync(p)) fs.unlinkSync(p);
    } catch (e) {
        console.warn("⚠️  não consegui remover:", p, "-", e.message);
    }
}

function resetWalletArtifacts(walletPath) {
    const dir = path.dirname(walletPath);
    const base = path.basename(walletPath); // ex: test_wallet_creddef_cat_issuer.db

    // 1) remove alvos diretos (inclui sqlite wal/shm/journal)
    const direct = [
        walletPath,
        walletPath + "-wal",
        walletPath + "-shm",
        walletPath + "-journal",
        walletPath + ".sidecar.json",
        walletPath + ".passbackup.json",
        walletPath + ".sidecar",
        walletPath + ".backup.json",
        walletPath + ".bak",
    ];
    direct.forEach(rmIfExists);

    // 2) remove qualquer arquivo no diretório que comece com o basename
    //    (pega variações que você não antecipou)
    try {
        for (const name of fs.readdirSync(dir)) {
            if (name === base) continue;
            if (name.startsWith(base)) {
                rmIfExists(path.join(dir, name));
            }
        }
    } catch (e) {
        console.warn("⚠️  não consegui varrer diretório:", dir, "-", e.message);
    }

    // 3) diagnóstico: listar o que sobrou relacionado
    const leftovers = [];
    try {
        for (const name of fs.readdirSync(dir)) {
            if (name === base || name.startsWith(base)) leftovers.push(name);
        }
    } catch { }

    if (leftovers.length) {
        console.warn("⚠️  Ainda restaram artefatos da wallet:", leftovers);
    }
}

const path = require("path");
const fs = require("fs");

const addon = require("../../index.node"); // ajuste se necessário

function must(cond, msg) {
    if (!cond) throw new Error(msg);
}

async function main() {
    const TRUSTEE_SEED = process.env.TRUSTEE_SEED || "000000000000000000000000Trustee1";
    const TRUSTEE_DID = process.env.TRUSTEE_DID || "V4SGRU86Z58d6TV7PBUe6f";
    const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
    const GENESIS_FILE = process.env.GENESIS_FILE || "./genesis.txn";
    const RESET_WALLET = process.env.RESET_WALLET === "1";

    const genesisAbs = path.resolve(GENESIS_FILE);
    must(fs.existsSync(genesisAbs), `GENESIS_FILE não encontrado: ${genesisAbs}`);

    const issuerWallet = path.resolve("./teste-node/wallets/test_wallet_creddef_cat_issuer.db");

    if (RESET_WALLET) {
        console.log("🧹 RESET_WALLET=1: removendo wallet + sidecar...");
        resetWalletArtifacts(issuerWallet);
    }

    const agent = new addon.IndyAgent();

    console.log("1) Criando wallet do issuer...");
    await agent.walletCreate(issuerWallet, WALLET_PASS);

    console.log("2) Abrindo wallet do issuer...");
    await agent.walletOpen(issuerWallet, WALLET_PASS);

    console.log("3) Conectando na rede...");
    // Se o seu método se chama connectPool, ajuste aqui.
    await agent.connectNetwork(genesisAbs);

    console.log("4) Importando Trustee DID no issuer...");
    await agent.importDidFromSeed(TRUSTEE_SEED);

    console.log("5) Issuer criando DID (createOwnDid)...");
    const [issuerDid, issuerVerkey] = await agent.createOwnDid();

    must(issuerDid && typeof issuerDid === "string", "createOwnDid não retornou issuerDid.");
    must(issuerVerkey && typeof issuerVerkey === "string", "createOwnDid não retornou issuerVerkey.");

    console.log("   issuerDid:", issuerDid);
    console.log("   issuerVerkey:", issuerVerkey);

    console.log("6) Registrando DID do issuer no ledger via Trustee...");

    async function tryRegisterDid(agent, GENESIS_FILE, submitterDid, did, verkey, role) {
        try {
            await agent.registerDidOnLedger(GENESIS_FILE, submitterDid, did, verkey, role);
        } catch (e) {
            const msg = e?.message || String(e);
            if (/already exists|exists|DID.*exist|NYM.*exist|Ledger/i.test(msg)) {
                console.log(`ℹ️ DID já estava no ledger, seguindo: ${did}`);
                return;
            }
            throw e;
        }
    }

    await tryRegisterDid(agent, genesisAbs, TRUSTEE_DID, issuerDid, issuerVerkey, "ENDORSER");


    console.log("7) Criando Schema no ledger...");
    const schemaName = "SCHEMA_CREDDEF_CAT_02";
    const schemaVersion = `1.0.${Date.now()}`;
    const attrs = ["cpf", "nome", "idade"];

    const schemaId = await agent.createAndRegisterSchema(
        genesisAbs,
        issuerDid,
        schemaName,
        schemaVersion,
        attrs
    );

    must(schemaId && typeof schemaId === "string", "createAndRegisterSchema não retornou schemaId.");
    console.log("   schemaId:", schemaId);

    console.log("8) Criando template local do CredDef (catálogo local)...");
    const tag = "TAG1";
    const envLabel = "test";
    const supportRevocation = false;

    // Esta função salva a credDef local e no ledger porque schamaId existe no ledger
    const savedJson = await agent.creddefSaveLocal(
        issuerDid,
        schemaId,
        tag,
        supportRevocation,
        envLabel
    );

    const saved = JSON.parse(savedJson);
    must(saved.id_local, "creddefSaveLocal não retornou id_local.");
    console.log("   id_local:", saved.id_local);

    console.log("9) Registrando CredDef no ledger a partir do template local...");
    // creddef_register_from_local(genesis_path, id_local, issuer_did_opt)
    // issuer_did_opt pode ser null (usa rec.issuer_did), mas vou passar explicitamente.
    const out = await agent.creddefRegisterFromLocal(genesisAbs, saved.id_local, issuerDid);

    must(out && out.ok === true, "creddefRegisterFromLocal retornou ok=false.");
    must(out.credDefId && typeof out.credDefId === "string", "creddefRegisterFromLocal não retornou credDefId.");

    console.log("   credDefId:", out.credDefId);

    const updated = JSON.parse(out.json);
    must(updated.on_ledger === true, "Record local não foi atualizado: on_ledger != true.");
    must(updated.cred_def_id === out.credDefId, "Record local não contém cred_def_id igual ao credDefId retornado.");
    must(updated.env === "prod", "Record local não foi promovido para env='prod'.");

    console.log("10) (Opcional) Fetch CredDef do ledger para sanity check...");

    // assinatura correta no seu binding: (GENESIS_FILE, credDefId)
    const fetched = await agent.fetchCredDefFromLedger(genesisAbs, out.credDefId);

    if (typeof fetched === "string") {
        const fv = JSON.parse(fetched);
        must(fv && (fv.cred_def || fv.data || fv.result), "Fetch creddef do ledger retornou vazio/inesperado.");
    } else {
        must(fetched, "Fetch creddef do ledger retornou vazio.");
    }

    console.log("✅ OK: TESTE CREDDEF CAT 02 passou.");

    console.log("11) Fechando wallet...");
    await agent.walletClose();
}

main().catch((e) => {
    console.error("❌ FALHA:", e);
    process.exit(1);
});
