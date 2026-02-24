/*
PARA RODAR ESTE TESTE (von-network local):
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
WALLET_PASS="minha_senha_teste" GENESIS_FILE=./genesis.txn \
ITER=20 \
node teste-node/time/test_time_01_von_network_ops.js
*/

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const { IndyAgent } = require(path.join(__dirname, "..", "..", "index.node"));

// -------------------------
// Helpers FS / ENV
// -------------------------
function rmIfExists(walletDbPath) {
    const sidecar = `${walletDbPath}.kdf.json`;
    try { fs.unlinkSync(walletDbPath); } catch (_) { }
    try { fs.unlinkSync(sidecar); } catch (_) { }
    try { fs.unlinkSync(`${sidecar}.tmp`); } catch (_) { }
    try { fs.unlinkSync(`${walletDbPath}-shm`); } catch (_) { }
    try { fs.unlinkSync(`${walletDbPath}-wal`); } catch (_) { }
}

function mustEnv(name) {
    const v = process.env[name];
    if (!v) throw new Error(`Env ${name} não definida.`);
    return v;
}

function mkdirp(p) {
    fs.mkdirSync(p, { recursive: true });
}

function writeFileAtomic(filePath, data) {
    mkdirp(path.dirname(filePath));
    fs.writeFileSync(filePath, data, "utf8");
}

function writeJson(filePath, obj) {
    writeFileAtomic(filePath, JSON.stringify(obj, null, 2));
}

function nowNs() {
    return process.hrtime.bigint();
}

function nsToMs(nsBigint) {
    return Number(nsBigint) / 1e6;
}

function percentile(sortedArr, p) {
    if (!sortedArr.length) return null;
    const idx = Math.ceil((p / 100) * sortedArr.length) - 1;
    return sortedArr[Math.max(0, Math.min(sortedArr.length - 1, idx))];
}

function summarize(valuesMs) {
    const arr = [...valuesMs].sort((a, b) => a - b);
    const sum = arr.reduce((a, b) => a + b, 0);
    const avg = arr.length ? sum / arr.length : 0;
    return {
        n: arr.length,
        avg_ms: avg,
        min_ms: arr[0] ?? null,
        max_ms: arr[arr.length - 1] ?? null,
        p50_ms: percentile(arr, 50),
        p95_ms: percentile(arr, 95),
    };
}

function padRight(s, n) {
    s = String(s);
    return s.length >= n ? s : s + " ".repeat(n - s.length);
}

function fmt(ms) {
    if (ms === null || ms === undefined) return "-";
    return `${ms.toFixed(2)} ms`;
}

// runKey (string) -> número 0..mod-1 para schema_version
function numericSuffixFromString(s, mod = 1000000) {
    let h = 0;
    for (let i = 0; i < s.length; i++) {
        h = (h * 31 + s.charCodeAt(i)) >>> 0;
    }
    return h % mod;
}

// -------------------------
// Timer Runner
// -------------------------
async function timed(stats, label, fn) {
    const t0 = nowNs();
    const out = await fn();
    const dt = nsToMs(nowNs() - t0);
    if (!stats[label]) stats[label] = [];
    stats[label].push(dt);
    return out;
}

function hasMethod(obj, name) {
    return obj && typeof obj[name] === "function";
}

// -------------------------
// Ledger: register DID (ignore if exists)
// -------------------------
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

// -------------------------
// MAIN
// -------------------------
(async () => {
    const GENESIS_FILE = mustEnv("GENESIS_FILE");
    const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
    const TRUSTEE_SEED = mustEnv("TRUSTEE_SEED");
    const TRUSTEE_DID = mustEnv("TRUSTEE_DID");

    const ITER = Number(process.env.ITER || "3");
    if (!Number.isFinite(ITER) || ITER < 1) throw new Error("ITER inválido.");

    const walletsDir = path.join(__dirname, "..", "wallets");
    const outDir = path.join(__dirname, "out");
    mkdirp(walletsDir);
    mkdirp(outDir);

    // Identificador único por processo/instância (para rodar em paralelo)
    const RUN_TAG = process.env.RUN_TAG || "single";
    const runKey =
        `${Date.now()}_${process.pid}_${RUN_TAG}_` +
        crypto.randomBytes(4).toString("hex");

    // Número derivado do runKey para schema_version (X.Y.Z numérico)
    const runVerNum = numericSuffixFromString(runKey, 1000000);

    const reportFile = path.join(outDir, `time_report_${runKey}.json`);
    const stats = {};

    console.log("============================================================");
    console.log("⏱️  TESTE TIME 01: benchmark de operações SSI (Von Network)");
    console.log("Config:", { GENESIS_FILE, ITER, walletPass: "***", RUN_TAG, runKey });
    console.log("============================================================");

    for (let i = 1; i <= ITER; i++) {
        console.log(`\n------------------ ITERAÇÃO ${i}/${ITER} ------------------`);

        const issuerWalletPath = path.join(walletsDir, `time_issuer_${runKey}_${i}.db`);
        const holderWalletPath = path.join(walletsDir, `time_holder_${runKey}_${i}.db`);
        rmIfExists(issuerWalletPath);
        rmIfExists(holderWalletPath);

        const issuer = new IndyAgent();
        const holder = new IndyAgent();

        try {
            await timed(stats, "walletCreate(issuer)", async () =>
                issuer.walletCreate(issuerWalletPath, WALLET_PASS)
            );
            await timed(stats, "walletCreate(holder)", async () =>
                holder.walletCreate(holderWalletPath, WALLET_PASS)
            );

            await timed(stats, "walletOpen(issuer)", async () =>
                issuer.walletOpen(issuerWalletPath, WALLET_PASS)
            );
            await timed(stats, "walletOpen(holder)", async () =>
                holder.walletOpen(holderWalletPath, WALLET_PASS)
            );

            await timed(stats, "connectNetwork(issuer)", async () =>
                issuer.connectNetwork(GENESIS_FILE)
            );
            await timed(stats, "connectNetwork(holder)", async () =>
                holder.connectNetwork(GENESIS_FILE)
            );

            await timed(stats, "importDidFromSeed(TRUSTEE)", async () =>
                issuer.importDidFromSeed(TRUSTEE_SEED)
            );

            const [issuerDid, issuerVerkey] = await timed(stats, "createOwnDid(issuer)", async () =>
                issuer.createOwnDid()
            );
            const [holderDid, holderVerkey] = await timed(stats, "createOwnDid(holder)", async () =>
                holder.createOwnDid()
            );

            await timed(stats, "registerDidOnLedger(issuer)", async () =>
                tryRegisterDid(issuer, GENESIS_FILE, TRUSTEE_DID, issuerDid, issuerVerkey, "ENDORSER")
            );


            // await timed(stats, "resolveDidOnLedger(issuer)", async () =>
            //     issuer.resolveDidOnLedger(issuerDid) // NAPI: resolve_did_on_ledger
            // );

            await timed(stats, "registerDidOnLedger(holder)", async () =>
                tryRegisterDid(issuer, GENESIS_FILE, TRUSTEE_DID, holderDid, holderVerkey, null)
            );

            // await timed(stats, "resolveDidOnLedger(holder)", async () =>
            //     issuer.resolveDidOnLedger(holderDid) // NAPI: resolve_did_on_ledger
            // );

            // ✅ schema_version válido: X.Y.Z (numérico)
            const schemaVer = `1.0.${runVerNum}`;
            const schemaName = `cpf_time_${runKey}_${i}`;

            const schemaId = await timed(stats, "createAndRegisterSchema(CPF)", async () =>
                issuer.createAndRegisterSchema(
                    GENESIS_FILE,
                    issuerDid,
                    schemaName,
                    schemaVer,
                    ["nome", "cpf", "idade"]
                )
            );

            const credDefTag = `TAG_CPF_TIME_${runKey}_${i}_${Date.now()}`;
            const credDefId = await timed(stats, "createAndRegisterCredDef(CPF)", async () =>
                issuer.createAndRegisterCredDef(GENESIS_FILE, issuerDid, schemaId, credDefTag)
            );

            const schemaCpfJson = await timed(stats, "fetchSchemaFromLedger(CPF)", async () =>
                holder.fetchSchemaFromLedger(GENESIS_FILE, schemaId)
            );
            const credDefCpfJson = await timed(stats, "fetchCredDefFromLedger(CPF)", async () =>
                holder.fetchCredDefFromLedger(GENESIS_FILE, credDefId)
            );

            await timed(stats, "createLinkSecret(default)", async () => {
                try { await holder.createLinkSecret("default"); } catch (_) { }
            });

            const offerId = `offer-time-${runKey}-${i}-${Date.now()}`;
            const offerJson = await timed(stats, "createCredentialOffer(CPF)", async () =>
                issuer.createCredentialOffer(credDefId, offerId)
            );

            const offerObj = JSON.parse(offerJson);
            const reqMetaId = offerObj?.nonce;
            if (!reqMetaId) throw new Error("Offer sem nonce (reqMetaId).");

            const reqJson = await timed(stats, "createCredentialRequest(CPF)", async () =>
                holder.createCredentialRequest("default", holderDid, credDefCpfJson, offerJson)
            );

            const valuesCpf = { nome: "Amarildo Dias", cpf: "123.456.789-09", idade: "35" };
            const credJson = await timed(stats, "createCredential(CPF)", async () =>
                issuer.createCredential(credDefId, offerJson, reqJson, JSON.stringify(valuesCpf))
            );

            const credLocalId = `cred-cpf-time-${runKey}-${i}`;
            await timed(stats, "storeCredential(CPF)", async () =>
                holder.storeCredential(credLocalId, credJson, reqMetaId, credDefCpfJson, null)
            );

            const presReq = {
                nonce: String(Date.now()),
                name: "proof-time-zkp18",
                version: "1.0",
                requested_attributes: {
                    attr_nome: { name: "nome", restrictions: [{ cred_def_id: credDefId }] },
                    attr_cpf: { name: "cpf", restrictions: [{ cred_def_id: credDefId }] },
                },
                requested_predicates: {
                    pred_idade_ge_18: {
                        name: "idade",
                        p_type: ">=",
                        p_value: 18,
                        restrictions: [{ cred_def_id: credDefId }],
                    },
                },
            };

            const requestedCreds = {
                requested_attributes: {
                    attr_nome: { cred_id: credLocalId, revealed: true },
                    attr_cpf: { cred_id: credLocalId, revealed: true },
                },
                requested_predicates: {
                    pred_idade_ge_18: { cred_id: credLocalId },
                },
            };

            const schemasMap = JSON.stringify({ [schemaId]: JSON.parse(schemaCpfJson) });
            const credDefsMap = JSON.stringify({ [credDefId]: JSON.parse(credDefCpfJson) });

            const presJson = await timed(stats, "createPresentation(ZKP18)", async () =>
                holder.createPresentation(
                    JSON.stringify(presReq),
                    JSON.stringify(requestedCreds),
                    schemasMap,
                    credDefsMap
                )
            );

            const ok = await timed(stats, "verifyPresentation(ZKP18)", async () =>
                issuer.verifyPresentation(
                    JSON.stringify(presReq),
                    presJson,
                    schemasMap,
                    credDefsMap
                )
            );
            if (!ok) throw new Error("verifyPresentation retornou false.");

            if (hasMethod(issuer, "envelopePackAuthcrypt") && hasMethod(holder, "envelopeUnpackAuto")) {
                const envJson = await timed(stats, "envelopePackAuthcrypt(offer)", async () =>
                    issuer.envelopePackAuthcrypt(
                        issuerDid,
                        holderVerkey,
                        "bench_offer",
                        null,
                        offerJson,
                        null,
                        JSON.stringify({ iter: i })
                    )
                );

                await timed(stats, "envelopeUnpackAuto(offer)", async () =>
                    holder.envelopeUnpackAuto(holderDid, envJson)
                );
            } else {
                if (!stats["_note_no_envelope"]) {
                    stats["_note_no_envelope"] = ["Lib não expõe envelopePackAuthcrypt/envelopeUnpackAuto"];
                }
            }

            console.log("✅ Iteração OK.");
        } finally {
            try { await issuer.walletClose(); } catch (_) { }
            try { await holder.walletClose(); } catch (_) { }

            // 🧹 Limpeza automática (evita encher HD em execuções longas/paralelas)
            rmIfExists(issuerWalletPath);
            rmIfExists(holderWalletPath);
        }
    }

    const summary = {};
    for (const [label, arr] of Object.entries(stats)) {
        if (label.startsWith("_note_")) continue;
        if (!Array.isArray(arr) || !arr.length) continue;
        summary[label] = summarize(arr);
    }

    const labels = Object.keys(summary);
    const col1 = Math.max(28, ...labels.map((s) => s.length));

    console.log("\n============================================================");
    console.log("📊 RESULTADOS (ms) — média / p95 / min / max  (N=" + ITER + ")");
    console.log("============================================================");
    for (const label of labels) {
        const s = summary[label];
        console.log(
            padRight(label, col1) +
            " | avg " + padRight(fmt(s.avg_ms), 12) +
            " | p95 " + padRight(fmt(s.p95_ms), 12) +
            " | min " + padRight(fmt(s.min_ms), 12) +
            " | max " + padRight(fmt(s.max_ms), 12)
        );
    }

    const report = {
        run_id: runKey,
        created_at: new Date().toISOString(),
        env: { GENESIS_FILE: process.env.GENESIS_FILE, ITER, RUN_TAG },
        notes: {
            envelope_methods:
                stats["_note_no_envelope"]?.[0] ||
                "envelopePackAuthcrypt/envelopeUnpackAuto medidos quando disponíveis",
        },
        raw_ms: Object.fromEntries(
            Object.entries(stats).filter(([k, v]) => !k.startsWith("_note_") && Array.isArray(v))
        ),
        summary,
    };

    writeJson(reportFile, report);
    console.log("\n📄 Relatório salvo em:", reportFile);
    console.log("============================================================");
})().catch((e) => {
    console.error("FALHA NO TESTE:", e?.message || e);
    console.error(e?.stack || "");
    process.exit(1);
});