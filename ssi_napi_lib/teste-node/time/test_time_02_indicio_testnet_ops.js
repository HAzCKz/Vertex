/*
PARA RODAR ESTE TESTE (INDICIO Testnet):
WALLET_PASS="minha_senha_teste" \
SUBMITTER_SEED="+0HGyElhOr/GuwUaDsyiTn926bFMrBUh" \
SUBMITTER_DID="7DffLFWsgrwbt7T1Ni9cmu" \
ITER=25 \
node teste-node/time/test_time_02_indicio_testnet_ops.js

O QUE ESTE TESTE FAZ:
- Baixa o genesis da Indicio (se não existir) em ./indicio_testnet.txn
- Usa o DID do SUBMITTER (ENDORSER/ISSUER) já existente na rede:
  - SUBMITTER_DID = 7DffLFWsgrwbt7T1Ni9cmu
  - Importa a seed do SUBMITTER na wallet do issuer (para assinar transações)
- Cria DIDs locais para Holder e Verifier e registra ambos no ledger como DIDs comuns (role null)
- Mede o tempo (ms) de:
  - walletCreate / walletOpen / connectNetwork / importDidFromSeed
  - createOwnDid / registerDidOnLedger (NYM)
  - createAndRegisterSchema / createAndRegisterCredDef
  - fetchSchemaFromLedger / fetchCredDefFromLedger
  - createLinkSecret
  - offer -> request -> issue -> store
  - proof request -> createPresentation -> verifyPresentation
  - (opcional) envelopePackAuthcrypt / envelopeUnpackAuto se existir na lib
- Roda ITER iterações e calcula média/p95/min/max
- Gera relatório JSON em teste-node/time/out
*/

const fs = require("fs");
const path = require("path");
const https = require("https");

const { IndyAgent } = require(path.join(__dirname, "..", "..", "index.node"));

// -------------------------
// Genesis (download)
// -------------------------
function downloadToFile(url, filePath) {
  return new Promise((resolve, reject) => {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const file = fs.createWriteStream(filePath);

    https
      .get(url, (res) => {
        if (res.statusCode !== 200) {
          file.close(() => {});
          try { fs.unlinkSync(filePath); } catch (_) {}
          return reject(new Error(`Falha ao baixar genesis. HTTP ${res.statusCode}`));
        }
        res.pipe(file);
        file.on("finish", () => file.close(resolve));
      })
      .on("error", (err) => {
        file.close(() => {});
        try { fs.unlinkSync(filePath); } catch (_) {}
        reject(err);
      });
  });
}

// -------------------------
// Helpers FS / ENV
// -------------------------
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
  const genesisUrl =
    "https://raw.githubusercontent.com/Indicio-tech/indicio-network/refs/heads/main/genesis_files/pool_transactions_testnet_genesis";
  const genesisFile = process.env.GENESIS_FILE || "./indicio_testnet.txn";

  // DADOS DO SUBMITTER (ENDORSER / ISSUER)
  const SUBMITTER_SEED = process.env.SUBMITTER_SEED || "+0HGyElhOr/GuwUaDsyiTn926bFMrBUh";
  const SUBMITTER_DID  = process.env.SUBMITTER_DID  || "7DffLFWsgrwbt7T1Ni9cmu";

  const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
  const ITER = Number(process.env.ITER || "10");
  if (!Number.isFinite(ITER) || ITER < 1) throw new Error("ITER inválido.");

  // garante genesis
  if (!fs.existsSync(genesisFile)) {
    console.log(`📥 Genesis não encontrado. Baixando da Indicio...`);
    await downloadToFile(genesisUrl, genesisFile);
    console.log(`✅ Genesis salvo em: ${genesisFile}`);
  } else {
    console.log(`📂 Genesis já existe: ${genesisFile}`);
  }

  const walletsDir = path.join(__dirname, "..", "wallets");
  const outDir = path.join(__dirname, "out");
  mkdirp(walletsDir);
  mkdirp(outDir);

  const runId = Date.now();
  const reportFile = path.join(outDir, `time_report_indicio_${runId}.json`);

  const stats = {};

  console.log("============================================================");
  console.log("⏱️  TESTE TIME 02: benchmark de operações SSI (INDICIO testnet)");
  console.log("Config:", {
    genesisFile,
    ITER,
    submitterDid: SUBMITTER_DID,
    walletPass: "***",
  });
  console.log("============================================================");

  for (let i = 1; i <= ITER; i++) {
    console.log(`\n------------------ ITERAÇÃO ${i}/${ITER} ------------------`);

    const issuerWalletPath = path.join(walletsDir, `time_indicio_issuer_${runId}_${i}.db`);
    const holderWalletPath = path.join(walletsDir, `time_indicio_holder_${runId}_${i}.db`);
    const verifierWalletPath = path.join(walletsDir, `time_indicio_verifier_${runId}_${i}.db`);
    rmIfExists(issuerWalletPath);
    rmIfExists(holderWalletPath);
    rmIfExists(verifierWalletPath);

    const issuer = new IndyAgent();
    const holder = new IndyAgent();
    const verifier = new IndyAgent();

    try {
      // 1) Wallet create/open
      await timed(stats, "walletCreate(issuer)", async () =>
        issuer.walletCreate(issuerWalletPath, WALLET_PASS)
      );
      await timed(stats, "walletCreate(holder)", async () =>
        holder.walletCreate(holderWalletPath, WALLET_PASS)
      );
      await timed(stats, "walletCreate(verifier)", async () =>
        verifier.walletCreate(verifierWalletPath, WALLET_PASS)
      );

      await timed(stats, "walletOpen(issuer)", async () =>
        issuer.walletOpen(issuerWalletPath, WALLET_PASS)
      );
      await timed(stats, "walletOpen(holder)", async () =>
        holder.walletOpen(holderWalletPath, WALLET_PASS)
      );
      await timed(stats, "walletOpen(verifier)", async () =>
        verifier.walletOpen(verifierWalletPath, WALLET_PASS)
      );

      // 2) Connect network (todos)
      await timed(stats, "connectNetwork(issuer)", async () =>
        issuer.connectNetwork(genesisFile)
      );
      await timed(stats, "connectNetwork(holder)", async () =>
        holder.connectNetwork(genesisFile)
      );
      await timed(stats, "connectNetwork(verifier)", async () =>
        verifier.connectNetwork(genesisFile)
      );

      // 3) Import seed do SUBMITTER na wallet do issuer (para assinar writes)
      await timed(stats, "importDidFromSeed(SUBMITTER)", async () =>
        issuer.importDidFromSeed(SUBMITTER_SEED)
      );

      // 4) DIDs do holder e verifier (locais) + registrar no ledger (DIDs comuns)
      const [holderDid, holderVerkey] = await timed(stats, "createOwnDid(holder)", async () =>
        holder.createOwnDid()
      );
      const [verifierDid, verifierVerkey] = await timed(stats, "createOwnDid(verifier)", async () =>
        verifier.createOwnDid()
      );

      await timed(stats, "registerDidOnLedger(holder)", async () =>
        tryRegisterDid(issuer, genesisFile, SUBMITTER_DID, holderDid, holderVerkey, null)
      );
      await timed(stats, "registerDidOnLedger(verifier)", async () =>
        tryRegisterDid(issuer, genesisFile, SUBMITTER_DID, verifierDid, verifierVerkey, null)
      );

      // 5) Schema + CredDef: o ISSUER é o próprio SUBMITTER_DID (já existente na rede)
      // schema_version precisa ser X.Y ou X.Y.Z (numérico)
      const schemaVer = `1.0.${runId % 1000000}`;
      const schemaName = `cpf_indicio_time_${runId}_${i}`;

      const schemaId = await timed(stats, "createAndRegisterSchema(CPF)", async () =>
        issuer.createAndRegisterSchema(
          genesisFile,
          SUBMITTER_DID,
          schemaName,
          schemaVer,
          ["nome", "cpf", "idade"]
        )
      );

      const credDefTag = `TAG_CPF_INDICIO_${runId}_${i}_${Date.now()}`;
      const credDefId = await timed(stats, "createAndRegisterCredDef(CPF)", async () =>
        issuer.createAndRegisterCredDef(genesisFile, SUBMITTER_DID, schemaId, credDefTag)
      );

      // 6) Fetch do ledger
      const schemaCpfJson = await timed(stats, "fetchSchemaFromLedger(CPF)", async () =>
        holder.fetchSchemaFromLedger(genesisFile, schemaId)
      );
      const credDefCpfJson = await timed(stats, "fetchCredDefFromLedger(CPF)", async () =>
        holder.fetchCredDefFromLedger(genesisFile, credDefId)
      );

      // 7) Link secret
      await timed(stats, "createLinkSecret(default)", async () => {
        try { await holder.createLinkSecret("default"); } catch (_) {}
      });

      // 8) Offer -> Request -> Issue -> Store
      const offerId = `offer-indicio-${runId}-${i}-${Date.now()}`;
      const offerJson = await timed(stats, "createCredentialOffer(CPF)", async () =>
        issuer.createCredentialOffer(credDefId, offerId)
      );

      const offerObj = JSON.parse(offerJson);
      const reqMetaId = offerObj?.nonce;
      if (!reqMetaId) throw new Error("Offer sem nonce (reqMetaId).");

      const reqJson = await timed(stats, "createCredentialRequest(CPF)", async () =>
        holder.createCredentialRequest("default", holderDid, credDefCpfJson, offerJson)
      );

      const valuesCpf = { nome: "Amarildo Dias", cpf: "123.456.789-09", idade: "35" }; // idade string numérica
      const credJson = await timed(stats, "createCredential(CPF)", async () =>
        issuer.createCredential(credDefId, offerJson, reqJson, JSON.stringify(valuesCpf))
      );

      const credIdLocal = `cred-cpf-indicio-${runId}-${i}`;
      await timed(stats, "storeCredential(CPF)", async () =>
        holder.storeCredential(credIdLocal, credJson, reqMetaId, credDefCpfJson, null)
      );

      // 9) Proof: Verifier cria request, Holder cria presentation, Verifier verifica
      const presReq = {
        nonce: String(Date.now()),
        name: "proof-indicio-zkp18",
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
          attr_nome: { cred_id: credIdLocal, revealed: true },
          attr_cpf: { cred_id: credIdLocal, revealed: true },
        },
        requested_predicates: {
          pred_idade_ge_18: { cred_id: credIdLocal },
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
        verifier.verifyPresentation(
          JSON.stringify(presReq),
          presJson,
          schemasMap,
          credDefsMap
        )
      );
      if (!ok) throw new Error("verifyPresentation retornou false.");

      // 10) Opcional: envelope pack/unpack (se existir)
      if (hasMethod(issuer, "envelopePackAuthcrypt") && hasMethod(holder, "envelopeUnpackAuto")) {
        const envJson = await timed(stats, "envelopePackAuthcrypt(offer)", async () =>
          issuer.envelopePackAuthcrypt(
            SUBMITTER_DID,
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
      try { await issuer.walletClose(); } catch (_) {}
      try { await holder.walletClose(); } catch (_) {}
      try { await verifier.walletClose(); } catch (_) {}
    }
  }

  // -------------------------
  // Relatório
  // -------------------------
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
    run_id: runId,
    created_at: new Date().toISOString(),
    network: "INDICIO_TESTNET",
    genesis: { url: genesisUrl, file: genesisFile },
    env: { ITER, SUBMITTER_DID },
    notes: {
      submitter: "Sem TRUSTEE. Writes assinados pelo SUBMITTER_DID (endorser/issuer). Holder+Verifier registrados como DIDs comuns (role null).",
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