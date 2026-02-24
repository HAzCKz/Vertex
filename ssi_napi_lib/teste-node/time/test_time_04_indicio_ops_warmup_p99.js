/*
PARA RODAR ESTE TESTE (INDICIO Testnet):
WALLET_PASS="minha_senha_teste" \
SUBMITTER_SEED="+0HGyElhOr/GuwUaDsyiTn926bFMrBUh" \
SUBMITTER_DID="7DffLFWsgrwbt7T1Ni9cmu" \
ITER=1 WARMUP=0 MEASURE_RESOLVE=0 \
node teste-node/time/test_time_04_indicio_ops_warmup_p99.js

ENV OPCIONAIS:
- GENESIS_FILE=./indicio_testnet.txn  (default)
- WARMUP=5               -> descarta as primeiras WARMUP iterações das estatísticas
- MEASURE_RESOLVE=1      -> mede resolveDidOnLedger(holder/verifier) após registrar NYM
*/

const fs = require("fs");
const path = require("path");
const https = require("https");
const crypto = require("crypto");

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

function stddev(values) {
  if (!values.length) return 0;
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const varSum = values.reduce((acc, x) => acc + Math.pow(x - mean, 2), 0);
  return Math.sqrt(varSum / values.length); // stddev populacional
}

function summarize(valuesMs) {
  const arr = [...valuesMs].sort((a, b) => a - b);
  const sum = arr.reduce((a, b) => a + b, 0);
  const avg = arr.length ? sum / arr.length : 0;

  return {
    n: arr.length,
    avg_ms: avg,
    stddev_ms: stddev(arr),
    min_ms: arr[0] ?? null,
    max_ms: arr[arr.length - 1] ?? null,
    p50_ms: percentile(arr, 50),
    p95_ms: percentile(arr, 95),
    p99_ms: percentile(arr, 99),
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
// Timer Runner (com WARMUP)
// -------------------------
async function timed(stats, label, fn, shouldRecord) {
  const t0 = nowNs();
  const out = await fn();
  const dt = nsToMs(nowNs() - t0);

  if (shouldRecord) {
    if (!stats[label]) stats[label] = [];
    stats[label].push(dt);
  }
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
  const GENESIS_FILE = process.env.GENESIS_FILE || "./indicio_testnet.txn";

  // SUBMITTER (ENDORSER/ISSUER) já existente na Indicio
  const SUBMITTER_SEED = process.env.SUBMITTER_SEED || "+0HGyElhOr/GuwUaDsyiTn926bFMrBUh";
  const SUBMITTER_DID  = process.env.SUBMITTER_DID  || "7DffLFWsgrwbt7T1Ni9cmu";

  const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";

  const ITER = Number(process.env.ITER || "30");
  const WARMUP = Number(process.env.WARMUP || "2");
  const MEASURE_RESOLVE = String(process.env.MEASURE_RESOLVE || "0") === "1";

  if (!Number.isFinite(ITER) || ITER < 1) throw new Error("ITER inválido.");
  if (!Number.isFinite(WARMUP) || WARMUP < 0) throw new Error("WARMUP inválido.");
  if (WARMUP >= ITER) throw new Error("WARMUP deve ser menor que ITER.");

  // garante genesis
  if (!fs.existsSync(GENESIS_FILE)) {
    console.log(`📥 Genesis não encontrado. Baixando da Indicio...`);
    await downloadToFile(genesisUrl, GENESIS_FILE);
    console.log(`✅ Genesis salvo em: ${GENESIS_FILE}`);
  } else {
    console.log(`📂 Genesis já existe: ${GENESIS_FILE}`);
  }

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

  const reportFile = path.join(outDir, `time_report_indicio_${runKey}.json`);
  const stats = {};      // somente pós-warmup
  const stats_all = {};  // bruto incluindo warmup

  console.log("============================================================");
  console.log("⏱️  TESTE TIME 04: benchmark SSI (INDICIO) + WARMUP + p99 + stddev");
  console.log("Config:", {
    GENESIS_FILE,
    ITER,
    WARMUP,
    MEASURE_RESOLVE,
    SUBMITTER_DID,
    walletPass: "***",
    RUN_TAG,
    runKey,
  });
  console.log("============================================================");

  for (let i = 1; i <= ITER; i++) {
    const isWarmup = i <= WARMUP;
    const shouldRecord = !isWarmup;

    console.log(`\n------------------ ITERAÇÃO ${i}/${ITER} ${isWarmup ? "(WARMUP)" : ""} ------------------`);

    const issuerWalletPath = path.join(walletsDir, `time_indicio_issuer_${runKey}_${i}.db`);
    const holderWalletPath = path.join(walletsDir, `time_indicio_holder_${runKey}_${i}.db`);
    const verifierWalletPath = path.join(walletsDir, `time_indicio_verifier_${runKey}_${i}.db`);
    rmIfExists(issuerWalletPath);
    rmIfExists(holderWalletPath);
    rmIfExists(verifierWalletPath);

    const issuer = new IndyAgent();
    const holder = new IndyAgent();
    const verifier = new IndyAgent();

    try {
      // helper para gravar sempre em stats_all e condicionalmente em stats
      const T = async (label, fn) => {
        const out = await timed(stats_all, label, fn, true);
        if (shouldRecord) {
          if (!stats[label]) stats[label] = [];
          stats[label].push(stats_all[label][stats_all[label].length - 1]);
        }
        return out;
      };

      // Wallets
      await T("walletCreate(issuer)", async () => issuer.walletCreate(issuerWalletPath, WALLET_PASS));
      await T("walletCreate(holder)", async () => holder.walletCreate(holderWalletPath, WALLET_PASS));
      await T("walletCreate(verifier)", async () => verifier.walletCreate(verifierWalletPath, WALLET_PASS));

      await T("walletOpen(issuer)", async () => issuer.walletOpen(issuerWalletPath, WALLET_PASS));
      await T("walletOpen(holder)", async () => holder.walletOpen(holderWalletPath, WALLET_PASS));
      await T("walletOpen(verifier)", async () => verifier.walletOpen(verifierWalletPath, WALLET_PASS));

      // Network
      await T("connectNetwork(issuer)", async () => issuer.connectNetwork(GENESIS_FILE));
      await T("connectNetwork(holder)", async () => holder.connectNetwork(GENESIS_FILE));
      await T("connectNetwork(verifier)", async () => verifier.connectNetwork(GENESIS_FILE));

      // Import seed do SUBMITTER para assinar writes
      await T("importDidFromSeed(SUBMITTER)", async () => issuer.importDidFromSeed(SUBMITTER_SEED));

      // DIDs locais (holder/verifier) + registrar como DIDs comuns (role null)
      const [holderDid, holderVerkey] = await T("createOwnDid(holder)", async () => holder.createOwnDid());
      const [verifierDid, verifierVerkey] = await T("createOwnDid(verifier)", async () => verifier.createOwnDid());

      await T("registerDidOnLedger(holder)", async () =>
        tryRegisterDid(issuer, GENESIS_FILE, SUBMITTER_DID, holderDid, holderVerkey, null)
      );

      if (MEASURE_RESOLVE && hasMethod(issuer, "resolveDidOnLedger")) {
        await T("resolveDidOnLedger(holder)", async () => issuer.resolveDidOnLedger(holderDid));
      } else if (MEASURE_RESOLVE && !stats_all["_note_no_resolve"]) {
        stats_all["_note_no_resolve"] = ["Lib não expõe resolveDidOnLedger"];
      }

      await T("registerDidOnLedger(verifier)", async () =>
        tryRegisterDid(issuer, GENESIS_FILE, SUBMITTER_DID, verifierDid, verifierVerkey, null)
      );

      if (MEASURE_RESOLVE && hasMethod(issuer, "resolveDidOnLedger")) {
        await T("resolveDidOnLedger(verifier)", async () => issuer.resolveDidOnLedger(verifierDid));
      }

      // Schema + CredDef assinados pelo SUBMITTER_DID (issuer on-ledger)
      const schemaVer = `1.0.${runVerNum}`; // X.Y.Z numérico
      const schemaName = `cpf_indicio_time_${runKey}_${i}`;

      const schemaId = await T("createAndRegisterSchema(CPF)", async () =>
        issuer.createAndRegisterSchema(
          GENESIS_FILE,
          SUBMITTER_DID,
          schemaName,
          schemaVer,
          ["nome", "cpf", "idade"]
        )
      );

      const credDefTag = `TAG_CPF_INDICIO_${runKey}_${i}_${Date.now()}`;
      const credDefId = await T("createAndRegisterCredDef(CPF)", async () =>
        issuer.createAndRegisterCredDef(GENESIS_FILE, SUBMITTER_DID, schemaId, credDefTag)
      );

      // Fetch do ledger (holder)
      const schemaCpfJson = await T("fetchSchemaFromLedger(CPF)", async () =>
        holder.fetchSchemaFromLedger(GENESIS_FILE, schemaId)
      );
      const credDefCpfJson = await T("fetchCredDefFromLedger(CPF)", async () =>
        holder.fetchCredDefFromLedger(GENESIS_FILE, credDefId)
      );

      // Link secret
      await T("createLinkSecret(default)", async () => {
        try { await holder.createLinkSecret("default"); } catch (_) {}
      });

      // Offer -> Request -> Issue -> Store
      const offerId = `offer-indicio-${runKey}-${i}-${Date.now()}`;
      const offerJson = await T("createCredentialOffer(CPF)", async () =>
        issuer.createCredentialOffer(credDefId, offerId)
      );

      const offerObj = JSON.parse(offerJson);
      const reqMetaId = offerObj?.nonce;
      if (!reqMetaId) throw new Error("Offer sem nonce (reqMetaId).");

      const reqJson = await T("createCredentialRequest(CPF)", async () =>
        holder.createCredentialRequest("default", holderDid, credDefCpfJson, offerJson)
      );

      const valuesCpf = { nome: "Amarildo Dias", cpf: "123.456.789-09", idade: "35" };
      const credJson = await T("createCredential(CPF)", async () =>
        issuer.createCredential(credDefId, offerJson, reqJson, JSON.stringify(valuesCpf))
      );

      const credLocalId = `cred-cpf-indicio-${runKey}-${i}`;
      await T("storeCredential(CPF)", async () =>
        holder.storeCredential(credLocalId, credJson, reqMetaId, credDefCpfJson, null)
      );

      // Proof: verifier cria request, holder cria presentation, verifier verifica
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
          attr_nome: { cred_id: credLocalId, revealed: true },
          attr_cpf: { cred_id: credLocalId, revealed: true },
        },
        requested_predicates: {
          pred_idade_ge_18: { cred_id: credLocalId },
        },
      };

      const schemasMap = JSON.stringify({ [schemaId]: JSON.parse(schemaCpfJson) });
      const credDefsMap = JSON.stringify({ [credDefId]: JSON.parse(credDefCpfJson) });

      const presJson = await T("createPresentation(ZKP18)", async () =>
        holder.createPresentation(
          JSON.stringify(presReq),
          JSON.stringify(requestedCreds),
          schemasMap,
          credDefsMap
        )
      );

      const ok = await T("verifyPresentation(ZKP18)", async () =>
        verifier.verifyPresentation(
          JSON.stringify(presReq),
          presJson,
          schemasMap,
          credDefsMap
        )
      );
      if (!ok) throw new Error("verifyPresentation retornou false.");

      // Envelope pack/unpack (opcional)
      if (hasMethod(issuer, "envelopePackAuthcrypt") && hasMethod(holder, "envelopeUnpackAuto")) {
        const envJson = await T("envelopePackAuthcrypt(offer)", async () =>
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
        await T("envelopeUnpackAuto(offer)", async () =>
          holder.envelopeUnpackAuto(holderDid, envJson)
        );
      } else {
        if (!stats_all["_note_no_envelope"]) {
          stats_all["_note_no_envelope"] = ["Lib não expõe envelopePackAuthcrypt/envelopeUnpackAuto"];
        }
      }

      console.log("✅ Iteração OK.");
    } finally {
      try { await issuer.walletClose(); } catch (_) {}
      try { await holder.walletClose(); } catch (_) {}
      try { await verifier.walletClose(); } catch (_) {}

      // 🧹 Limpeza automática (evita encher HD em execuções longas/paralelas)
      rmIfExists(issuerWalletPath);
      rmIfExists(holderWalletPath);
      rmIfExists(verifierWalletPath);
    }
  }

  // -------------------------
  // Relatório (pós-warmup)
  // -------------------------
  const summary = {};
  for (const [label, arr] of Object.entries(stats)) {
    if (label.startsWith("_note_")) continue;
    if (!Array.isArray(arr) || !arr.length) continue;
    summary[label] = summarize(arr);
  }

  const labels = Object.keys(summary);
  const col1 = Math.max(30, ...labels.map((s) => s.length));

  console.log("\n============================================================");
  console.log("📊 RESULTADOS (ms) — avg / stddev / p95 / p99 / min / max (N=" + (ITER - WARMUP) + ")");
  console.log("============================================================");
  for (const label of labels) {
    const s = summary[label];
    console.log(
      padRight(label, col1) +
        " | avg " + padRight(fmt(s.avg_ms), 12) +
        " | sd " + padRight(fmt(s.stddev_ms), 12) +
        " | p95 " + padRight(fmt(s.p95_ms), 12) +
        " | p99 " + padRight(fmt(s.p99_ms), 12) +
        " | min " + padRight(fmt(s.min_ms), 12) +
        " | max " + padRight(fmt(s.max_ms), 12)
    );
  }

  const report = {
    run_id: runKey,
    created_at: new Date().toISOString(),
    network: "INDICIO_TESTNET",
    genesis: { url: genesisUrl, file: GENESIS_FILE },
    env: { ITER, WARMUP, RUN_TAG, MEASURE_RESOLVE, SUBMITTER_DID },
    notes: {
      submitter:
        "Sem TRUSTEE. Writes assinados pelo SUBMITTER_DID (endorser/issuer). Holder+Verifier registrados como DIDs comuns (role null).",
      envelope_methods:
        stats_all["_note_no_envelope"]?.[0] ||
        "envelopePackAuthcrypt/envelopeUnpackAuto medidos quando disponíveis",
      resolve_methods:
        stats_all["_note_no_resolve"]?.[0] ||
        "resolveDidOnLedger medido quando MEASURE_RESOLVE=1 e método existe",
    },
    raw_ms_all: Object.fromEntries(
      Object.entries(stats_all).filter(([k, v]) => !k.startsWith("_note_") && Array.isArray(v))
    ),
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