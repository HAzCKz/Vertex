/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
ITER=400 \
WARMUP=1 \
node teste-node/revocation/test_revocation_45_timing_revoke_single_vs_all_1000_windows_von.js

Para subir o bfilter:
cd /home/yugi/programacao/bfilter
BFILTER_ADMIN_TOKEN="dev-admin-token" cargo run

ENV OPCIONAIS:
- ITER=6      -> número total de iterações do benchmark
- WARMUP=1    -> iterações descartadas das estatísticas
*/

/*
Benchmark de revogação para credenciais com 1000 janelas diárias.

Mede:
- tempo para revogar a última janela válida e suas 10 janelas extras de confirmação (revogando da janela 999)
- tempo para revogar todas as 1000 janelas válidas e as 10 extras (revogando da janela 0)

Também valida:
- cada credencial emitida possui exatamente 1000 janelas válidas e 10 extras;
- o preflight prevê 11 e 1010 chaves respectivamente;
- o delta de entradas no Bloom acompanha o número de chaves gravadas.

Como cada revogação altera o manifesto do Bloom, este benchmark emite cada
credencial com o manifesto mais recente imediatamente antes da sua própria
medição de revogação.
*/

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const {
  NETWORK_CONFIG,
  assert,
  downloadGenesisHttp,
  loadIndyAgent,
  fn,
  walletCreateOpenIdempotent,
  parseJsonSafe,
  extractNonce,
  cleanupWalletFamily,
  ensureWalletDir,
} = require("./_helpers");

const CONTROL_ATTRS = [
  "seed",
  "start_time",
  "unit_of_time",
  "time_window",
  "root_merkle_L",
];

const WINDOW_COUNT = 1000;
const LAST_WINDOW_INDEX = WINDOW_COUNT - 1;
const REQUIRED_EXTRA_WINDOWS_FOR_FP = 10;
const TOTAL_WINDOW_COUNT = WINDOW_COUNT + REQUIRED_EXTRA_WINDOWS_FOR_FP;

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function sha256Base64(input) {
  return crypto.createHash("sha256").update(input).digest("base64");
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
  return Math.sqrt(varSum / values.length);
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

function mkdirp(p) {
  fs.mkdirSync(p, { recursive: true });
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

async function fetchManifestEnvelope(baseUrl) {
  const resp = await fetch(`${baseUrl}/manifest`);
  assert(resp.ok, `Falha GET /manifest: ${resp.status}`);
  const manifestBodyText = await resp.text();
  const envelope = JSON.parse(manifestBodyText);
  assert(envelope.ok === true, "manifesto Bloom deveria retornar ok=true");
  envelope.manifest_hash_body = sha256Base64(manifestBodyText);
  return envelope;
}

function getActiveInsertedCount(manifestEnvelope) {
  const manifest = manifestEnvelope.manifest || {};
  const activeId = manifest.active_filter_id;
  const filters = Array.isArray(manifest.filters) ? manifest.filters : [];
  const active = filters.find((item) => item.filter_id === activeId) || filters[filters.length - 1];
  return Number(active?.inserted_count || 0);
}

function getTotalInsertedCount(manifestEnvelope) {
  const manifest = manifestEnvelope.manifest || {};
  const filters = Array.isArray(manifest.filters) ? manifest.filters : [];
  return filters.reduce((sum, item) => sum + Number(item?.inserted_count || 0), 0);
}

(async () => {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";
  const BFILTER_BASE_URL = process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080";
  const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";
  const TRUSTEE_SEED = process.env.TRUSTEE_SEED || NETWORK_CONFIG.trusteeSeed;
  const TRUSTEE_DID = process.env.TRUSTEE_DID || NETWORK_CONFIG.trusteeDid;
  const ITER = Number(process.env.ITER || "6");
  const WARMUP = Number(process.env.WARMUP || "1");

  if (!Number.isFinite(ITER) || ITER < 1) throw new Error("ITER inválido");
  if (!Number.isFinite(WARMUP) || WARMUP < 0 || WARMUP >= ITER) {
    throw new Error("WARMUP inválido");
  }

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_bench_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_bench_holder.db");

  const outDir = path.join(__dirname, "out");
  mkdirp(outDir);
  const runTag = `${Date.now()}_${process.pid}`;
  const reportFile = path.join(outDir, `revocation_bench_1000_windows_${runTag}.json`);

  const genesisAbs = path.join(process.cwd(), process.env.GENESIS_FILE || NETWORK_CONFIG.genesisFile);
  await downloadGenesisHttp(NETWORK_CONFIG.genesisUrl, genesisAbs);

  if (RESET) {
    cleanupWalletFamily(issuerDb);
    cleanupWalletFamily(holderDb);
  }

  const issuer = new IndyAgent();
  const holder = new IndyAgent();

  await walletCreateOpenIdempotent(issuer, issuerDb, pass);
  await walletCreateOpenIdempotent(holder, holderDb, pass);

  try {
    await issuer.connectNetwork(genesisAbs);
    await holder.connectNetwork(genesisAbs);

    const importDidFromSeed = fn(issuer, "importDidFromSeed", "import_did_from_seed");
    const createAndRegisterSchema = fn(issuer, "createAndRegisterSchema", "create_and_register_schema");
    const creddefSaveLocal = fn(issuer, "creddefSaveLocal", "creddef_save_local");
    const creddefRegisterFromLocal = fn(issuer, "creddefRegisterFromLocal", "creddef_register_from_local");
    const fetchCredDefFromLedger = fn(issuer, "fetchCredDefFromLedger", "fetch_cred_def_from_ledger");
    const createCredentialOffer = fn(issuer, "createCredentialOffer", "create_credential_offer");
    const createCredentialRequest = fn(holder, "createCredentialRequest", "create_credential_request");
    const createLinkSecret = fn(holder, "createLinkSecret", "create_link_secret");
    const revocationBuildManifestAnchor = fn(issuer, "revocationBuildManifestAnchor", "revocation_build_manifest_anchor");
    const revocationWriteManifestAnchorOnLedger = fn(issuer, "revocationWriteManifestAnchorOnLedger", "revocation_write_manifest_anchor_on_ledger");
    const issueRevocableCredential = fn(issuer, "issueRevocableCredential", "issue_revocable_credential");
    const getIssuedRevocableCredentialSummary = fn(
      issuer,
      "getIssuedRevocableCredentialSummary",
      "get_issued_revocable_credential_summary"
    );
    const preflightRevokeIssuedCredential = fn(
      issuer,
      "preflightRevokeIssuedCredential",
      "preflight_revoke_issued_credential"
    );
    const revokeIssuedCredentialFromWindow = fn(
      issuer,
      "revokeIssuedCredentialFromWindow",
      "revoke_issued_credential_from_window"
    );

    console.log("============================================================");
    console.log("⏱️ TESTE REVOGAÇÃO 45: benchmark revogar 1 vs 1000 janelas");
    console.log("Config:", {
      ITER,
      WARMUP,
      WINDOW_COUNT,
      BFILTER_BASE_URL,
      GENESIS_FILE: genesisAbs,
      walletPass: "***",
    });
    console.log("============================================================");

    const [trusteeDid] = await importDidFromSeed(TRUSTEE_SEED);
    assert(trusteeDid === TRUSTEE_DID, `Trustee DID inesperado: ${trusteeDid}`);

    const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
    const [holderDid] = await holder.createOwnDid();
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, issuerDid, issuerVerkey, "ENDORSER");

    const manifestEnvelope = await fetchManifestEnvelope(BFILTER_BASE_URL);
    const manifestHash = manifestEnvelope.manifest_hash_body;
    const manifestJson = await revocationBuildManifestAnchor(
      issuerDid,
      `${BFILTER_BASE_URL}/manifest`,
      manifestHash,
      String(manifestEnvelope.manifest.version || 1)
    );
    const manifest = parseJsonSafe(manifestJson, "manifest_anchor");
    parseJsonSafe(
      await revocationWriteManifestAnchorOnLedger(genesisAbs, issuerDid, JSON.stringify(manifest)),
      "write_manifest"
    );

    const schemaId = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRevBench1000_${Date.now()}`,
      `1.${nowSec()}`,
      ["nome", "cpf", ...CONTROL_ATTRS]
    );
    const localCredDefJson = await creddefSaveLocal(
      issuerDid,
      schemaId,
      `TAG_REV_BENCH_${Date.now()}`,
      false,
      "prod"
    );
    const localCredDef = parseJsonSafe(localCredDefJson, "creddef_local");
    const credDefReg = await creddefRegisterFromLocal(genesisAbs, localCredDef.id_local, issuerDid);
    const credDefId = credDefReg.credDefId || credDefReg.cred_def_id;
    const credDefLedger = parseJsonSafe(
      await fetchCredDefFromLedger(genesisAbs, credDefId),
      "creddef_ledger"
    );

    try {
      await createLinkSecret("default");
    } catch (_) {}

    async function issueBenchCredential(label, iteration) {
      const manifestEnvelopeCurrent = await fetchManifestEnvelope(BFILTER_BASE_URL);
      const manifestCurrentJson = await revocationBuildManifestAnchor(
        issuerDid,
        `${BFILTER_BASE_URL}/manifest`,
        manifestEnvelopeCurrent.manifest_hash_body,
        String(manifestEnvelopeCurrent.manifest.version || 1)
      );
      const manifestCurrent = parseJsonSafe(
        manifestCurrentJson,
        `manifest_current_${label}_${iteration}`
      );

      const offerJson = await createCredentialOffer(
        credDefId,
        `offer-bench-${label}-${iteration}-${Date.now()}`
      );
      const requestJson = await createCredentialRequest(
        "default",
        holderDid,
        JSON.stringify(credDefLedger),
        offerJson
      );

      const issuerLocalCredentialId = `issued-bench-${label}-${iteration}-${Date.now()}`;
      const startTime = nowSec();
      const validityEnd = startTime + 86400 * (WINDOW_COUNT - 1);

      const issuedJson = await issueRevocableCredential(
        genesisAbs,
        issuerLocalCredentialId,
        holderDid,
        credDefId,
        schemaId,
        offerJson,
        requestJson,
        JSON.stringify({
          nome: `Alice ${label} ${iteration}`,
          cpf: String(10000000000 + iteration * 10 + (label === "single" ? 1 : 2)),
        }),
        startTime,
        validityEnd,
        "days",
        1,
        REQUIRED_EXTRA_WINDOWS_FOR_FP,
        JSON.stringify(manifestCurrent),
        null,
        null
      );
      const issued = parseJsonSafe(issuedJson, `issued_${label}_${iteration}`);
      const summaryJson = await getIssuedRevocableCredentialSummary(issuerLocalCredentialId);
      const summary = parseJsonSafe(summaryJson, `summary_${label}_${iteration}`);
      assert(summary.revocation_summary.window_count === TOTAL_WINDOW_COUNT, `window_count deveria ser ${TOTAL_WINDOW_COUNT}`);
      return {
        issuerLocalCredentialId,
        issued,
      };
    }

    const allStats = {
      revoke_single_window_ms: [],
      revoke_all_windows_ms: [],
      bloom_delta_single: [],
      bloom_delta_all: [],
    };
    const keptStats = {
      revoke_single_window_ms: [],
      revoke_all_windows_ms: [],
      bloom_delta_single: [],
      bloom_delta_all: [],
    };

    for (let i = 1; i <= ITER; i++) {
      const isWarmup = i <= WARMUP;
      console.log(`\n------------------ ITERAÇÃO ${i}/${ITER} ${isWarmup ? "(WARMUP)" : ""} ------------------`);

      const single = await issueBenchCredential("single", i);
      const preflightSingle = parseJsonSafe(
        await preflightRevokeIssuedCredential(single.issuerLocalCredentialId, LAST_WINDOW_INDEX),
        `preflight_single_${i}`
      );
      assert(preflightSingle.can_revoke === true, "preflight single deveria permitir revogação");
      assert(preflightSingle.preflight.revocation_keys_to_write === 1 + REQUIRED_EXTRA_WINDOWS_FOR_FP, "single deveria escrever 11 chaves");

      const manifestBeforeSingle = await fetchManifestEnvelope(BFILTER_BASE_URL);
      const insertedBeforeSingle = getTotalInsertedCount(manifestBeforeSingle);
      const t0Single = nowNs();
      const revokeSingle = parseJsonSafe(
        await revokeIssuedCredentialFromWindow(
          single.issuerLocalCredentialId,
          BFILTER_ADMIN_TOKEN,
          LAST_WINDOW_INDEX,
          "bench-single-window",
          "teste-node"
        ),
        `revoke_single_${i}`
      );
      const dtSingleMs = nsToMs(nowNs() - t0Single);
      const insertedAfterSingle = getTotalInsertedCount(await fetchManifestEnvelope(BFILTER_BASE_URL));
      const deltaSingle = insertedAfterSingle - insertedBeforeSingle;
      assert(revokeSingle.revocation_keys_written === 1 + REQUIRED_EXTRA_WINDOWS_FOR_FP, "revoke single deveria escrever 11 chaves");
      assert(deltaSingle === 1 + REQUIRED_EXTRA_WINDOWS_FOR_FP, `delta Bloom single deveria ser 11, mas foi ${deltaSingle}`);

      const full = await issueBenchCredential("full", i);
      const preflightAll = parseJsonSafe(
        await preflightRevokeIssuedCredential(full.issuerLocalCredentialId, 0),
        `preflight_all_${i}`
      );
      assert(preflightAll.can_revoke === true, "preflight all deveria permitir revogação");
      assert(preflightAll.preflight.revocation_keys_to_write === TOTAL_WINDOW_COUNT, `full deveria escrever ${TOTAL_WINDOW_COUNT} chaves`);

      const manifestBeforeAll = await fetchManifestEnvelope(BFILTER_BASE_URL);
      const insertedBeforeAll = getTotalInsertedCount(manifestBeforeAll);
      const t0All = nowNs();
      const revokeAll = parseJsonSafe(
        await revokeIssuedCredentialFromWindow(
          full.issuerLocalCredentialId,
          BFILTER_ADMIN_TOKEN,
          0,
          "bench-all-windows",
          "teste-node"
        ),
        `revoke_all_${i}`
      );
      const dtAllMs = nsToMs(nowNs() - t0All);
      const insertedAfterAll = getTotalInsertedCount(await fetchManifestEnvelope(BFILTER_BASE_URL));
      const deltaAll = insertedAfterAll - insertedBeforeAll;
      assert(revokeAll.revocation_keys_written === TOTAL_WINDOW_COUNT, `revoke all deveria escrever ${TOTAL_WINDOW_COUNT} chaves`);
      assert(deltaAll === TOTAL_WINDOW_COUNT, `delta Bloom full deveria ser ${TOTAL_WINDOW_COUNT}, mas foi ${deltaAll}`);

      allStats.revoke_single_window_ms.push(dtSingleMs);
      allStats.revoke_all_windows_ms.push(dtAllMs);
      allStats.bloom_delta_single.push(deltaSingle);
      allStats.bloom_delta_all.push(deltaAll);

      if (!isWarmup) {
        keptStats.revoke_single_window_ms.push(dtSingleMs);
        keptStats.revoke_all_windows_ms.push(dtAllMs);
        keptStats.bloom_delta_single.push(deltaSingle);
        keptStats.bloom_delta_all.push(deltaAll);
      }

      console.log("single-window:", {
        revoke_from_window: LAST_WINDOW_INDEX,
        time_ms: Number(dtSingleMs.toFixed(2)),
        bloom_delta: deltaSingle,
      });
      console.log("all-windows:", {
        revoke_from_window: 0,
        time_ms: Number(dtAllMs.toFixed(2)),
        bloom_delta: deltaAll,
      });
    }

    const report = {
      ok: true,
      generated_at: new Date().toISOString(),
      config: {
        ITER,
        WARMUP,
        WINDOW_COUNT,
        unit_of_time: "days",
        time_window: 1,
      },
      summaries: {
        revoke_single_window: summarize(keptStats.revoke_single_window_ms),
        revoke_all_windows: summarize(keptStats.revoke_all_windows_ms),
      },
      bloom_deltas: {
        single_window: summarize(keptStats.bloom_delta_single),
        all_windows: summarize(keptStats.bloom_delta_all),
      },
      raw: {
        all_iterations: allStats,
        measured_only: keptStats,
      },
    };

    fs.writeFileSync(reportFile, JSON.stringify(report, null, 2), "utf8");

    console.log("\n============================================================");
    console.log("📊 RESUMO BENCHMARK");
    console.log("revoke_single_window:", report.summaries.revoke_single_window);
    console.log("revoke_all_windows:", report.summaries.revoke_all_windows);
    console.log("bloom_deltas:", report.bloom_deltas);
    console.log(`📄 Relatório salvo em: ${reportFile}`);
    console.log("============================================================");
    console.log("✅ OK: TESTE REVOGAÇÃO 45 passou.");
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 45:", e && e.stack ? e.stack : e);
  process.exit(1);
});
