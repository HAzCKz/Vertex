#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const {
  ensureDirSync,
  firstNonEmpty,
  parseMaybeJson,
  round,
  summarizeNumbers,
  timestampTag,
  writeCsv,
  writeJson,
} = require("./benchmarks/utils");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const DEFAULT_RESULTS_ROOT = path.join(PROJECT_ROOT, "tests", "results");
const DEFAULT_VON_CONFIG = path.join(PROJECT_ROOT, "tests", "blindrevoke.config.json");
const DEFAULT_INDICIO_CONFIG = path.join(PROJECT_ROOT, "tests", "blindrevoke-indicio.config.json");
const DEFAULT_ITERATIONS = 10;
const SKIP_ITERATIONS_PER_OPERATION = 3;
const DEFAULT_TRUSTEE_DID = "V4SGRU86Z58d6TV7PBUe6f";
const OPERATIONS = [
  { key: "schema", label: "Gravação de SCHEMA" },
  { key: "cred_def", label: "Gravação de CRED_DEF" },
  { key: "did", label: "Gravação de DID comum" },
  { key: "attrib", label: "Gravação de ATTRIB" },
];

let ssiApi = null;

function getSsi() {
  if (!ssiApi) ssiApi = require("../src/main/ssi/ssi-api");
  return ssiApi;
}

function printHelp() {
  console.log([
    "Uso: node tests/blindrevoke-ledger-ops-bench.js [all|run-network|compare] [opções]",
    "",
    "Comando padrão: all",
    "",
    "Opções gerais:",
    `  --iterations <n>       Operações medidas por tipo e por rede. Padrão: ${DEFAULT_ITERATIONS}`,
    `  warmups descartados    ${SKIP_ITERATIONS_PER_OPERATION} execução(ões) inicial(is) por tipo, configurado no topo do arquivo`,
    "  --output-dir <dir>     Pasta de saída. Padrão: tests/results/ledger-ops-<timestamp>",
    "",
    "Opções de all:",
    "  --von-config <file>    Config da von-network. Padrão: tests/blindrevoke.config.json",
    "  --indicio-config <f>   Config da Indicio. Padrão: tests/blindrevoke-indicio.config.json",
    "",
    "Opções de run-network:",
    "  --network <label>      Nome da rede no relatório",
    "  --config <file>        Config do benchmark para a rede",
    "",
    "Opções de compare:",
    "  --von-summary <file>   JSON summary da von-network",
    "  --indicio-summary <f>  JSON summary da Indicio",
  ].join("\n"));
}

function parseCliArgs(argv) {
  const out = {
    command: "all",
    iterations: DEFAULT_ITERATIONS,
    outputDir: "",
    vonConfig: DEFAULT_VON_CONFIG,
    indicioConfig: DEFAULT_INDICIO_CONFIG,
    config: "",
    network: "",
    vonSummary: "",
    indicioSummary: "",
  };

  const args = argv.slice();
  if (args[0] && !args[0].startsWith("-")) {
    out.command = args.shift();
  }

  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    }
    if (arg === "--iterations") {
      out.iterations = Math.max(1, Math.trunc(Number(args[i + 1]) || DEFAULT_ITERATIONS));
      i += 1;
      continue;
    }
    if (arg === "--output-dir") {
      out.outputDir = resolveFromProject(args[i + 1] || "");
      i += 1;
      continue;
    }
    if (arg === "--von-config") {
      out.vonConfig = resolveFromProject(args[i + 1] || "");
      i += 1;
      continue;
    }
    if (arg === "--indicio-config") {
      out.indicioConfig = resolveFromProject(args[i + 1] || "");
      i += 1;
      continue;
    }
    if (arg === "--config") {
      out.config = resolveFromProject(args[i + 1] || "");
      i += 1;
      continue;
    }
    if (arg === "--network") {
      out.network = String(args[i + 1] || "").trim();
      i += 1;
      continue;
    }
    if (arg === "--von-summary") {
      out.vonSummary = resolveFromProject(args[i + 1] || "");
      i += 1;
      continue;
    }
    if (arg === "--indicio-summary") {
      out.indicioSummary = resolveFromProject(args[i + 1] || "");
      i += 1;
      continue;
    }
    throw new Error(`Argumento desconhecido: ${arg}`);
  }

  if (!out.outputDir) {
    out.outputDir = path.join(DEFAULT_RESULTS_ROOT, `ledger-ops-${timestampTag()}`);
  }
  out.vonConfig = resolveFromProject(out.vonConfig);
  out.indicioConfig = resolveFromProject(out.indicioConfig);
  out.config = resolveFromProject(out.config);
  return out;
}

function resolveFromProject(inputPath) {
  if (!inputPath) return "";
  if (path.isAbsolute(inputPath)) return inputPath;
  return path.resolve(PROJECT_ROOT, inputPath);
}

function loadConfig(configPathInput) {
  const configPath = resolveFromProject(configPathInput);
  if (!fs.existsSync(configPath)) {
    throw new Error(`Arquivo de configuração não encontrado: ${configPath}`);
  }
  const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
  const baseDir = path.dirname(configPath);
  return {
    ...config,
    configPath,
    genesisPathResolved: resolveConfigPath(config.genesisPath, { baseDir, mustExist: true }),
    walletPathResolved: resolveConfigPath(config.walletPath, { baseDir }),
    outputRootResolved: resolveConfigPath(config.outputRoot, { baseDir }),
  };
}

function resolveConfigPath(rawPath, options = {}) {
  const input = firstNonEmpty(rawPath);
  if (!input) return "";
  if (path.isAbsolute(input)) return input;
  const candidates = [
    path.resolve(PROJECT_ROOT, input),
    options.baseDir ? path.resolve(options.baseDir, input) : "",
  ].filter(Boolean);
  if (options.mustExist) {
    return candidates.find((candidate) => fs.existsSync(candidate)) || candidates[0] || input;
  }
  return candidates[0] || input;
}

function parseDidTuple(raw) {
  if (Array.isArray(raw)) {
    return {
      did: String(raw[0] || "").trim(),
      verkey: String(raw[1] || "").trim(),
    };
  }
  const parsed = parseMaybeJson(raw, raw);
  if (Array.isArray(parsed)) {
    return {
      did: String(parsed[0] || "").trim(),
      verkey: String(parsed[1] || "").trim(),
    };
  }
  return {
    did: firstNonEmpty(parsed?.did, parsed?.id),
    verkey: firstNonEmpty(parsed?.verkey, parsed?.verKey),
  };
}

function toSchemaId(issuerDid, name, version) {
  return `${String(issuerDid)}:2:${String(name)}:${String(version)}`;
}

function extractSchemaId(rawSchema, issuerDid, name, version) {
  const parsed = parseMaybeJson(rawSchema, null);
  if (typeof rawSchema === "string") {
    const trimmed = rawSchema.trim();
    if (trimmed && trimmed.includes(":2:")) return trimmed;
  }
  return firstNonEmpty(
    parsed?.schemaId,
    parsed?.schema_id,
    parsed?.id,
    parsed?.data?.schemaId,
    parsed?.data?.schema_id,
    parsed?.result?.id,
    parsed?.result?.schemaId,
    toSchemaId(issuerDid, name, version)
  );
}

function extractCredDefId(rawCredDef) {
  const parsed = parseMaybeJson(rawCredDef, null);
  if (typeof rawCredDef === "string") {
    const trimmed = rawCredDef.trim();
    if (trimmed && trimmed.includes(":3:CL:")) return trimmed;
  }
  return firstNonEmpty(
    parsed?.credDefId,
    parsed?.cred_def_id,
    parsed?.id,
    parsed?.data?.credDefId,
    parsed?.data?.cred_def_id,
    parsed?.result?.id,
    parsed?.result?.credDefId
  );
}

function compactError(err) {
  return String(err?.message || err || "").replace(/\s+/g, " ").trim();
}

function htmlEscape(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function htmlTable(headers, rows) {
  if (!rows.length) return "Sem dados.\n";
  const tableStyle = "border-collapse: collapse; width: 100%; margin: 12px 0;";
  const thStyle = "border: 1px solid #444; padding: 6px 8px; background: #f2f2f2; text-align: left;";
  const tdStyle = "border: 1px solid #444; padding: 6px 8px; vertical-align: top;";
  return [
    `<table border="1" cellspacing="0" cellpadding="6" style="${tableStyle}">`,
    "  <thead>",
    `    <tr>${headers.map((header) => `<th style="${thStyle}">${htmlEscape(header)}</th>`).join("")}</tr>`,
    "  </thead>",
    "  <tbody>",
    ...rows.map((row) => (
      `    <tr>${row.map((cell) => `<td style="${tdStyle}">${htmlEscape(cell ?? "-")}</td>`).join("")}</tr>`
    )),
    "  </tbody>",
    "</table>",
    "",
  ].join("\n");
}

function formatDurationMs(value) {
  const ms = Number(value);
  if (!Number.isFinite(ms) || ms < 0) return "-";
  if (ms < 1000) return `${round(ms)} ms`;
  const totalSeconds = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  const milliseconds = Math.floor(ms % 1000);
  return `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}.${String(milliseconds).padStart(3, "0")}`;
}

async function ensureWalletOpen(config) {
  const ssi = getSsi();
  const walletPath = config.walletPathResolved;
  const walletPass = String(config.walletPass || "");
  if (!walletPath || !walletPass) {
    throw new Error("walletPath e walletPass são obrigatórios na configuração.");
  }
  if (!fs.existsSync(walletPath)) {
    await ssi.walletCreate(walletPath, walletPass);
  }
  await ssi.walletOpen(walletPath, walletPass);
}

async function ensureSubmitter(config) {
  const ssi = getSsi();
  const submitterSeed = firstNonEmpty(
    config.identities?.submitter?.seed,
    config.trusteeSeed,
    "000000000000000000000000Trustee1"
  );
  const submitterDidConfigured = firstNonEmpty(
    config.identities?.submitter?.did,
    config.trusteeDid,
    DEFAULT_TRUSTEE_DID
  );
  const raw = await ssi.importDidFromSeed(submitterSeed);
  const parsed = parseDidTuple(raw);
  return {
    did: firstNonEmpty(parsed.did, submitterDidConfigured),
    verkey: firstNonEmpty(parsed.verkey),
    didConfigured: submitterDidConfigured || null,
  };
}

async function measureWithError(fn) {
  const startedAtNs = process.hrtime.bigint();
  try {
    const value = await fn();
    const elapsedMs = Number(process.hrtime.bigint() - startedAtNs) / 1_000_000;
    return { ok: true, value, elapsedMs };
  } catch (err) {
    const elapsedMs = Number(process.hrtime.bigint() - startedAtNs) / 1_000_000;
    return { ok: false, err, elapsedMs };
  }
}

function baseRow(ctx, operation, iteration) {
  const skipIterations = ctx.skipIterationsPerOperation || 0;
  const includedInStats = iteration > skipIterations;
  return {
    network: ctx.network,
    operation,
    iteration,
    measured_iteration: includedInStats ? iteration - skipIterations : "",
    included_in_stats: includedInStats,
    discard_reason: includedInStats ? "" : "warmup",
    status: "pending",
    method: "",
    elapsed_ms: "",
    elapsed_label: "",
    submitter_did: ctx.submitter.did,
    issuer_did: ctx.issuerDid,
    target_did: "",
    schema_id: "",
    cred_def_id: "",
    attrib_key: "",
    error: "",
  };
}

function totalIterationsForOperation(ctx) {
  return ctx.iterations + (ctx.skipIterationsPerOperation || 0);
}

function progressLabel(ctx, iteration) {
  const skipIterations = ctx.skipIterationsPerOperation || 0;
  const total = totalIterationsForOperation(ctx);
  if (iteration <= skipIterations) {
    return `${iteration}/${total} warmup descartado`;
  }
  return `${iteration - skipIterations}/${ctx.iterations}`;
}

async function runSchemaWrites(ctx) {
  const ssi = getSsi();
  const rows = [];
  const prefix = firstNonEmpty(ctx.config.ledgerOps?.schemaNamePrefix, "LedgerOpsBenchSchema");
  const version = firstNonEmpty(ctx.config.ledgerOps?.schemaVersion, "1.0");
  const attrNames = Array.isArray(ctx.config.ledgerOps?.schemaAttributes)
    ? ctx.config.ledgerOps.schemaAttributes.map(String)
    : ["nome", "doc", "perfil"];

  const totalIterations = totalIterationsForOperation(ctx);
  for (let i = 1; i <= totalIterations; i += 1) {
    const row = baseRow(ctx, "schema", i);
    const name = `${prefix}-${ctx.runTag}-${String(i).padStart(2, "0")}`;
    const expectedSchemaId = toSchemaId(ctx.issuerDid, name, version);
    row.method = "createAndRegisterSchema";

    const measured = await measureWithError(async () => {
      return ssi.createAndRegisterSchema(
        ctx.config.genesisPathResolved,
        ctx.issuerDid,
        name,
        version,
        attrNames
      );
    });

    row.elapsed_ms = round(measured.elapsedMs);
    row.elapsed_label = formatDurationMs(measured.elapsedMs);
    if (measured.ok) {
      row.status = "ok";
      row.schema_id = extractSchemaId(measured.value, ctx.issuerDid, name, version);
    } else {
      row.status = "error";
      row.schema_id = expectedSchemaId;
      row.error = [row.error, compactError(measured.err)].filter(Boolean).join(" | ");
    }
    rows.push(row);
    console.log(`[${ctx.network}] schema ${progressLabel(ctx, i)}: ${row.status} ${row.elapsed_label}`);
  }

  return rows;
}

async function runCredDefWrites(ctx, schemaRows) {
  const ssi = getSsi();
  const rows = [];
  const schemaIdByIteration = new Map(
    schemaRows
      .filter((row) => row.status === "ok" && firstNonEmpty(row.schema_id))
      .map((row) => [Number(row.iteration), row.schema_id])
  );

  const totalIterations = totalIterationsForOperation(ctx);
  for (let i = 1; i <= totalIterations; i += 1) {
    const row = baseRow(ctx, "cred_def", i);
    const schemaId = schemaIdByIteration.get(i) || "";
    row.schema_id = schemaId;
    if (!schemaId) {
      row.status = "skipped";
      row.error = "sem schema registrado para esta iteração";
      rows.push(row);
      continue;
    }

    const tag = `LEDGEROPS-${ctx.runTag}-${String(i).padStart(2, "0")}`;
    row.method = "createAndRegisterCredDef";

    const measured = await measureWithError(async () => {
      return ssi.createAndRegisterCredDef(ctx.config.genesisPathResolved, ctx.issuerDid, schemaId, tag);
    });

    row.elapsed_ms = round(measured.elapsedMs);
    row.elapsed_label = formatDurationMs(measured.elapsedMs);
    if (measured.ok) {
      row.status = "ok";
      row.cred_def_id = extractCredDefId(measured.value);
    } else {
      row.status = "error";
      row.error = [row.error, compactError(measured.err)].filter(Boolean).join(" | ");
    }
    rows.push(row);
    console.log(`[${ctx.network}] cred_def ${progressLabel(ctx, i)}: ${row.status} ${row.elapsed_label}`);
  }

  return rows;
}

async function runDidWrites(ctx) {
  const ssi = getSsi();
  const rows = [];
  const totalIterations = totalIterationsForOperation(ctx);
  for (let i = 1; i <= totalIterations; i += 1) {
    const row = baseRow(ctx, "did", i);
    row.method = "registerDidOnLedger(role=null)";

    let target;
    try {
      target = parseDidTuple(await ssi.createOwnDid());
      if (!target.did || !target.verkey) throw new Error("createOwnDid não retornou DID/verkey.");
      row.target_did = target.did;
    } catch (err) {
      row.status = "setup_error";
      row.error = compactError(err);
      rows.push(row);
      console.log(`[${ctx.network}] did ${progressLabel(ctx, i)}: ${row.status} -`);
      continue;
    }

    const measured = await measureWithError(() => ssi.registerDidOnLedger(
      ctx.config.genesisPathResolved,
      ctx.submitter.did,
      target.did,
      target.verkey,
      ""
    ));

    row.elapsed_ms = round(measured.elapsedMs);
    row.elapsed_label = formatDurationMs(measured.elapsedMs);
    if (measured.ok) {
      row.status = "ok";
    } else {
      row.status = "error";
      row.error = compactError(measured.err);
    }
    rows.push(row);
    console.log(`[${ctx.network}] did ${progressLabel(ctx, i)}: ${row.status} ${row.elapsed_label}`);
  }
  return rows;
}

async function runAttribWrites(ctx) {
  const ssi = getSsi();
  const rows = [];
  const totalIterations = totalIterationsForOperation(ctx);
  for (let i = 1; i <= totalIterations; i += 1) {
    const row = baseRow(ctx, "attrib", i);
    const key = `ledger_ops_${ctx.runTag}_${String(i).padStart(2, "0")}`;
    const value = JSON.stringify({
      benchmark: "ledger-ops",
      network: ctx.network,
      iteration: i,
      run_tag: ctx.runTag,
    });
    row.method = "writeAttribOnLedger";
    row.attrib_key = key;
    row.target_did = ctx.submitter.did;

    const measured = await measureWithError(() => ssi.writeAttribOnLedger(
      ctx.config.genesisPathResolved,
      ctx.submitter.did,
      key,
      value
    ));

    row.elapsed_ms = round(measured.elapsedMs);
    row.elapsed_label = formatDurationMs(measured.elapsedMs);
    if (measured.ok) {
      row.status = "ok";
    } else {
      row.status = "error";
      row.error = compactError(measured.err);
    }
    rows.push(row);
    console.log(`[${ctx.network}] attrib ${progressLabel(ctx, i)}: ${row.status} ${row.elapsed_label}`);
  }
  return rows;
}

function buildNetworkSummary(ctx, rows, totalElapsedMs) {
  const operationRows = OPERATIONS.map((operation) => {
    const scoped = rows.filter((row) => row.operation === operation.key);
    const includedRows = scoped.filter((row) => row.included_in_stats === true);
    const discardedRows = scoped.filter((row) => row.included_in_stats !== true);
    const okRows = includedRows.filter((row) => row.status === "ok");
    const stats = summarizeNumbers(okRows.map((row) => row.elapsed_ms));
    return {
      operation: operation.key,
      label: operation.label,
      attempts: includedRows.length,
      total_attempts: scoped.length,
      discarded_warmups: discardedRows.length,
      discarded_ok: discardedRows.filter((row) => row.status === "ok").length,
      discarded_errors: discardedRows.filter((row) => row.status !== "ok").length,
      ok: okRows.length,
      errors: includedRows.filter((row) => row.status === "error").length,
      setup_errors: includedRows.filter((row) => row.status === "setup_error").length,
      skipped: includedRows.filter((row) => row.status === "skipped").length,
      min_ms: stats.min,
      max_ms: stats.max,
      mean_ms: stats.mean,
      median_ms: stats.median,
      p95_ms: stats.p95,
      stdev_ms: stats.stdev,
      total_ok_elapsed_ms: round(okRows.reduce((acc, row) => acc + Number(row.elapsed_ms || 0), 0)),
    };
  });

  return {
    generatedAt: new Date().toISOString(),
    network: ctx.network,
    configPath: ctx.config.configPath,
    genesisPath: ctx.config.genesisPathResolved,
    walletPath: ctx.config.walletPathResolved,
    outputDir: ctx.outputDir,
    iterations: ctx.iterations,
    skipIterationsPerOperation: ctx.skipIterationsPerOperation || 0,
    runTag: ctx.runTag,
    submitterDid: ctx.submitter.did,
    issuerDid: ctx.issuerDid,
    totalElapsedMs: round(totalElapsedMs),
    totalElapsedLabel: formatDurationMs(totalElapsedMs),
    operations: operationRows,
  };
}

function buildNetworkMarkdown(summary) {
  const sections = [];
  sections.push(`# Ledger Ops Benchmark - ${summary.network}`);
  sections.push("");
  sections.push(`- Gerado em: ${summary.generatedAt}`);
  sections.push(`- Config: ${summary.configPath}`);
  sections.push(`- Genesis: ${summary.genesisPath}`);
  sections.push(`- Submitter DID: ${summary.submitterDid}`);
  sections.push(`- Iterações por operação: ${summary.iterations}`);
  sections.push(`- Warmups descartados por operação: ${summary.skipIterationsPerOperation}`);
  sections.push(`- Tempo total: ${summary.totalElapsedLabel}`);
  sections.push("");
  sections.push("## Resumo");
  sections.push(htmlTable(
    [
      "Operação",
      "Tentativas medidas",
      "Warmups descartados",
      "OK medidos",
      "Erros medidos",
      "Mediana (ms)",
      "Média (ms)",
      "P95 (ms)",
      "Mín. (ms)",
      "Máx. (ms)",
    ],
    summary.operations.map((row) => [
      row.label,
      row.attempts,
      row.discarded_warmups,
      row.ok,
      row.errors + row.setup_errors + row.skipped,
      row.median_ms,
      row.mean_ms,
      row.p95_ms,
      row.min_ms,
      row.max_ms,
    ])
  ));
  return `${sections.join("\n")}\n`;
}

async function runNetwork(options) {
  if (!options.config) throw new Error("--config é obrigatório em run-network.");
  if (!options.network) throw new Error("--network é obrigatório em run-network.");

  const config = loadConfig(options.config);
  const outputDir = options.outputDir;
  ensureDirSync(outputDir);

  const startedAt = Date.now();
  await ensureWalletOpen(config);
  const ssi = getSsi();
  await ssi.connectNetwork(config.genesisPathResolved);
  const submitter = await ensureSubmitter(config);
  const issuerDid = submitter.did;
  const ctx = {
    network: options.network,
    config,
    outputDir,
    iterations: options.iterations,
    skipIterationsPerOperation: Math.max(0, Math.trunc(Number(SKIP_ITERATIONS_PER_OPERATION) || 0)),
    runTag: timestampTag(),
    submitter,
    issuerDid,
  };

  const schemaRows = await runSchemaWrites(ctx);
  const credDefRows = await runCredDefWrites(ctx, schemaRows);
  const didRows = await runDidWrites(ctx);
  const attribRows = await runAttribWrites(ctx);
  const rows = [...schemaRows, ...credDefRows, ...didRows, ...attribRows];
  const totalElapsedMs = Date.now() - startedAt;
  const summary = buildNetworkSummary(ctx, rows, totalElapsedMs);

  writeCsv(path.join(outputDir, "ledger-ops-runs.csv"), rows);
  writeJson(path.join(outputDir, "ledger-ops-summary.json"), summary);
  fs.writeFileSync(path.join(outputDir, "ledger-ops-summary.md"), buildNetworkMarkdown(summary), "utf-8");

  try {
    await ssi.walletClose();
  } catch (_) {
    // best effort
  }

  console.log(`[${options.network}] resumo gerado em ${path.join(outputDir, "ledger-ops-summary.md")}`);
}

function deltaPercent(base, next) {
  if (base === undefined || base === null || base === "" || next === undefined || next === null || next === "") return "-";
  const a = Number(base);
  const b = Number(next);
  if (!Number.isFinite(a) || !Number.isFinite(b)) return "-";
  if (a === 0) return b === 0 ? "0%" : "-";
  return `${round(((b - a) / a) * 100, 2)}%`;
}

function deltaValue(base, next) {
  if (base === undefined || base === null || base === "" || next === undefined || next === null || next === "") return "-";
  const a = Number(base);
  const b = Number(next);
  if (!Number.isFinite(a) || !Number.isFinite(b)) return "-";
  return round(b - a);
}

function buildComparison(options) {
  const von = JSON.parse(fs.readFileSync(options.vonSummary, "utf-8"));
  const indicio = JSON.parse(fs.readFileSync(options.indicioSummary, "utf-8"));
  const outputDir = options.outputDir;
  ensureDirSync(outputDir);

  const rows = OPERATIONS.map((operation) => {
    const vonOp = von.operations.find((row) => row.operation === operation.key) || {};
    const indicioOp = indicio.operations.find((row) => row.operation === operation.key) || {};
    return {
      operation: operation.key,
      label: operation.label,
      von_ok: vonOp.ok ?? 0,
      indicio_ok: indicioOp.ok ?? 0,
      von_median_ms: vonOp.median_ms ?? null,
      indicio_median_ms: indicioOp.median_ms ?? null,
      delta_median_ms: deltaValue(vonOp.median_ms, indicioOp.median_ms),
      delta_median_percent: deltaPercent(vonOp.median_ms, indicioOp.median_ms),
      von_mean_ms: vonOp.mean_ms ?? null,
      indicio_mean_ms: indicioOp.mean_ms ?? null,
      delta_mean_ms: deltaValue(vonOp.mean_ms, indicioOp.mean_ms),
      delta_mean_percent: deltaPercent(vonOp.mean_ms, indicioOp.mean_ms),
      von_p95_ms: vonOp.p95_ms ?? null,
      indicio_p95_ms: indicioOp.p95_ms ?? null,
      delta_p95_ms: deltaValue(vonOp.p95_ms, indicioOp.p95_ms),
      delta_p95_percent: deltaPercent(vonOp.p95_ms, indicioOp.p95_ms),
    };
  });

  const comparison = {
    generatedAt: new Date().toISOString(),
    outputDir,
    vonNetwork: {
      summaryPath: options.vonSummary,
      outputDir: von.outputDir,
      configPath: von.configPath,
      submitterDid: von.submitterDid,
      totalElapsedMs: von.totalElapsedMs,
      totalElapsedLabel: von.totalElapsedLabel,
      skipIterationsPerOperation: von.skipIterationsPerOperation || 0,
    },
    indicio: {
      summaryPath: options.indicioSummary,
      outputDir: indicio.outputDir,
      configPath: indicio.configPath,
      submitterDid: indicio.submitterDid,
      totalElapsedMs: indicio.totalElapsedMs,
      totalElapsedLabel: indicio.totalElapsedLabel,
      skipIterationsPerOperation: indicio.skipIterationsPerOperation || 0,
    },
    rows,
  };

  const sections = [];
  sections.push("# Comparativo de Operações de Ledger: von-network x Indicio");
  sections.push("");
  sections.push(`- Gerado em: ${comparison.generatedAt}`);
  sections.push(`- Iterações por operação: ${von.iterations}`);
  sections.push(`- Warmups descartados por operação: ${von.skipIterationsPerOperation || 0}`);
  sections.push("- Delta: Indicio - von-network.");
  sections.push("");
  sections.push("## Redes");
  sections.push(htmlTable(
    ["Rede", "Config", "Submitter DID", "Tempo total"],
    [
      ["von-network", von.configPath, von.submitterDid, von.totalElapsedLabel],
      ["Indicio", indicio.configPath, indicio.submitterDid, indicio.totalElapsedLabel],
      ["Delta", "-", "-", formatDurationMs(deltaValue(von.totalElapsedMs, indicio.totalElapsedMs))],
    ]
  ));
  sections.push("## Comparação");
  sections.push(htmlTable(
    [
      "Operação",
      "OK von",
      "OK Indicio",
      "Mediana von (ms)",
      "Mediana Indicio (ms)",
      "Delta mediana (ms)",
      "Delta mediana %",
      "Média von (ms)",
      "Média Indicio (ms)",
      "Delta média (ms)",
      "Delta média %",
      "P95 von (ms)",
      "P95 Indicio (ms)",
      "Delta P95 (ms)",
      "Delta P95 %",
    ],
    rows.map((row) => [
      row.label,
      row.von_ok,
      row.indicio_ok,
      row.von_median_ms,
      row.indicio_median_ms,
      row.delta_median_ms,
      row.delta_median_percent,
      row.von_mean_ms,
      row.indicio_mean_ms,
      row.delta_mean_ms,
      row.delta_mean_percent,
      row.von_p95_ms,
      row.indicio_p95_ms,
      row.delta_p95_ms,
      row.delta_p95_percent,
    ])
  ));

  const markdownPath = path.join(outputDir, "ledger-ops-comparison.md");
  const jsonPath = path.join(outputDir, "ledger-ops-comparison.json");
  const csvPath = path.join(outputDir, "ledger-ops-comparison.csv");
  fs.writeFileSync(markdownPath, `${sections.join("\n")}\n`, "utf-8");
  writeJson(jsonPath, comparison);
  writeCsv(csvPath, rows);
  writeJson(path.join(DEFAULT_RESULTS_ROOT, "latest-ledger-ops-comparison.json"), {
    generatedAt: comparison.generatedAt,
    outputDir,
    markdown: markdownPath,
    summary: jsonPath,
    csv: csvPath,
    vonSummary: options.vonSummary,
    indicioSummary: options.indicioSummary,
  });
  console.log(`Comparativo gerado em ${markdownPath}`);
}

function runAll(options) {
  ensureDirSync(options.outputDir);
  const networks = [
    {
      label: "von-network",
      config: options.vonConfig,
      outputDir: path.join(options.outputDir, "von-network"),
    },
    {
      label: "Indicio",
      config: options.indicioConfig,
      outputDir: path.join(options.outputDir, "indicio"),
    },
  ];

  for (const network of networks) {
    const args = [
      __filename,
      "run-network",
      "--network",
      network.label,
      "--config",
      network.config,
      "--iterations",
      String(options.iterations),
      "--output-dir",
      network.outputDir,
    ];
    const result = spawnSync(process.execPath, args, {
      cwd: PROJECT_ROOT,
      stdio: "inherit",
    });
    if (result.error) throw result.error;
    if (result.status !== 0) {
      throw new Error(`Benchmark da rede ${network.label} falhou com exit code ${result.status}.`);
    }
  }

  buildComparison({
    outputDir: options.outputDir,
    vonSummary: path.join(options.outputDir, "von-network", "ledger-ops-summary.json"),
    indicioSummary: path.join(options.outputDir, "indicio", "ledger-ops-summary.json"),
  });
}

async function main() {
  const options = parseCliArgs(process.argv.slice(2));
  if (options.command === "all") {
    runAll(options);
    return;
  }
  if (options.command === "run-network") {
    await runNetwork(options);
    return;
  }
  if (options.command === "compare") {
    buildComparison(options);
    return;
  }
  throw new Error(`Comando desconhecido: ${options.command}`);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err?.stack || err?.message || err);
    process.exitCode = 1;
  });
}
