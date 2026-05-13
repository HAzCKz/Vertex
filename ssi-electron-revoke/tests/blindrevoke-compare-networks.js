#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

const {
  ensureDirSync,
  round,
  timestampTag,
  writeJson,
} = require("./benchmarks/utils");

const PROJECT_ROOT = path.resolve(__dirname, "..");
const DEFAULT_RESULTS_ROOT = path.join(PROJECT_ROOT, "tests", "results");
const RUN_DIR_RE = /^blindrevoke-bench-(\d{8}-\d{6})$/;

const TABLES = [
  {
    file: "table-1-issue.csv",
    title: "Tabela 1. Emissão da Credencial Revogável",
    keyColumns: ["janelas"],
  },
  {
    file: "table-2-verify.csv",
    title: "Tabela 2. Latência de Verificação",
    keyColumns: ["janelas", "cenario"],
  },
  {
    file: "table-3-false-positive.csv",
    title: "Tabela 3. Falso Positivo",
    keyColumns: [],
  },
  {
    file: "table-4-proof-size.csv",
    title: "Tabela 4. Tamanho do Pacote Completo de Apresentação",
    keyColumns: ["janelas_validas"],
  },
  {
    file: "table-4b-proof-diagnostics.csv",
    title: "Tabela 4B. Decomposição Diagnóstica da Prova Revogável",
    keyColumns: ["janelas_validas"],
  },
  {
    file: "table-5-throughput.csv",
    title: "Tabela 5. Throughput do Bloom",
    keyColumns: ["amostras", "janelas_por_credencial", "janela_revogacao"],
  },
  {
    file: "table-5b-k-vector-ledger-write.csv",
    title: "Tabela 5B. Tempo de Registro do Vetor K no Ledger",
    keyColumns: ["chunk_size_solicitado"],
  },
  {
    file: "table-6-issuer-revocation.csv",
    title: "Tabela 6. Tempo de Revogação da Credencial pelo Issuer",
    keyColumns: ["janelas", "cenario"],
  },
  {
    file: "table-7-proof-size-delivered.csv",
    title: "Tabela 7. Tamanho do Pacote de Apresentação com Entrega Parcial de Janelas",
    keyColumns: ["janelas_validas"],
  },
];

function parseCliArgs(argv) {
  const out = {
    resultsRoot: DEFAULT_RESULTS_ROOT,
    vonRoot: "",
    indicioRoot: "",
    outputDir: "",
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--results-root") {
      out.resultsRoot = resolveFromProject(argv[i + 1] || out.resultsRoot);
      i += 1;
      continue;
    }
    if (arg === "--von-root") {
      out.vonRoot = resolveFromProject(argv[i + 1] || "");
      i += 1;
      continue;
    }
    if (arg === "--indicio-root") {
      out.indicioRoot = resolveFromProject(argv[i + 1] || "");
      i += 1;
      continue;
    }
    if (arg === "--output-dir") {
      out.outputDir = resolveFromProject(argv[i + 1] || "");
      i += 1;
      continue;
    }
    if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    }
    throw new Error(`Argumento desconhecido: ${arg}`);
  }

  out.resultsRoot = resolveFromProject(out.resultsRoot);
  out.vonRoot = out.vonRoot || out.resultsRoot;
  out.indicioRoot = out.indicioRoot || path.join(out.resultsRoot, "indicio");
  out.outputDir = out.outputDir || path.join(out.resultsRoot, `network-comparison-${timestampTag()}`);
  return out;
}

function resolveFromProject(inputPath) {
  if (!inputPath) return "";
  if (path.isAbsolute(inputPath)) return inputPath;
  return path.resolve(PROJECT_ROOT, inputPath);
}

function printHelp() {
  console.log([
    "Uso: node tests/blindrevoke-compare-networks.js [opções]",
    "",
    "Opções:",
    "  --results-root <dir>   Raiz dos resultados. Padrão: tests/results",
    "  --von-root <dir>       Pasta onde ficam os runs da von-network. Padrão: <results-root>",
    "  --indicio-root <dir>   Pasta onde ficam os runs da Indicio. Padrão: <results-root>/indicio",
    "  --output-dir <dir>     Pasta de saída do comparativo.",
  ].join("\n"));
}

function findLatestRun(rootDir, networkLabel) {
  if (!fs.existsSync(rootDir)) {
    throw new Error(`Pasta de resultados da ${networkLabel} não encontrada: ${rootDir}`);
  }

  const runs = fs.readdirSync(rootDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => {
      const match = RUN_DIR_RE.exec(entry.name);
      if (!match) return null;

      const outputRoot = path.join(rootDir, entry.name);
      const reportDir = path.join(outputRoot, "report");
      const paperSummary = path.join(reportDir, "paper-summary.md");
      if (!fs.existsSync(paperSummary)) return null;

      const stat = fs.statSync(outputRoot);
      return {
        name: entry.name,
        tag: match[1],
        outputRoot,
        reportDir,
        paperSummary,
        mtimeMs: stat.mtimeMs,
      };
    })
    .filter(Boolean)
    .sort((a, b) => {
      const byTag = b.tag.localeCompare(a.tag);
      if (byTag !== 0) return byTag;
      return b.mtimeMs - a.mtimeMs;
    });

  if (runs.length === 0) {
    throw new Error(`Nenhum run com report/paper-summary.md encontrado para ${networkLabel} em ${rootDir}`);
  }

  return runs[0];
}

function parseCsv(text) {
  if (!String(text || "").trim()) return [];

  const records = [];
  let row = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    const next = text[i + 1];

    if (ch === "\"") {
      if (inQuotes && next === "\"") {
        field += "\"";
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (ch === "," && !inQuotes) {
      row.push(field);
      field = "";
      continue;
    }

    if ((ch === "\n" || ch === "\r") && !inQuotes) {
      if (ch === "\r" && next === "\n") i += 1;
      row.push(field);
      if (row.some((value) => value !== "")) records.push(row);
      row = [];
      field = "";
      continue;
    }

    field += ch;
  }

  row.push(field);
  if (row.some((value) => value !== "")) records.push(row);
  if (records.length === 0) return [];

  const headers = records[0];
  return records.slice(1).map((record) => {
    const obj = {};
    headers.forEach((header, index) => {
      obj[header] = record[index] ?? "";
    });
    return obj;
  });
}

function readCsv(filePath) {
  return parseCsv(fs.readFileSync(filePath, "utf-8"));
}

function readJsonIfExists(filePath) {
  if (!fs.existsSync(filePath)) return null;
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
  } catch (_) {
    return null;
  }
}

function getHeaders(rows) {
  return Array.from(
    rows.reduce((acc, row) => {
      Object.keys(row || {}).forEach((key) => acc.add(key));
      return acc;
    }, new Set())
  );
}

function makeRowKey(row, keyColumns, index) {
  if (!Array.isArray(keyColumns) || keyColumns.length === 0) return `linha ${index + 1}`;
  return keyColumns.map((key) => `${key}=${formatCell(row?.[key])}`).join("; ");
}

function indexRows(rows, keyColumns) {
  const map = new Map();
  rows.forEach((row, index) => {
    const key = makeRowKey(row, keyColumns, index);
    map.set(key, { row, index });
  });
  return map;
}

function numericValue(value) {
  const text = String(value ?? "").trim();
  if (!text) return null;
  if (!/^-?(?:\d+|\d*\.\d+)(?:e[+-]?\d+)?$/i.test(text)) return null;
  const num = Number(text);
  return Number.isFinite(num) ? num : null;
}

function formatNumber(value, decimals = 6) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "-";
  const rounded = round(n, decimals);
  if (rounded === null) return "-";
  return String(rounded);
}

function formatDurationMs(value) {
  if (value === undefined || value === null || value === "") return "-";
  const ms = Number(value);
  if (!Number.isFinite(ms) || ms < 0) return "-";
  if (ms < 1000) return `${formatNumber(ms, 3)} ms`;

  const totalSeconds = Math.floor(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  const milliseconds = Math.floor(ms % 1000);
  const hh = String(hours).padStart(2, "0");
  const mm = String(minutes).padStart(2, "0");
  const ss = String(seconds).padStart(2, "0");
  const mmm = String(milliseconds).padStart(3, "0");

  if (hours > 0) return `${hh}:${mm}:${ss}.${mmm}`;
  return `${mm}:${ss}.${mmm}`;
}

function formatCell(value) {
  if (value === undefined || value === null || value === "") return "-";
  return String(value).replace(/\|/g, "\\|");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function compareValues(vonValue, indicioValue) {
  const vonNumber = numericValue(vonValue);
  const indicioNumber = numericValue(indicioValue);

  if (vonNumber !== null && indicioNumber !== null) {
    const delta = indicioNumber - vonNumber;
    const percent = vonNumber === 0
      ? (delta === 0 ? "0%" : "-")
      : `${formatNumber((delta / vonNumber) * 100, 2)}%`;
    return {
      same: delta === 0,
      delta: formatNumber(delta),
      percent,
      numeric: true,
      deltaNumber: delta,
      percentNumber: vonNumber === 0 ? null : (delta / vonNumber) * 100,
    };
  }

  const same = String(vonValue ?? "") === String(indicioValue ?? "");
  return {
    same,
    delta: same ? "igual" : "diferente",
    percent: "-",
    numeric: false,
    deltaNumber: null,
    percentNumber: null,
  };
}

function buildComparisonRows(table, vonRows, indicioRows) {
  const vonHeaders = getHeaders(vonRows);
  const indicioHeaders = getHeaders(indicioRows);
  const headers = Array.from(new Set([...vonHeaders, ...indicioHeaders]));
  const keyColumns = table.keyColumns || [];
  const compareColumns = headers.filter((header) => !keyColumns.includes(header));
  const vonByKey = indexRows(vonRows, keyColumns);
  const indicioByKey = indexRows(indicioRows, keyColumns);
  const allKeys = Array.from(new Set([...vonByKey.keys(), ...indicioByKey.keys()]));

  return allKeys.flatMap((key) => {
    const von = vonByKey.get(key)?.row || null;
    const indicio = indicioByKey.get(key)?.row || null;

    if (!von || !indicio) {
      return [{
        key,
        metric: "_linha_",
        vonValue: von ? "presente" : "-",
        indicioValue: indicio ? "presente" : "-",
        delta: von && indicio ? "igual" : "ausente",
        percent: "-",
        same: Boolean(von && indicio),
        numeric: false,
      }];
    }

    return compareColumns.map((metric) => {
      const comparison = compareValues(von[metric], indicio[metric]);
      return {
        key,
        metric,
        vonValue: formatCell(von[metric]),
        indicioValue: formatCell(indicio[metric]),
        delta: comparison.delta,
        percent: comparison.percent,
        same: comparison.same,
        numeric: comparison.numeric,
        deltaNumber: comparison.deltaNumber,
        percentNumber: comparison.percentNumber,
      };
    });
  });
}

function summarizeComparison(rows) {
  return rows.reduce((acc, row) => {
    acc.compared += 1;
    if (row.same) {
      acc.same += 1;
    } else if (row.numeric) {
      acc.numericDifferent += 1;
    } else {
      acc.textDifferent += 1;
    }
    return acc;
  }, {
    compared: 0,
    same: 0,
    numericDifferent: 0,
    textDifferent: 0,
  });
}

function markdownTable(headers, rows) {
  if (!rows.length) return "Sem dados.\n";
  const tableStyle = "border-collapse: collapse; width: 100%; margin: 12px 0;";
  const headerStyle = "border: 1px solid #444; padding: 6px 8px; background: #f2f2f2; text-align: left;";
  const cellStyle = "border: 1px solid #444; padding: 6px 8px; vertical-align: top;";
  const lines = [
    `<table border="1" cellspacing="0" cellpadding="6" style="${tableStyle}">`,
    "  <thead>",
    `    <tr>${headers.map((header) => `<th style="${headerStyle}">${escapeHtml(header)}</th>`).join("")}</tr>`,
    "  </thead>",
    "  <tbody>",
    ...rows.map((row) => (
      `    <tr>${row.map((cell) => `<td style="${cellStyle}">${escapeHtml(formatCell(cell))}</td>`).join("")}</tr>`
    )),
    "  </tbody>",
    "</table>",
  ];
  return `${lines.join("\n")}\n\n`;
}

function buildMetadata(run, label) {
  const index = readJsonIfExists(path.join(run.reportDir, "report-index.json"));
  return {
    label,
    outputRoot: run.outputRoot,
    reportDir: run.reportDir,
    paperSummary: run.paperSummary,
    totalElapsedMs: index?.totalElapsedMs ?? null,
    totalElapsedLabel: index?.totalElapsedLabel ?? "-",
  };
}

function buildReport(options, vonRun, indicioRun) {
  const generatedAt = new Date().toISOString();
  const vonMeta = buildMetadata(vonRun, "von-network");
  const indicioMeta = buildMetadata(indicioRun, "Indicio");
  const sections = [];
  const machineSummary = {
    generatedAt,
    outputDir: options.outputDir,
    networks: {
      vonNetwork: vonMeta,
      indicio: indicioMeta,
    },
    tables: [],
  };

  const elapsedComparison = compareValues(vonMeta.totalElapsedMs, indicioMeta.totalElapsedMs);
  sections.push("# Comparativo BlindRevoke: von-network x Indicio");
  sections.push("");
  sections.push(`- Gerado em: ${generatedAt}`);
  sections.push(`- von-network: ${vonMeta.outputRoot}`);
  sections.push(`- Indicio: ${indicioMeta.outputRoot}`);
  sections.push("- Delta: Indicio - von-network.");
  sections.push("");
  sections.push("## Relatórios usados");
  sections.push(markdownTable(
    ["Rede", "Tempo total", "Total (ms)", "paper-summary.md"],
    [
      ["von-network", vonMeta.totalElapsedLabel, vonMeta.totalElapsedMs ?? "-", vonMeta.paperSummary],
      ["Indicio", indicioMeta.totalElapsedLabel, indicioMeta.totalElapsedMs ?? "-", indicioMeta.paperSummary],
    ]
  ));
  sections.push(markdownTable(
    ["Métrica", "Delta", "Delta %"],
    [["Tempo total", formatDurationMs(elapsedComparison.deltaNumber), elapsedComparison.percent]]
  ));

  const summaryRows = [];
  const tableSections = [];

  for (const table of TABLES) {
    const vonCsv = path.join(vonRun.reportDir, table.file);
    const indicioCsv = path.join(indicioRun.reportDir, table.file);

    if (!fs.existsSync(vonCsv) || !fs.existsSync(indicioCsv)) {
      const missing = [
        fs.existsSync(vonCsv) ? "" : "von-network",
        fs.existsSync(indicioCsv) ? "" : "Indicio",
      ].filter(Boolean).join(", ");
      summaryRows.push([table.title, "-", "-", "-", `CSV ausente: ${missing}`]);
      machineSummary.tables.push({
        file: table.file,
        title: table.title,
        missing,
      });
      tableSections.push(`## ${table.title}\n\nCSV ausente: ${missing}.\n`);
      continue;
    }

    const vonRows = readCsv(vonCsv);
    const indicioRows = readCsv(indicioCsv);
    const comparisonRows = buildComparisonRows(table, vonRows, indicioRows);
    const summary = summarizeComparison(comparisonRows);
    summaryRows.push([
      table.title,
      summary.compared,
      summary.same,
      summary.numericDifferent,
      summary.textDifferent,
    ]);
    machineSummary.tables.push({
      file: table.file,
      title: table.title,
      rowsCompared: summary.compared,
      equalValues: summary.same,
      numericDifferences: summary.numericDifferent,
      textDifferences: summary.textDifferent,
    });

    tableSections.push(`## ${table.title}`);
    tableSections.push("");
    tableSections.push(markdownTable(
      ["Chave", "Métrica", "von-network", "Indicio", "Delta", "Delta %"],
      comparisonRows.map((row) => [
        row.key,
        row.metric,
        row.vonValue,
        row.indicioValue,
        row.delta,
        row.percent,
      ])
    ));
  }

  sections.push("## Resumo das comparações");
  sections.push(markdownTable(
    ["Tabela", "Valores comparados", "Iguais", "Dif. numéricas", "Dif. texto/status"],
    summaryRows
  ));
  sections.push(...tableSections);

  return {
    markdown: `${sections.join("\n")}\n`,
    summary: machineSummary,
  };
}

function main() {
  const options = parseCliArgs(process.argv.slice(2));
  const vonRun = findLatestRun(options.vonRoot, "von-network");
  const indicioRun = findLatestRun(options.indicioRoot, "Indicio");
  const report = buildReport(options, vonRun, indicioRun);

  ensureDirSync(options.outputDir);
  const markdownPath = path.join(options.outputDir, "network-comparison.md");
  const summaryPath = path.join(options.outputDir, "network-comparison.json");
  fs.writeFileSync(markdownPath, report.markdown, "utf-8");
  writeJson(summaryPath, report.summary);
  writeJson(path.join(options.resultsRoot, "latest-network-comparison.json"), {
    generatedAt: report.summary.generatedAt,
    outputDir: options.outputDir,
    markdown: markdownPath,
    summary: summaryPath,
    vonNetworkRun: vonRun.outputRoot,
    indicioRun: indicioRun.outputRoot,
  });

  console.log(`Comparativo gerado em ${markdownPath}`);
}

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error(err?.message || err);
    process.exitCode = 1;
  }
}
