#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

const ssi = require("../src/main/ssi/ssi-api");
const {
  byteLengthUtf8,
  ensureDirSync,
  firstNonEmpty,
  measureAsync,
  parseMaybeJson,
  resolvePathFrom,
  round,
  sha256Base64,
  summarizeNumbers,
  timestampTag,
  writeCsv,
  writeJson,
} = require("./benchmarks/utils");

const DEFAULT_TRUSTEE_DID = "V4SGRU86Z58d6TV7PBUe6f";
const DEFAULT_EXTRA_WINDOWS_FOR_FP = 10;
const DEFAULT_BINARY_THRESHOLD = 50;
const DEFAULT_VERIFY_CONCURRENCY = 8;
const DEFAULT_TAIL_CONFIRMATION_WINDOWS = 11;
const REVOCATION_ACTIVE_K_ATTR_KEY = "REVOCATION_K_ACTIVE";
const REQUIRED_REVOCATION_CONTROL_ATTRIBUTES = [
  "seed",
  "start_time",
  "unit_of_time",
  "time_window",
  "root_merkle_L",
];

function getDominantValue(values) {
  const counts = new Map();
  for (const value of values || []) {
    const key = firstNonEmpty(value, "unknown");
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  let bestKey = "";
  let bestCount = -1;
  for (const [key, count] of counts.entries()) {
    if (count > bestCount) {
      bestKey = key;
      bestCount = count;
    }
  }
  return bestKey || null;
}

function withRequiredRevocationControlAttributes(attrNames) {
  const seen = new Set();
  const out = [];
  for (const attr of Array.isArray(attrNames) ? attrNames : []) {
    const normalized = String(attr || "").trim();
    if (!normalized) continue;
    const key = normalized.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(normalized);
  }
  for (const attr of REQUIRED_REVOCATION_CONTROL_ATTRIBUTES) {
    const key = attr.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(attr);
  }
  return out;
}

function formatReportValue(value) {
  if (value === undefined || value === null || value === "") return "-";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return "-";
    return String(value);
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  return String(value);
}

function formatDurationMs(value) {
  const ms = Number(value);
  if (!Number.isFinite(ms) || ms < 0) return "-";
  if (ms < 1000) return `${round(ms)} ms`;

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

function formatChunkSizeLabel(value) {
  if (value === undefined || value === null || value === "") return "default";
  const numeric = Number(value);
  if (!Number.isInteger(numeric) || numeric <= 0) return "default";
  return String(numeric);
}

function normalizeKVectorChunkSizeList(config) {
  const rawList = Array.isArray(config?.chunkSizeBytesList)
    ? config.chunkSizeBytesList
    : [config?.chunkSizeBytes ?? null];
  const normalized = [];
  const seen = new Set();

  for (const value of rawList) {
    let next = null;
    if (!(value === undefined || value === null || value === "")) {
      const numeric = Number(value);
      if (!Number.isInteger(numeric) || numeric <= 0) continue;
      next = numeric;
    }
    const key = formatChunkSizeLabel(next);
    if (seen.has(key)) continue;
    seen.add(key);
    normalized.push(next);
  }

  return normalized.length > 0 ? normalized : [null];
}

function estimateKVectorAttribWrites(ledgerAnchor) {
  if (!ledgerAnchor || typeof ledgerAnchor !== "object" || Array.isArray(ledgerAnchor)) return null;
  let total = Math.max(0, Math.trunc(Number(ledgerAnchor.chunk_count) || 0));

  // Inferimos um ATTRIB para o índice e outro para o ponteiro ativo do emissor.
  if (firstNonEmpty(ledgerAnchor.index_key)) total += 1;
  if (firstNonEmpty(ledgerAnchor.k_vector_id)) total += 1;

  return total > 0 ? total : null;
}

function markdownTable(rows, columns) {
  const headers = columns.map((col) => col.label);
  const lines = [
    `| ${headers.join(" | ")} |`,
    `| ${columns.map(() => "---").join(" | ")} |`,
  ];
  for (const row of rows || []) {
    const cells = columns.map((col) => {
      const raw = typeof col.value === "function" ? col.value(row) : row?.[col.key];
      return formatReportValue(raw).replace(/\|/g, "\\|");
    });
    lines.push(`| ${cells.join(" | ")} |`);
  }
  return `${lines.join("\n")}\n`;
}

function buildReportSection(title, rows, columns) {
  if (!Array.isArray(rows) || rows.length === 0) return `## ${title}\n\nSem dados.\n`;
  return `## ${title}\n\n${markdownTable(rows, columns)}\n`;
}

function buildIssueReportRows(issueResult) {
  return (issueResult?.rows || []).map((row) => ({
    janelas: row.windowCountRequested,
    experimentos: row.experimentCount,
    janelas_validas: row.baseWindowCount,
    janelas_confirmacao: row.confirmationWindowCount,
    tempo_emissao_ms: row.issueElapsedMs,
    envelope_holder_bytes: row.holderEnvelopeBytes,
    holder_bundle_bytes: row.holderBundleBytes,
    manifesto_bytes: row.manifestBytes,
    chunk_count: row.chunkCount,
  }));
}

function buildVerifyReportRows(verifyResult) {
  return (verifyResult?.rows || []).map((row) => ({
    janelas: row.windowCountRequested,
    cenario: row.scenario,
    experimentos: row.verifyRunCount,
    warmups: row.warmupRunCount,
    revogada_na_janela: row.revokedWindowIndex,
    latencia_mediana_ms: row.medianLatencyMs,
    latencia_p95_ms: row.p95LatencyMs,
    janelas_consultadas_mediana: row.medianScannedWindows,
    modo_dominante: row.dominantMode,
    decisoes: row.decisionHistogram,
  }));
}

function buildFalsePositiveReportRows(falsePositiveResult) {
  if (!falsePositiveResult) return [];
  return [{
    status: falsePositiveResult.skipped ? "skipped" : "ok",
    manifesto: falsePositiveResult.manifestUrl,
    motivo: falsePositiveResult.skipReason || null,
    fillers: falsePositiveResult.fillerCount,
    testes: falsePositiveResult.targetCount,
    fps_observados: falsePositiveResult.observedFalsePositives,
    taxa_fp_observada: falsePositiveResult.observedFalsePositiveRate,
    fps_escaparam: falsePositiveResult.escapedFalsePositives,
    taxa_fp_escaparam: falsePositiveResult.escapedFalsePositiveRate,
    latencia_mediana_ms: falsePositiveResult.latencyMs?.median,
    janelas_consultadas_mediana: falsePositiveResult.scannedWindows?.median,
  }];
}

function buildProofSizeReportRows(proofResult) {
  return (proofResult?.rows || []).map((row) => ({
    janelas_validas: row.baseWindowCount,
    experimentos: row.experimentCount,
    janelas_extras_fp: row.confirmationWindowCount,
    janelas_totais_pacote: row.totalWindowCount,
    tempo_total_montagem_ms: row.buildElapsedMs,
    tempo_prova_revogavel_ms: row.packageBuildElapsedMs,
    tempo_serializacao_payload_ms: row.payloadSerializeElapsedMs,
    tempo_criptografia_envelope_ms: row.envelopeEncryptElapsedMs,
    payload_apresentacao_bytes: row.presentationPayloadBytes,
    envelope_criptografado_bytes: row.encryptedEnvelopeBytes,
  }));
}

function buildProofDeliveredReportRows(proofResult) {
  return (proofResult?.deliveredRows || []).map((row) => ({
    janelas_validas: row.baseWindowCount,
    experimentos: row.experimentCount,
    janelas_extras_fp: row.confirmationWindowCount,
    janelas_entregues_verificador: row.deliveredWindowCount,
    tempo_total_montagem_ms: row.buildElapsedMs,
    tempo_prova_revogavel_ms: row.packageBuildElapsedMs,
    tempo_serializacao_payload_ms: row.payloadSerializeElapsedMs,
    tempo_criptografia_envelope_ms: row.envelopeEncryptElapsedMs,
    payload_apresentacao_bytes: row.presentationPayloadBytes,
    envelope_criptografado_bytes: row.encryptedEnvelopeBytes,
  }));
}

function buildProofDiagnosticsReportRows(proofResult) {
  return (proofResult?.rows || []).map((row) => ({
    janelas_validas: row.baseWindowCount,
    experimentos: row.experimentCount,
    janelas_totais_pacote: row.totalWindowCount,
    apresentacao_anoncreds_ms: row.anoncredsPresentationElapsedMs,
    primary_proof_ms: row.primaryProofOnlyElapsedMs,
    sequencia_revogacao_total_ms: row.fullProofSequenceElapsedMs,
    confirmacoes_estimadas_ms: row.confirmationProofsEstimatedElapsedMs,
  }));
}

function buildThroughputReportRows(throughputResult) {
  if (!throughputResult) return [];
  return [{
    amostras: throughputResult.sampleCredentialCount,
    janelas_por_credencial: throughputResult.sampleWindowCount,
    janela_revogacao: throughputResult.revokeFromWindow,
    escritas_por_credencial: throughputResult.writesPerCredential?.median,
    escrita_ops_s: throughputResult.writeOpsPerSecond,
    leitura_ops_s: throughputResult.readOpsPerSecond,
    escrita_mediana_ms: throughputResult.writeLatencyMs?.median,
    leitura_mediana_ms: throughputResult.readLatencyMs?.median,
  }];
}

function buildKVectorLedgerWriteReportRows(kVectorLedgerResult) {
  return (kVectorLedgerResult?.rows || []).map((row) => ({
    chunk_size_solicitado: row.requestedChunkSizeLabel,
    experimentos: row.experimentCount,
    escritas_k: row.writeCount,
    k_reutilizados: row.reusedExistingCount,
    status: row.status,
    registro_k_ms: row.writeElapsedMs,
    setup_k_ms: row.setupCreateElapsedMs,
    attribs_estimados: row.estimatedAttribWrites,
    chunks_k: row.chunkCount,
    chunk_size_efetivo_bytes: row.effectiveChunkSizeBytes,
    total_k_bytes: row.totalBytes,
    valores_k: row.valueCount,
  }));
}

function buildIssuerRevocationReportRows(issuerRevocationResult) {
  return (issuerRevocationResult?.rows || []).map((row) => ({
    janelas: row.windowCountRequested,
    cenario: row.scenario,
    experimentos: row.experimentCount,
    janela_revogacao: row.revokeFromWindow,
    tempo_revogacao_ms: row.elapsedMs,
    chaves_esperadas: row.expectedKeysToWrite,
    chaves_escritas: row.actualKeysWritten,
  }));
}

function normalizeReportInput(result) {
  if (result && typeof result === "object" && typeof result.benchmark === "string") {
    return {
      [result.benchmark]: result,
    };
  }
  return result || {};
}

function buildExperimentSamplingNotes(ctx, normalizedResult) {
  const falsePositiveResult = normalizedResult["false-positive"] || {};
  const throughputResult = normalizedResult["bloom-throughput"] || {};
  const kVectorLedgerResult = normalizedResult["k-vector-ledger-write"] || {};
  const verifyResult = normalizedResult["verify-latency"] || {};
  const issueResult = normalizedResult["issue-metrics"] || {};
  const proofResult = normalizedResult["proof-payload-size"] || {};
  const issuerRevocationResult = normalizedResult["issuer-revocation"] || {};

  const issueIterations = Number(issueResult.iterations ?? ctx.config.issueIterations ?? 1);
  const verifyIterations = Number(verifyResult.iterations ?? ctx.config.verifyIterations ?? 5);
  const verifyWarmups = Number(verifyResult.warmupIterations ?? ctx.config.verifyWarmups ?? 1);
  const falsePositiveTrials = Number(falsePositiveResult.targetCount ?? ctx.config.falsePositive?.trialCredentialCount ?? 20);
  const falsePositiveFillers = Number(falsePositiveResult.fillerCount ?? ctx.config.falsePositive?.fillerCredentialCount ?? 0);
  const proofIterations = Number(proofResult.iterations ?? ctx.config.proofIterations ?? 1);
  const throughputSamples = Number(throughputResult.sampleCredentialCount ?? ctx.config.throughput?.sampleCredentialCount ?? 20);
  const kVectorLedgerIterations = Number(kVectorLedgerResult.iterations ?? ctx.config.kVectorLedger?.iterations ?? 1);
  const issuerRevocationIterations = Number(issuerRevocationResult.iterations ?? ctx.config.issuerRevocationIterations ?? 1);

  return [
    "## Amostragem dos Experimentos",
    "",
    `- Tabela 1: ${issueIterations} emissão(ões) por configuração de janelas.`,
    `- Tabela 2: ${verifyIterations} verificação(ões) medidas por linha, com ${verifyWarmups} aquecimento(s) não contabilizado(s).`,
    `- Tabela 3: ${falsePositiveTrials} teste(s) em credenciais-alvo, com ${falsePositiveFillers} filler(s) revogado(s).`,
    `- Tabelas 4, 4B e 7: ${proofIterations} montagem(ens) por configuração de janelas.`,
    `- Tabela 5: ${throughputSamples} amostra(s) de credencial para escrita e ${throughputSamples} para leitura.`,
    `- Tabela 5B: ${kVectorLedgerIterations} registro(s) do vetor K por configuração de chunk.`,
    `- Tabela 6: ${issuerRevocationIterations} revogação(ões) por linha.`,
    "",
  ].join("\n");
}

function writeReportArtifacts(ctx, result) {
  const normalizedResult = normalizeReportInput(result);
  const reportDir = path.join(ctx.outputRoot, "report");
  ensureDirSync(reportDir);
  const totalElapsedMs = Number(ctx.runMetrics?.totalElapsedMs || 0);
  const stageProgress = Array.isArray(ctx.runMetrics?.stageProgress) ? ctx.runMetrics.stageProgress : [];

  const issueRows = buildIssueReportRows(normalizedResult["issue-metrics"]);
  const verifyRows = buildVerifyReportRows(normalizedResult["verify-latency"]);
  const falsePositiveRows = buildFalsePositiveReportRows(normalizedResult["false-positive"]);
  const proofRows = buildProofSizeReportRows(normalizedResult["proof-payload-size"]);
  const proofDeliveredRows = buildProofDeliveredReportRows(normalizedResult["proof-payload-size"]);
  const proofDiagnosticRows = buildProofDiagnosticsReportRows(normalizedResult["proof-payload-size"]);
  const throughputRows = buildThroughputReportRows(normalizedResult["bloom-throughput"]);
  const kVectorLedgerRows = buildKVectorLedgerWriteReportRows(normalizedResult["k-vector-ledger-write"]);
  const issuerRevocationRows = buildIssuerRevocationReportRows(normalizedResult["issuer-revocation"]);
  const experimentSamplingNotes = buildExperimentSamplingNotes(ctx, normalizedResult);

  const sections = [
    "# BlindRevoke Experimental Summary",
    "",
    `- Generated at: ${new Date().toISOString()}`,
    `- Config: ${ctx.config._configPath}`,
    `- Output: ${ctx.outputRoot}`,
    `- Default filter profile: ${firstNonEmpty(ctx.config.filterProfiles?.default?.label, "default")}`,
    `- Tempo total de processamento: ${formatDurationMs(totalElapsedMs)}`,
    "",
    experimentSamplingNotes,
    buildReportSection("Tabela 1. Emissão da Credencial Revogável", issueRows, [
      { label: "Janelas", key: "janelas" },
      { label: "Experimentos", key: "experimentos" },
      { label: "Janelas válidas", key: "janelas_validas" },
      { label: "Confirmação", key: "janelas_confirmacao" },
      { label: "Emissão (ms)", key: "tempo_emissao_ms" },
      { label: "Envelope Holder (bytes)", key: "envelope_holder_bytes" },
      { label: "Bundle (bytes)", key: "holder_bundle_bytes" },
      { label: "Manifesto (bytes)", key: "manifesto_bytes" },
      { label: "Chunks K", key: "chunk_count" },
    ]),
    buildReportSection("Tabela 2. Latência de Verificação", verifyRows, [
      { label: "Janelas", key: "janelas" },
      { label: "Cenário", key: "cenario" },
      { label: "Experimentos", key: "experimentos" },
      { label: "Warmups", key: "warmups" },
      { label: "Janela revogação", key: "revogada_na_janela" },
      { label: "Mediana (ms)", key: "latencia_mediana_ms" },
      { label: "P95 (ms)", key: "latencia_p95_ms" },
      { label: "Janelas consultadas", key: "janelas_consultadas_mediana" },
      { label: "Modo dominante", key: "modo_dominante" },
    ]),
    buildReportSection("Tabela 3. Falso Positivo", falsePositiveRows, [
      { label: "Status", key: "status" },
      { label: "Manifesto", key: "manifesto" },
      { label: "Motivo", key: "motivo" },
      { label: "Fillers", key: "fillers" },
      { label: "Testes", key: "testes" },
      { label: "FP observados", key: "fps_observados" },
      { label: "Taxa FP", key: "taxa_fp_observada" },
      { label: "FP escaparam", key: "fps_escaparam" },
      { label: "Taxa escaparam", key: "taxa_fp_escaparam" },
      { label: "Latência mediana (ms)", key: "latencia_mediana_ms" },
    ]),
    buildReportSection("Tabela 4. Tamanho do Pacote Completo de Apresentação", proofRows, [
      { label: "Janelas válidas", key: "janelas_validas" },
      { label: "Experimentos", key: "experimentos" },
      { label: "Janelas extras FP", key: "janelas_extras_fp" },
      { label: "Janelas totais no pacote", key: "janelas_totais_pacote" },
      { label: "Total (ms)", key: "tempo_total_montagem_ms" },
      { label: "Prova revogável (ms)", key: "tempo_prova_revogavel_ms" },
      { label: "Serialização payload (ms)", key: "tempo_serializacao_payload_ms" },
      { label: "Authcrypt envelope (ms)", key: "tempo_criptografia_envelope_ms" },
      { label: "Payload apresentação (bytes)", key: "payload_apresentacao_bytes" },
      { label: "Envelope criptografado (bytes)", key: "envelope_criptografado_bytes" },
    ]),
    buildReportSection("Tabela 4B. Decomposição Diagnóstica da Prova Revogável", proofDiagnosticRows, [
      { label: "Janelas válidas", key: "janelas_validas" },
      { label: "Experimentos", key: "experimentos" },
      { label: "Janelas totais no pacote", key: "janelas_totais_pacote" },
      { label: "Apresentação anoncreds (ms)", key: "apresentacao_anoncreds_ms" },
      { label: "Primary proof (ms)", key: "primary_proof_ms" },
      { label: "Sequência revogável total (ms)", key: "sequencia_revogacao_total_ms" },
      { label: "Confirmações estimadas (ms)", key: "confirmacoes_estimadas_ms" },
    ]),
    buildReportSection("Tabela 5. Throughput do Bloom", throughputRows, [
      { label: "Amostras", key: "amostras" },
      { label: "Janelas/credencial", key: "janelas_por_credencial" },
      { label: "Janela revogação", key: "janela_revogacao" },
      { label: "Escritas/credencial", key: "escritas_por_credencial" },
      { label: "Escrita (ops/s)", key: "escrita_ops_s" },
      { label: "Leitura (ops/s)", key: "leitura_ops_s" },
      { label: "Escrita mediana (ms/op)", key: "escrita_mediana_ms" },
      { label: "Leitura mediana (ms)", key: "leitura_mediana_ms" },
    ]),
    buildReportSection("Tabela 5B. Tempo de Registro do Vetor K no Ledger", kVectorLedgerRows, [
      { label: "Chunk solicitado", key: "chunk_size_solicitado" },
      { label: "Experimentos", key: "experimentos" },
      { label: "Escritas K", key: "escritas_k" },
      { label: "K reutilizados", key: "k_reutilizados" },
      { label: "Status", key: "status" },
      { label: "Registro K (ms)", key: "registro_k_ms" },
      { label: "Setup K (ms)", key: "setup_k_ms" },
      { label: "ATTRIBs estimados", key: "attribs_estimados" },
      { label: "Chunks K", key: "chunks_k" },
      { label: "Chunk efetivo (bytes)", key: "chunk_size_efetivo_bytes" },
      { label: "Total K (bytes)", key: "total_k_bytes" },
      { label: "Valores K", key: "valores_k" },
    ]),
    buildReportSection("Tabela 6. Tempo de Revogação da Credencial pelo Issuer", issuerRevocationRows, [
      { label: "Janelas", key: "janelas" },
      { label: "Cenário", key: "cenario" },
      { label: "Experimentos", key: "experimentos" },
      { label: "Janela revogação", key: "janela_revogacao" },
      { label: "Revogação (ms)", key: "tempo_revogacao_ms" },
      { label: "Chaves esperadas", key: "chaves_esperadas" },
      { label: "Chaves escritas", key: "chaves_escritas" },
    ]),
    buildReportSection("Tabela 7. Tamanho do Pacote de Apresentação com Entrega Parcial de Janelas", proofDeliveredRows, [
      { label: "Janelas válidas", key: "janelas_validas" },
      { label: "Experimentos", key: "experimentos" },
      { label: "Janelas extras FP", key: "janelas_extras_fp" },
      { label: "Janelas entregues ao Verificador", key: "janelas_entregues_verificador" },
      { label: "Total (ms)", key: "tempo_total_montagem_ms" },
      { label: "Prova revogável (ms)", key: "tempo_prova_revogavel_ms" },
      { label: "Serialização payload (ms)", key: "tempo_serializacao_payload_ms" },
      { label: "Authcrypt envelope (ms)", key: "tempo_criptografia_envelope_ms" },
      { label: "Payload apresentação (bytes)", key: "payload_apresentacao_bytes" },
      { label: "Envelope criptografado (bytes)", key: "envelope_criptografado_bytes" },
    ]),
  ];

  fs.writeFileSync(path.join(reportDir, "paper-summary.md"), `${sections.join("\n")}\n`, "utf-8");

  writeCsv(path.join(reportDir, "table-1-issue.csv"), issueRows);
  writeCsv(path.join(reportDir, "table-2-verify.csv"), verifyRows);
  writeCsv(path.join(reportDir, "table-3-false-positive.csv"), falsePositiveRows);
  writeCsv(path.join(reportDir, "table-4-proof-size.csv"), proofRows);
  writeCsv(path.join(reportDir, "table-4b-proof-diagnostics.csv"), proofDiagnosticRows);
  writeCsv(path.join(reportDir, "table-5-throughput.csv"), throughputRows);
  writeCsv(path.join(reportDir, "table-5b-k-vector-ledger-write.csv"), kVectorLedgerRows);
  writeCsv(path.join(reportDir, "table-6-issuer-revocation.csv"), issuerRevocationRows);
  writeCsv(path.join(reportDir, "table-7-proof-size-delivered.csv"), proofDeliveredRows);

  fs.writeFileSync(
    path.join(reportDir, "table-1-issue.md"),
    markdownTable(issueRows, [
      { label: "Janelas", key: "janelas" },
      { label: "Experimentos", key: "experimentos" },
      { label: "Janelas válidas", key: "janelas_validas" },
      { label: "Confirmação", key: "janelas_confirmacao" },
      { label: "Emissão (ms)", key: "tempo_emissao_ms" },
      { label: "Envelope Holder (bytes)", key: "envelope_holder_bytes" },
      { label: "Bundle (bytes)", key: "holder_bundle_bytes" },
      { label: "Manifesto (bytes)", key: "manifesto_bytes" },
      { label: "Chunks K", key: "chunk_count" },
    ]),
    "utf-8"
  );
  fs.writeFileSync(
    path.join(reportDir, "table-2-verify.md"),
    markdownTable(verifyRows, [
      { label: "Janelas", key: "janelas" },
      { label: "Cenário", key: "cenario" },
      { label: "Experimentos", key: "experimentos" },
      { label: "Warmups", key: "warmups" },
      { label: "Janela revogação", key: "revogada_na_janela" },
      { label: "Mediana (ms)", key: "latencia_mediana_ms" },
      { label: "P95 (ms)", key: "latencia_p95_ms" },
      { label: "Janelas consultadas", key: "janelas_consultadas_mediana" },
      { label: "Modo dominante", key: "modo_dominante" },
    ]),
    "utf-8"
  );
  fs.writeFileSync(
    path.join(reportDir, "table-3-false-positive.md"),
    markdownTable(falsePositiveRows, [
      { label: "Status", key: "status" },
      { label: "Manifesto", key: "manifesto" },
      { label: "Motivo", key: "motivo" },
      { label: "Fillers", key: "fillers" },
      { label: "Testes", key: "testes" },
      { label: "FP observados", key: "fps_observados" },
      { label: "Taxa FP", key: "taxa_fp_observada" },
      { label: "FP escaparam", key: "fps_escaparam" },
      { label: "Taxa escaparam", key: "taxa_fp_escaparam" },
      { label: "Latência mediana (ms)", key: "latencia_mediana_ms" },
    ]),
    "utf-8"
  );
  fs.writeFileSync(
    path.join(reportDir, "table-4-proof-size.md"),
    markdownTable(proofRows, [
      { label: "Janelas válidas", key: "janelas_validas" },
      { label: "Experimentos", key: "experimentos" },
      { label: "Janelas extras FP", key: "janelas_extras_fp" },
      { label: "Janelas totais no pacote", key: "janelas_totais_pacote" },
      { label: "Total (ms)", key: "tempo_total_montagem_ms" },
      { label: "Prova revogável (ms)", key: "tempo_prova_revogavel_ms" },
      { label: "Serialização payload (ms)", key: "tempo_serializacao_payload_ms" },
      { label: "Authcrypt envelope (ms)", key: "tempo_criptografia_envelope_ms" },
      { label: "Payload apresentação (bytes)", key: "payload_apresentacao_bytes" },
      { label: "Envelope criptografado (bytes)", key: "envelope_criptografado_bytes" },
    ]),
    "utf-8"
  );
  fs.writeFileSync(
    path.join(reportDir, "table-4b-proof-diagnostics.md"),
    markdownTable(proofDiagnosticRows, [
      { label: "Janelas válidas", key: "janelas_validas" },
      { label: "Experimentos", key: "experimentos" },
      { label: "Janelas totais no pacote", key: "janelas_totais_pacote" },
      { label: "Apresentação anoncreds (ms)", key: "apresentacao_anoncreds_ms" },
      { label: "Primary proof (ms)", key: "primary_proof_ms" },
      { label: "Sequência revogável total (ms)", key: "sequencia_revogacao_total_ms" },
      { label: "Confirmações estimadas (ms)", key: "confirmacoes_estimadas_ms" },
    ]),
    "utf-8"
  );
  fs.writeFileSync(
    path.join(reportDir, "table-7-proof-size-delivered.md"),
    markdownTable(proofDeliveredRows, [
      { label: "Janelas válidas", key: "janelas_validas" },
      { label: "Experimentos", key: "experimentos" },
      { label: "Janelas extras FP", key: "janelas_extras_fp" },
      { label: "Janelas entregues ao Verificador", key: "janelas_entregues_verificador" },
      { label: "Total (ms)", key: "tempo_total_montagem_ms" },
      { label: "Prova revogável (ms)", key: "tempo_prova_revogavel_ms" },
      { label: "Serialização payload (ms)", key: "tempo_serializacao_payload_ms" },
      { label: "Authcrypt envelope (ms)", key: "tempo_criptografia_envelope_ms" },
      { label: "Payload apresentação (bytes)", key: "payload_apresentacao_bytes" },
      { label: "Envelope criptografado (bytes)", key: "envelope_criptografado_bytes" },
    ]),
    "utf-8"
  );
  fs.writeFileSync(
    path.join(reportDir, "table-5-throughput.md"),
    markdownTable(throughputRows, [
      { label: "Amostras", key: "amostras" },
      { label: "Janelas/credencial", key: "janelas_por_credencial" },
      { label: "Janela revogação", key: "janela_revogacao" },
      { label: "Escritas/credencial", key: "escritas_por_credencial" },
      { label: "Escrita (ops/s)", key: "escrita_ops_s" },
      { label: "Leitura (ops/s)", key: "leitura_ops_s" },
      { label: "Escrita mediana (ms/op)", key: "escrita_mediana_ms" },
      { label: "Leitura mediana (ms)", key: "leitura_mediana_ms" },
    ]),
    "utf-8"
  );
  fs.writeFileSync(
    path.join(reportDir, "table-5b-k-vector-ledger-write.md"),
    markdownTable(kVectorLedgerRows, [
      { label: "Chunk solicitado", key: "chunk_size_solicitado" },
      { label: "Experimentos", key: "experimentos" },
      { label: "Escritas K", key: "escritas_k" },
      { label: "K reutilizados", key: "k_reutilizados" },
      { label: "Status", key: "status" },
      { label: "Registro K (ms)", key: "registro_k_ms" },
      { label: "Setup K (ms)", key: "setup_k_ms" },
      { label: "ATTRIBs estimados", key: "attribs_estimados" },
      { label: "Chunks K", key: "chunks_k" },
      { label: "Chunk efetivo (bytes)", key: "chunk_size_efetivo_bytes" },
      { label: "Total K (bytes)", key: "total_k_bytes" },
      { label: "Valores K", key: "valores_k" },
    ]),
    "utf-8"
  );
  fs.writeFileSync(
    path.join(reportDir, "table-6-issuer-revocation.md"),
    markdownTable(issuerRevocationRows, [
      { label: "Janelas", key: "janelas" },
      { label: "Cenário", key: "cenario" },
      { label: "Experimentos", key: "experimentos" },
      { label: "Janela revogação", key: "janela_revogacao" },
      { label: "Revogação (ms)", key: "tempo_revogacao_ms" },
      { label: "Chaves esperadas", key: "chaves_esperadas" },
      { label: "Chaves escritas", key: "chaves_escritas" },
    ]),
    "utf-8"
  );

  const reportIndex = {
    reportDir,
    totalElapsedMs: round(totalElapsedMs),
    totalElapsedLabel: formatDurationMs(totalElapsedMs),
    stageProgress,
    files: [
      "paper-summary.md",
      "table-1-issue.csv",
      "table-1-issue.md",
      "table-2-verify.csv",
      "table-2-verify.md",
      "table-3-false-positive.csv",
      "table-3-false-positive.md",
      "table-4-proof-size.csv",
      "table-4-proof-size.md",
      "table-4b-proof-diagnostics.csv",
      "table-4b-proof-diagnostics.md",
      "table-5-throughput.csv",
      "table-5-throughput.md",
      "table-5b-k-vector-ledger-write.csv",
      "table-5b-k-vector-ledger-write.md",
      "table-6-issuer-revocation.csv",
      "table-6-issuer-revocation.md",
      "table-7-proof-size-delivered.csv",
      "table-7-proof-size-delivered.md",
    ],
  };
  writeJson(path.join(reportDir, "report-index.json"), reportIndex);
  return reportIndex;
}

function parseCliArgs(argv) {
  const out = {
    command: "campaign",
    configPath: "",
    outputDir: "",
  };

  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--config") {
      out.configPath = argv[i + 1] || "";
      i += 1;
      continue;
    }
    if (arg === "--output-dir") {
      out.outputDir = argv[i + 1] || "";
      i += 1;
      continue;
    }
    positional.push(arg);
  }

  if (positional[0]) out.command = positional[0];
  return out;
}

function resolveConfigValuePath(rawPath, options = {}) {
  const input = firstNonEmpty(rawPath);
  if (!input) return "";
  if (path.isAbsolute(input)) return input;

  const candidates = [
    options.cwd ? path.resolve(options.cwd, input) : "",
    options.projectRoot ? path.resolve(options.projectRoot, input) : "",
    options.baseDir ? path.resolve(options.baseDir, input) : "",
  ].filter(Boolean);

  if (options.mustExist) {
    const existing = candidates.find((candidate) => fs.existsSync(candidate));
    return existing || candidates[0] || input;
  }

  return candidates[0] || input;
}

function loadConfig(configPathInput) {
  const cwd = process.cwd();
  const configPath = resolvePathFrom(cwd, configPathInput || "tests/blindrevoke.config.json");
  if (!fs.existsSync(configPath)) {
    throw new Error(
      `Arquivo de configuração não encontrado em ${configPath}. Use --config ou crie uma cópia de tests/blindrevoke.config.example.json.`
    );
  }
  const raw = fs.readFileSync(configPath, "utf-8");
  const parsed = JSON.parse(raw);
  const baseDir = path.dirname(configPath);
  const projectRoot = path.resolve(__dirname, "..");
  return {
    ...parsed,
    _configPath: configPath,
    _baseDir: baseDir,
    _projectRoot: projectRoot,
    genesisPathResolved: resolveConfigValuePath(parsed.genesisPath, {
      cwd,
      projectRoot,
      baseDir,
      mustExist: true,
    }),
    walletPathResolved: resolveConfigValuePath(parsed.walletPath, {
      cwd,
      projectRoot,
      baseDir,
      mustExist: false,
    }),
    outputRootResolved: resolveConfigValuePath(parsed.outputRoot || "tests/results", {
      cwd,
      projectRoot,
      baseDir,
      mustExist: false,
    }),
  };
}

function unwrapLedgerPayload(raw) {
  let current = raw;
  for (let i = 0; i < 6; i += 1) {
    if (typeof current === "string") {
      const parsed = parseMaybeJson(current, null);
      if (!parsed || parsed === current) break;
      current = parsed;
      continue;
    }
    if (!current || typeof current !== "object" || Array.isArray(current)) break;

    if (typeof current.json === "string") {
      const parsed = parseMaybeJson(current.json, null);
      if (parsed) {
        current = parsed;
        continue;
      }
    }
    if (typeof current.data === "string") {
      const parsed = parseMaybeJson(current.data, null);
      if (parsed) {
        current = parsed;
        continue;
      }
    }
    if (current.data && typeof current.data === "object") {
      current = current.data;
      continue;
    }
    if (typeof current.result === "string") {
      const parsed = parseMaybeJson(current.result, null);
      if (parsed) {
        current = parsed;
        continue;
      }
    }
    if (current.result && typeof current.result === "object") {
      current = current.result;
      continue;
    }
    if (typeof current.value === "string") {
      const parsed = parseMaybeJson(current.value, null);
      if (parsed) {
        current = parsed;
        continue;
      }
    }
    if (current.value && typeof current.value === "object") {
      current = current.value;
      continue;
    }
    break;
  }
  return current;
}

function extractAttribReadValue(data) {
  if (data === undefined || data === null) return "";
  if (typeof data === "string") return data;
  if (typeof data === "number" || typeof data === "boolean") return String(data);
  if (typeof data === "object") {
    if (typeof data.value === "string") return data.value;
    if (typeof data.attribValue === "string") return data.attribValue;
    if (typeof data.data === "string") return data.data;
    if (typeof data.result === "string") return data.result;
  }
  return "";
}

function isLedgerLookupMiss(raw, unwrapped) {
  const rawObj = raw && typeof raw === "object" && !Array.isArray(raw) ? raw : null;
  const unwrappedObj = unwrapped && typeof unwrapped === "object" && !Array.isArray(unwrapped) ? unwrapped : null;

  const rawMessage = firstNonEmpty(
    rawObj?.message,
    rawObj?.error,
    rawObj?.reason,
    rawObj?.details?.message
  ).toLowerCase();
  const unwrappedMessage = firstNonEmpty(
    unwrappedObj?.message,
    unwrappedObj?.error,
    unwrappedObj?.reason,
    unwrappedObj?.details?.message
  ).toLowerCase();
  const combinedMessage = `${rawMessage} ${unwrappedMessage}`.trim();

  const hasNoPayload =
    (rawObj && Object.prototype.hasOwnProperty.call(rawObj, "data") && rawObj.data === null)
    || (rawObj && Object.prototype.hasOwnProperty.call(rawObj, "result") && rawObj.result === null)
    || (rawObj && Object.prototype.hasOwnProperty.call(rawObj, "value") && rawObj.value === null);

  const looksLikeMissMessage =
    combinedMessage.includes("not found")
    || combinedMessage.includes("não encontrada")
    || combinedMessage.includes("não encontrado")
    || combinedMessage.includes("nao encontrada")
    || combinedMessage.includes("nao encontrado")
    || combinedMessage.includes("data is null");

  const hasCredDefShape = !!firstNonEmpty(
    unwrappedObj?.id,
    unwrappedObj?.cred_def_id,
    unwrappedObj?.credDefId,
    unwrappedObj?.schema_id,
    unwrappedObj?.schemaId
  );

  return (hasNoPayload || looksLikeMissMessage) && !hasCredDefShape;
}

function addUnitsUtc(baseDate, unitOfTime, amount) {
  const date = new Date(baseDate.getTime());
  switch (String(unitOfTime || "").trim().toLowerCase()) {
    case "second":
    case "seconds":
      date.setUTCSeconds(date.getUTCSeconds() + amount);
      return date;
    case "minute":
    case "minutes":
      date.setUTCMinutes(date.getUTCMinutes() + amount);
      return date;
    case "hour":
    case "hours":
      date.setUTCHours(date.getUTCHours() + amount);
      return date;
    case "day":
    case "days":
      date.setUTCDate(date.getUTCDate() + amount);
      return date;
    case "week":
    case "weeks":
      date.setUTCDate(date.getUTCDate() + (amount * 7));
      return date;
    case "month":
    case "months":
      date.setUTCMonth(date.getUTCMonth() + amount);
      return date;
    case "year":
    case "years":
      date.setUTCFullYear(date.getUTCFullYear() + amount);
      return date;
    case "decade":
    case "decades":
      date.setUTCFullYear(date.getUTCFullYear() + (amount * 10));
      return date;
    default:
      return null;
  }
}

function computeValidityEndFromBaseWindowCount(startTime, unitOfTime, timeWindow, baseWindowCount) {
  if (!Number.isFinite(startTime) || startTime <= 0) {
    throw new Error("startTime inválido para calcular validityEnd.");
  }
  if (!Number.isInteger(baseWindowCount) || baseWindowCount <= 0) {
    throw new Error("baseWindowCount deve ser inteiro positivo.");
  }
  let cursor = new Date(startTime * 1000);
  for (let i = 0; i < baseWindowCount; i += 1) {
    const next = addUnitsUtc(cursor, unitOfTime, timeWindow);
    if (!next) {
      throw new Error(`unitOfTime inválido: ${unitOfTime}`);
    }
    cursor = next;
  }
  return Math.trunc(cursor.getTime() / 1000) - 1;
}

function computeBaseWindowCountFromControl(control) {
  const startTime = Number(control?.start_time);
  const validityEnd = Number(control?.validity_end);
  const timeWindow = Number(control?.time_window);
  const unitOfTime = String(control?.unit_of_time || "").trim();
  if (!Number.isFinite(startTime) || !Number.isFinite(validityEnd) || validityEnd < startTime) return null;
  if (!Number.isFinite(timeWindow) || timeWindow <= 0 || !unitOfTime) return null;

  const startDate = new Date(Math.trunc(startTime) * 1000);
  let index = 0;
  let cursor = startDate;
  while (index < 100000) {
    if (Math.trunc(cursor.getTime() / 1000) > validityEnd) break;
    const next = addUnitsUtc(cursor, unitOfTime, Math.trunc(timeWindow));
    if (!next) return null;
    cursor = next;
    index += 1;
  }
  return index > 0 ? index : null;
}

function deriveBundleWindowLayout(bundle) {
  const control = bundle?.control || {};
  const extraWindowsForFp = Math.max(0, Math.trunc(Number(control?.extra_windows_for_fp) || 0));
  const totalWindowCountRaw = Number(control?.window_count);
  const fallbackBaseWindowCount = Number.isFinite(totalWindowCountRaw) && totalWindowCountRaw > 0
    ? Math.max(1, Math.trunc(totalWindowCountRaw) - extraWindowsForFp)
    : null;
  const computedBaseWindowCount = computeBaseWindowCountFromControl(control);

  const baseWindowCount = Math.max(
    1,
    Math.trunc(
      Number(control?.base_window_count) > 0
        ? Number(control?.base_window_count)
        : (computedBaseWindowCount || fallbackBaseWindowCount || 1)
    )
  );

  const confirmationWindowCount = Math.max(
    0,
    Math.trunc(
      Number(control?.confirmation_window_count) > 0
        ? Number(control?.confirmation_window_count)
        : extraWindowsForFp
    )
  );

  const totalWindowCount = Math.max(
    baseWindowCount,
    Math.trunc(
      Number(control?.window_count) > 0
        ? Number(control?.window_count)
        : (baseWindowCount + confirmationWindowCount)
    )
  );

  const lastValidWindowIndex =
    Number(control?.last_valid_window_index) > 0 || baseWindowCount === 1
      ? Math.trunc(Number(control?.last_valid_window_index) || 0)
      : Math.max(0, baseWindowCount - 1);

  const lastConfirmationWindowIndex =
    Number(control?.last_confirmation_window_index) > 0 || totalWindowCount === 1
      ? Math.trunc(Number(control?.last_confirmation_window_index) || 0)
      : Math.max(0, totalWindowCount - 1);

  return {
    baseWindowCount,
    confirmationWindowCount,
    totalWindowCount,
    lastValidWindowIndex,
    lastConfirmationWindowIndex,
  };
}

function buildExhaustiveWindowScanPlan(bundle, additionalWindowCap) {
  const layout = deriveBundleWindowLayout(bundle);
  const plan = [];
  for (let primaryWindowIndex = 0; primaryWindowIndex <= layout.lastValidWindowIndex; primaryWindowIndex += 1) {
    plan.push({
      primaryWindowIndex,
      additionalWindowCount: Math.max(
        0,
        Math.min(additionalWindowCap, layout.lastConfirmationWindowIndex - primaryWindowIndex)
      ),
      lastConfirmationWindowIndex: layout.lastConfirmationWindowIndex,
    });
  }
  return {
    lastValidWindowIndex: layout.lastValidWindowIndex,
    lastConfirmationWindowIndex: layout.lastConfirmationWindowIndex,
    steps: plan,
  };
}

function buildWindowScanStep(scanPlan, primaryWindowIndex, additionalWindowCap) {
  const idx = Math.max(0, Math.trunc(Number(primaryWindowIndex) || 0));
  return {
    primaryWindowIndex: idx,
    additionalWindowCount: Math.max(
      0,
      Math.min(additionalWindowCap, scanPlan.lastConfirmationWindowIndex - idx)
    ),
    lastConfirmationWindowIndex: scanPlan.lastConfirmationWindowIndex,
  };
}

function compactStatus(status) {
  if (!status || typeof status !== "object") return null;
  return {
    verified: !!status.verified,
    accepted: !!status.accepted,
    revoked: !!status.revoked,
    decision: firstNonEmpty(status.decision) || null,
    requires_more_windows: !!status.requires_more_windows,
    next_required_window_index: status.next_required_window_index ?? null,
    consecutive_hits: Number(status.consecutive_hits ?? 0),
    trace_len: Number(status.trace_len ?? 0),
    details: firstNonEmpty(status.details) || null,
    false_positive_confirmed: !!status.false_positive_confirmed,
  };
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

function isUnauthorizedLedgerWriteError(err) {
  const message = String(err?.stack || err?.message || err || "").toLowerCase();
  return message.includes("unauthorizedclientrequest")
    || message.includes("not enough trustee signatures")
    || message.includes("not enough steward signatures")
    || message.includes("not enough endorser signatures");
}

function uniqueId(prefix) {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1_000_000_000)}`;
}

function buildBenchmarkValues(baseValues, suffix) {
  const source = baseValues && typeof baseValues === "object" ? baseValues : {};
  const out = {};
  Object.entries(source).forEach(([key, value]) => {
    if (typeof value === "string") out[key] = `${value}-${suffix}`;
    else out[key] = String(value);
  });
  return out;
}

function normalizeCredentialValuesRaw(rec) {
  if (!rec || typeof rec !== "object") return {};

  const direct = rec.values_raw;
  if (direct && typeof direct === "object" && !Array.isArray(direct)) {
    return direct;
  }

  const values = rec.values;
  if (!values || typeof values !== "object" || Array.isArray(values)) return {};
  const out = {};
  Object.entries(values).forEach(([key, value]) => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const raw = firstNonEmpty(value?.raw);
      if (raw) out[key] = raw;
    }
  });
  return out;
}

function parseCredentialsRecords(rawData) {
  const parsed = parseMaybeJson(rawData, rawData);
  let arr = [];

  if (Array.isArray(parsed)) {
    arr = parsed;
  } else if (parsed && typeof parsed === "object") {
    if (Array.isArray(parsed.items)) arr = parsed.items;
    else if (Array.isArray(parsed.data)) arr = parsed.data;
    else if (Array.isArray(parsed.records)) arr = parsed.records;
    else if (Array.isArray(parsed.list)) arr = parsed.list;
  }

  return arr
    .map((item) => {
      const parsedItem = parseMaybeJson(item, item);
      const unwrapped = unwrapLedgerPayload(parsedItem);
      if (!unwrapped || typeof unwrapped !== "object" || Array.isArray(unwrapped)) return null;
      const idLocal = firstNonEmpty(unwrapped?.id_local, unwrapped?.id);
      const schemaId = firstNonEmpty(unwrapped?.schema_id, unwrapped?.schemaId);
      const credDefId = firstNonEmpty(unwrapped?.cred_def_id, unwrapped?.credDefId);
      return {
        ...unwrapped,
        id_local: idLocal,
        schema_id: schemaId,
        cred_def_id: credDefId,
        values_raw: normalizeCredentialValuesRaw(unwrapped),
      };
    })
    .filter((rec) => rec && rec.id_local && rec.schema_id && rec.cred_def_id);
}

async function getStoredCredentialRecordById(credentialIdLocal) {
  const targetId = String(credentialIdLocal || "").trim();
  if (!targetId) return null;

  let listRaw;
  try {
    listRaw = await ssi.listCredentials();
  } catch (_) {
    return null;
  }

  const records = parseCredentialsRecords(listRaw);
  return records.find((rec) => firstNonEmpty(rec?.id_local, rec?.id) === targetId) || null;
}

function normalizeComparableValuesMap(valuesRaw) {
  if (!valuesRaw || typeof valuesRaw !== "object" || Array.isArray(valuesRaw)) return {};
  const out = {};
  Object.keys(valuesRaw)
    .map((key) => String(key || "").trim())
    .filter(Boolean)
    .sort()
    .forEach((key) => {
      out[key] = String(valuesRaw[key] ?? "").trim();
    });
  return out;
}

function stripCredentialRecordMetadata(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  const cloned = { ...value };
  delete cloned.id_local;
  delete cloned.id;
  delete cloned.schema_id;
  delete cloned.schemaId;
  delete cloned.cred_def_id;
  delete cloned.credDefId;
  delete cloned.stored_at;
  delete cloned.storedAt;
  delete cloned.alias;
  delete cloned.values_raw;
  return cloned;
}

function canonicalizeComparableJson(value) {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeComparableJson(item));
  }
  if (value && typeof value === "object") {
    const out = {};
    Object.keys(value)
      .sort()
      .forEach((key) => {
        out[key] = canonicalizeComparableJson(value[key]);
      });
    return out;
  }
  return value;
}

function fingerprintCredentialObject(value) {
  const stripped = stripCredentialRecordMetadata(value);
  if (!stripped || typeof stripped !== "object" || Array.isArray(stripped)) return "";
  try {
    return JSON.stringify(canonicalizeComparableJson(stripped));
  } catch (_) {
    return "";
  }
}

function valuesRawMapsEqual(aRaw, bRaw) {
  const a = normalizeComparableValuesMap(aRaw);
  const b = normalizeComparableValuesMap(bRaw);
  const aKeys = Object.keys(a);
  const bKeys = Object.keys(b);
  if (aKeys.length !== bKeys.length) return false;
  for (const key of aKeys) {
    if (!Object.prototype.hasOwnProperty.call(b, key)) return false;
    if (a[key] !== b[key]) return false;
  }
  return true;
}

async function findMatchingStoredCredentialId(credentialObj, credDefIdHint, preferredIdLocal) {
  const preferred = String(preferredIdLocal || "").trim();
  const targetCredDefId = firstNonEmpty(credDefIdHint, credentialObj?.cred_def_id, credentialObj?.credDefId);
  const targetValues = normalizeCredentialValuesRaw(credentialObj);
  const targetFingerprint = fingerprintCredentialObject(credentialObj);

  let listRaw;
  try {
    listRaw = await ssi.listCredentials();
  } catch (_) {
    return "";
  }
  const records = parseCredentialsRecords(listRaw);
  if (!records.length) return "";

  if (preferred) {
    const foundById = records.find((rec) => firstNonEmpty(rec?.id_local, rec?.id) === preferred);
    if (foundById) {
      const foundFingerprint = fingerprintCredentialObject(foundById);
      if (targetFingerprint && foundFingerprint && foundFingerprint === targetFingerprint) {
        return preferred;
      }
    }
  }

  const byCredDef = targetCredDefId
    ? records.filter((rec) => firstNonEmpty(rec?.cred_def_id, rec?.credDefId) === targetCredDefId)
    : records;

  if (targetFingerprint) {
    const foundByFingerprint = byCredDef.find((rec) => {
      const recFingerprint = fingerprintCredentialObject(rec);
      return !!recFingerprint && recFingerprint === targetFingerprint;
    });
    if (foundByFingerprint) {
      return firstNonEmpty(foundByFingerprint?.id_local, foundByFingerprint?.id);
    }
  }

  const targetHasValues = Object.keys(normalizeComparableValuesMap(targetValues)).length > 0;
  if (!targetHasValues) {
    return firstNonEmpty(byCredDef[0]?.id_local, byCredDef[0]?.id);
  }

  const found = byCredDef.find((rec) => valuesRawMapsEqual(targetValues, rec?.values_raw));
  return firstNonEmpty(found?.id_local, found?.id);
}

function extractRequestMetadataIdFromCredential(credentialObj) {
  if (!credentialObj || typeof credentialObj !== "object") return "";
  return firstNonEmpty(
    credentialObj?.request_metadata_id,
    credentialObj?.requestMetadataId,
    credentialObj?.offer_nonce,
    credentialObj?.offerNonce,
    credentialObj?.request_nonce,
    credentialObj?.requestNonce,
    credentialObj?.req_meta_id,
    credentialObj?.reqMetaId,
    credentialObj?.nonce
  );
}

function isLikelyDuplicateError(err) {
  const message = String(err?.message || err || "").toLowerCase();
  return message.includes("duplicate") || message.includes("already exists") || message.includes("já existe");
}

function isMissingRequestMetadataError(err) {
  const message = String(err?.message || err || "").toLowerCase();
  return message.includes("request metadata não encontrado") || message.includes("request metadata id ausente");
}

function isInvalidSignatureProofError(err) {
  const message = String(err?.message || err || "").toLowerCase();
  return message.includes("invalid signature correctness proof")
    || message.includes("q != q'")
    || message.includes("q != q\\'");
}

function extractNonceFromOffer(offerObj) {
  if (!offerObj || typeof offerObj !== "object") return "";
  return firstNonEmpty(
    offerObj?.nonce,
    offerObj?.offer_nonce,
    offerObj?.offerNonce,
    offerObj?.req_meta_id,
    offerObj?.reqMetaId
  );
}

function extractNonceFromRequest(reqObj) {
  if (!reqObj || typeof reqObj !== "object") return "";
  return firstNonEmpty(
    reqObj?.nonce,
    reqObj?.offer_nonce,
    reqObj?.offerNonce,
    reqObj?.req_meta_id,
    reqObj?.reqMetaId
  );
}

function extractStoredCredentialId(raw) {
  const parsed = parseMaybeJson(raw, raw);
  if (typeof parsed === "string") return String(parsed).trim();
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return "";
  return firstNonEmpty(
    parsed?.id_local,
    parsed?.credential_id_local,
    parsed?.credentialIdLocal,
    parsed?.credential_id,
    parsed?.credentialId,
    parsed?.id,
    parsed?.data?.id_local,
    parsed?.data?.credential_id_local,
    parsed?.data?.credentialIdLocal,
    parsed?.data?.credential_id,
    parsed?.data?.credentialId,
    parsed?.data?.id
  );
}

function buildBenchmarkPresentationArtifacts(credentialRecord, proofName, proofVersion, proofNonce) {
  const credentialId = firstNonEmpty(credentialRecord?.id_local, credentialRecord?.id);
  const schemaId = firstNonEmpty(credentialRecord?.schema_id, credentialRecord?.schemaId);
  const credDefId = firstNonEmpty(credentialRecord?.cred_def_id, credentialRecord?.credDefId);
  const valuesRaw = credentialRecord?.values_raw && typeof credentialRecord.values_raw === "object"
    ? credentialRecord.values_raw
    : {};

  if (!credentialId || !schemaId || !credDefId) {
    throw new Error("Credencial inválida para montar pacote de apresentação no benchmark.");
  }

  const normalizeAttrName = (name) => {
    const raw = String(name || "").trim();
    return raw === "root_merkle_l" ? "root_merkle_L" : raw;
  };

  const requestedAttributes = {};
  const requestedCredAttributes = {};
  const seenAttrNames = new Set();
  let attrRefSeq = 1;

  for (const attrNameRaw of Object.keys(valuesRaw)) {
    const attrName = normalizeAttrName(attrNameRaw);
    if (!attrName || seenAttrNames.has(attrName)) continue;
    seenAttrNames.add(attrName);
    const referent = `attr_${attrRefSeq++}`;
    requestedAttributes[referent] = {
      name: attrName,
      restrictions: [{ cred_def_id: credDefId }],
    };
    requestedCredAttributes[referent] = {
      cred_id: credentialId,
      revealed: true,
    };
  }

  if (attrRefSeq === 1) {
    throw new Error("Credencial sem atributos utilizáveis para apresentação no benchmark.");
  }

  return {
    presentationRequest: {
      nonce: proofNonce,
      name: proofName,
      version: proofVersion,
      requested_attributes: requestedAttributes,
      requested_predicates: {},
    },
    requestedCredentials: {
      requested_attributes: requestedCredAttributes,
      requested_predicates: {},
    },
    usedSchemaIds: [schemaId],
    usedCredDefIds: [credDefId],
    counts: {
      requestedAttributes: Object.keys(requestedAttributes).length,
      requestedPredicates: 0,
      totalRequested: Object.keys(requestedAttributes).length,
    },
  };
}

async function buildFullPresentationEnvelopeForFixture(ctx, fixture) {
  return buildPresentationEnvelopeForFixture(ctx, fixture, {});
}

function computeDeliveredWindowCountFromTotal(totalWindowCount) {
  const numericTotal = Math.max(0, Number(totalWindowCount) || 0);
  if (numericTotal <= 0) return 1;
  return Math.min(numericTotal, Math.max(1, Math.floor(numericTotal * 0.01)));
}

async function buildPresentationEnvelopeForFixture(ctx, fixture, options = {}) {
  const { issuer, holder } = await ensureIdentities(ctx);
  const holderCredentialByFixtureId = await getStoredCredentialRecordById(fixture.holderCredentialIdLocal);
  const holderCredentialIdLocal = firstNonEmpty(
    holderCredentialByFixtureId?.id_local,
    await findMatchingStoredCredentialId(
      fixture.credentialJsonObject,
      fixture.credDefId,
      fixture.issuerLocalCredentialId
    )
  );
  if (!holderCredentialIdLocal) {
    throw new Error(
      `Credencial do holder não encontrada para ${fixture.issuerLocalCredentialId}.`
      + (fixture.holderCredentialStoreError ? ` storeCredential: ${fixture.holderCredentialStoreError}` : "")
      + (fixture.walletOfferStoreError ? ` storeReceivedOffer: ${fixture.walletOfferStoreError}` : "")
    );
  }
  const holderCredentialRecord = holderCredentialByFixtureId
    || await getStoredCredentialRecordById(holderCredentialIdLocal);
  if (!holderCredentialRecord) {
    throw new Error(`Registro da credencial do holder não encontrado para ${holderCredentialIdLocal}.`);
  }
  const credentialRecord = {
    id_local: holderCredentialIdLocal,
    schema_id: firstNonEmpty(holderCredentialRecord?.schema_id, holderCredentialRecord?.schemaId, fixture.schemaId),
    cred_def_id: firstNonEmpty(holderCredentialRecord?.cred_def_id, holderCredentialRecord?.credDefId, fixture.credDefId),
    values_raw: holderCredentialRecord?.values_raw && typeof holderCredentialRecord.values_raw === "object"
      ? holderCredentialRecord.values_raw
      : {},
  };

  const proofName = `bench-presentation-${fixture.issuerLocalCredentialId}`;
  const proofVersion = "1.0";
  const proofNonce = `${Date.now()}${Math.floor(Math.random() * 1_000_000)}`;
  const artifacts = buildBenchmarkPresentationArtifacts(
    credentialRecord,
    proofName,
    proofVersion,
    proofNonce
  );

  const schemasMap = {};
  for (const schemaId of artifacts.usedSchemaIds) {
    schemasMap[schemaId] = unwrapLedgerPayload(
      parseMaybeJson(await ssi.fetchSchemaFromLedger(ctx.config.genesisPathResolved, schemaId), null)
    );
  }

  const credDefsMap = {};
  for (const credDefId of artifacts.usedCredDefIds) {
    credDefsMap[credDefId] = unwrapLedgerPayload(
      parseMaybeJson(await ssi.fetchCredDefFromLedger(ctx.config.genesisPathResolved, credDefId), null)
    );
  }

  const deliveredWindowCount = Math.min(
    fixture.bundleLayout.totalWindowCount,
    Math.max(1, Number(options.deliveredWindowCount ?? fixture.bundleLayout.totalWindowCount))
  );
  const additionalWindowCount = Math.max(0, deliveredWindowCount - 1);
  const revocationSequences = [{
    credential_id_local: holderCredentialIdLocal,
    primary_window_index: 0,
    additional_window_count: additionalWindowCount,
  }];

  const anoncredsPresentationMeasured = await measureAsync(() => ssi.createPresentation(
    JSON.stringify(artifacts.presentationRequest),
    JSON.stringify(artifacts.requestedCredentials),
    JSON.stringify(schemasMap),
    JSON.stringify(credDefsMap)
  ));
  const anoncredsPresentationObj = parseMaybeJson(anoncredsPresentationMeasured.value, null);
  if (!anoncredsPresentationObj || typeof anoncredsPresentationObj !== "object" || Array.isArray(anoncredsPresentationObj)) {
    throw new Error("Apresentação anoncreds inválida no benchmark.");
  }

  const primaryProofMeasured = await measureAsync(() => ssi.buildPresentationRevocationProofV2(
    fixture.bundleIdLocal,
    0,
    0,
    holderCredentialIdLocal
  ));
  const primaryProofData = parseMaybeJson(primaryProofMeasured.value, null);
  const primaryProofSequence = primaryProofData?.proof_sequence || primaryProofData;
  if (!primaryProofSequence || typeof primaryProofSequence !== "object" || Array.isArray(primaryProofSequence)) {
    throw new Error("Primary proof inválido no benchmark.");
  }

  const fullProofSequenceMeasured = await measureAsync(() => ssi.buildPresentationRevocationProofV2(
    fixture.bundleIdLocal,
    0,
    additionalWindowCount,
    holderCredentialIdLocal
  ));
  const fullProofSequenceData = parseMaybeJson(fullProofSequenceMeasured.value, null);
  const fullProofSequence = fullProofSequenceData?.proof_sequence || fullProofSequenceData;
  if (!fullProofSequence || typeof fullProofSequence !== "object" || Array.isArray(fullProofSequence)) {
    throw new Error("Sequência revogável completa inválida no benchmark.");
  }

  const totalStartedAtNs = process.hrtime.bigint();

  const packageStartedAtNs = process.hrtime.bigint();
  const packageRaw = await ssi.createPresentationPackageWithRevocationV2(
    JSON.stringify(artifacts.presentationRequest),
    JSON.stringify(artifacts.requestedCredentials),
    JSON.stringify(schemasMap),
    JSON.stringify(credDefsMap),
    JSON.stringify(revocationSequences)
  );
  const packageBuildElapsedMs = Number(process.hrtime.bigint() - packageStartedAtNs) / 1_000_000;
  const packageObj = parseMaybeJson(packageRaw, null);
  if (!packageObj || typeof packageObj !== "object" || Array.isArray(packageObj)) {
    throw new Error("Pacote de apresentação revogável inválido no benchmark.");
  }

  const presentationObj = parseMaybeJson(packageObj.presentation_json, packageObj.presentation_json);
  const revocationProofSequences = Array.isArray(packageObj.revocation_proof_sequences)
    ? packageObj.revocation_proof_sequences
    : [];
  const usedCredentials = Array.isArray(packageObj.used_credentials)
    ? packageObj.used_credentials
    : [];

  const metaJson = JSON.stringify({
    proof_name: proofName,
    proof_version: proofVersion,
    requested_attributes: artifacts.counts.requestedAttributes,
    requested_predicates: artifacts.counts.requestedPredicates,
    payload_format: "presentation_package_v2_revocation",
    revocation_sequences: revocationSequences.length,
    revocation_proof_sequences: revocationProofSequences.length,
  });

  const serializeStartedAtNs = process.hrtime.bigint();
  const presentationPayload = {
    type: "ssi/presentation-envelope-payload",
    version: 2,
    presentation_json: presentationObj,
    presentation_request: artifacts.presentationRequest,
    requested_credentials: artifacts.requestedCredentials,
    schema_ids: artifacts.usedSchemaIds,
    cred_def_ids: artifacts.usedCredDefIds,
    revocation_proof_sequences: revocationProofSequences,
    used_credentials: usedCredentials,
    revocation_sequences: revocationSequences,
    created_at_ms: Date.now(),
  };
  const presentationPayloadJson = JSON.stringify(presentationPayload);
  const payloadSerializeElapsedMs = Number(process.hrtime.bigint() - serializeStartedAtNs) / 1_000_000;

  const envelopeStartedAtNs = process.hrtime.bigint();
  const envelopeJson = await ssi.envelopePackAuthcrypt(
    holder.did,
    issuer.verkey,
    "ssi/proof/presentation",
    uniqueId("thread"),
    presentationPayloadJson,
    null,
    metaJson
  );
  const envelopeEncryptElapsedMs = Number(process.hrtime.bigint() - envelopeStartedAtNs) / 1_000_000;
  const totalElapsedMs = Number(process.hrtime.bigint() - totalStartedAtNs) / 1_000_000;

  return {
    deliveredWindowCount,
    presentationPayload,
    presentationPayloadJson,
    envelopeJson,
    revocationProofSequencesCount: revocationProofSequences.length,
    anoncredsPresentationElapsedMs: round(anoncredsPresentationMeasured.elapsedMs),
    primaryProofOnlyElapsedMs: round(primaryProofMeasured.elapsedMs),
    fullProofSequenceElapsedMs: round(fullProofSequenceMeasured.elapsedMs),
    confirmationProofsEstimatedElapsedMs: round(
      Math.max(0, Number(fullProofSequenceMeasured.elapsedMs) - Number(primaryProofMeasured.elapsedMs))
    ),
    packageBuildElapsedMs: round(packageBuildElapsedMs),
    payloadSerializeElapsedMs: round(payloadSerializeElapsedMs),
    envelopeEncryptElapsedMs: round(envelopeEncryptElapsedMs),
    buildElapsedMs: round(totalElapsedMs),
  };
}

async function fetchJson(url) {
  if (typeof fetch !== "function") {
    throw new Error("Este runtime Node não expõe fetch global.");
  }
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`Falha HTTP ${resp.status} ao ler ${url}`);
  }
  const text = await resp.text();
  return {
    text,
    json: parseMaybeJson(text, null),
  };
}

function buildBloomAdminHeaders(adminToken) {
  const token = String(adminToken || "").trim();
  if (!token) return {};
  return {
    Authorization: `Bearer ${token}`,
    "X-Admin-Token": token,
  };
}

function deriveBloomServiceBaseUrl(manifestUrl) {
  const normalized = String(manifestUrl || "").trim();
  if (!normalized) {
    throw new Error("manifestUrl ausente ao derivar a base do serviço Bloom.");
  }
  let parsed;
  try {
    parsed = new URL(normalized);
  } catch (error) {
    throw new Error(`manifestUrl inválida para o serviço Bloom: ${normalized}`);
  }
  return `${parsed.protocol}//${parsed.host}`;
}

function getBloomResetPath(ctx) {
  return firstNonEmpty(ctx.config.bloomBootstrap?.resetPath, "/test/reset");
}

function findFilterProfileByManifestUrl(ctx, manifestUrl) {
  const normalizedManifestUrl = String(manifestUrl || "").trim();
  if (!normalizedManifestUrl) return null;

  const profiles = ctx.config.filterProfiles && typeof ctx.config.filterProfiles === "object"
    ? Object.values(ctx.config.filterProfiles)
    : [];
  return profiles.find((profile) => (
    normalizedManifestUrl === String(firstNonEmpty(profile?.manifestUrl)).trim()
  )) || null;
}

function buildBloomResetPayload(profile) {
  if (!profile) return {};

  const payload = {};
  const mBits = Number(profile.filterBits ?? profile.mBits);
  const kHashes = Number(profile.k ?? profile.kHashes ?? profile.hashCount);
  const filterId = firstNonEmpty(profile.resetFilterId, profile.filterId);

  if (Number.isInteger(mBits) && mBits > 0) payload.m_bits = mBits;
  if (Number.isInteger(kHashes) && kHashes > 0) payload.k = kHashes;
  if (filterId) payload.filter_id = filterId;

  return payload;
}

async function resetBloomFilterService(ctx, manifestUrl, profileOverride = null) {
  if (typeof fetch !== "function") {
    throw new Error("Este runtime Node não expõe fetch global.");
  }
  const baseUrl = deriveBloomServiceBaseUrl(manifestUrl);
  const resetPath = getBloomResetPath(ctx);
  const resetUrl = new URL(resetPath, `${baseUrl}/`).toString();
  const payload = buildBloomResetPayload(profileOverride || findFilterProfileByManifestUrl(ctx, manifestUrl));
  let response;
  try {
    response = await fetch(resetUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...buildBloomAdminHeaders(ctx.config.bloomAdminToken),
      },
      body: JSON.stringify(payload),
    });
  } catch (error) {
    throw new Error(
      `Falha conectando ao serviço Bloom em ${resetUrl}: ${String(error?.message || error || "fetch failed")}`
    );
  }
  const bodyText = await response.text().catch(() => "");
  if (!response.ok) {
    throw new Error(
      `Falha ao resetar o serviço Bloom em ${resetUrl}: HTTP ${response.status}${bodyText ? ` - ${bodyText}` : ""}`
    );
  }
  return {
    resetUrl,
    requestPayload: payload,
    responseBody: bodyText,
  };
}

async function buildLiveManifestAnchorData(issuerDid, manifestUrl, manifestVersion) {
  const manifestResp = await fetchJson(manifestUrl);
  const manifestHash = sha256Base64(manifestResp.text);
  const manifestJson = await ssi.revocationBuildManifestAnchor(
    issuerDid,
    manifestUrl,
    manifestHash,
    manifestVersion
  );
  const manifestObj = parseMaybeJson(manifestJson, null);
  if (!manifestObj || typeof manifestObj !== "object") {
    throw new Error("Não foi possível construir o manifesto de revogação.");
  }
  return {
    manifestObj,
    manifestJson: JSON.stringify(manifestObj),
    manifestBytes: Buffer.byteLength(manifestResp.text, "utf-8"),
    manifestHash,
  };
}

async function fetchBloomManifestDiagnostics(manifestUrl) {
  const { json } = await fetchJson(manifestUrl);
  const manifest = json?.manifest || json;
  const filters = Array.isArray(manifest?.filters) ? manifest.filters : [];
  const activeFilterId = String(manifest?.active_filter_id || "").trim();
  const activeFilter = filters.find((item) => String(item?.filter_id || "").trim() === activeFilterId) || null;
  return {
    manifestUrl,
    activeFilterId,
    filterCount: filters.length,
    totalInsertedCount: filters.reduce((sum, item) => sum + Number(item?.inserted_count || 0), 0),
    activeInsertedCount: Number(activeFilter?.inserted_count || 0),
    activeWindowStartMin: activeFilter?.window_start_min ?? null,
    activeWindowStartMax: activeFilter?.window_start_max ?? null,
  };
}

function cloneJsonLike(value) {
  if (value === undefined || value === null) return value;
  return JSON.parse(JSON.stringify(value));
}

function applyManifestAnchorToProofSequence(sequenceObj, manifestObj) {
  if (!sequenceObj || typeof sequenceObj !== "object" || Array.isArray(sequenceObj)) return sequenceObj;
  if (!manifestObj || typeof manifestObj !== "object" || Array.isArray(manifestObj)) return sequenceObj;

  const patchProof = (proof) => {
    if (!proof || typeof proof !== "object" || Array.isArray(proof)) return proof;
    return {
      ...proof,
      manifest: manifestObj,
    };
  };

  return {
    ...sequenceObj,
    primary_proof: patchProof(sequenceObj.primary_proof),
    confirmation_proofs: Array.isArray(sequenceObj.confirmation_proofs)
      ? sequenceObj.confirmation_proofs.map((proof) => patchProof(proof))
      : [],
  };
}

async function tryReadRevocationManifestFromLedger(genesisPath, issuerDid) {
  const normalizedGenesisPath = String(genesisPath || "").trim();
  const normalizedIssuerDid = String(issuerDid || "").trim();
  if (!normalizedGenesisPath || !normalizedIssuerDid) return null;
  try {
    const raw = await ssi.revocationReadManifestAnchorFromLedger(normalizedGenesisPath, normalizedIssuerDid);
    const parsed = parseMaybeJson(raw, raw);
    const unwrapped = unwrapLedgerPayload(parsed);
    return unwrapped?.manifest || parsed?.manifest || null;
  } catch (_) {
    return null;
  }
}

async function readRevocationSetupFromLedger(genesisPath, issuerDid) {
  const normalizedGenesisPath = String(genesisPath || "").trim();
  const normalizedIssuerDid = String(issuerDid || "").trim();
  if (!normalizedGenesisPath || !normalizedIssuerDid) return null;

  let activeKAnchor = null;
  let activeKVector = null;

  try {
    const rawActive = await ssi.readAttribFromLedger(
      normalizedGenesisPath,
      normalizedIssuerDid,
      REVOCATION_ACTIVE_K_ATTR_KEY
    );
    const activeValue = extractAttribReadValue(rawActive);
    const activeParsed = parseMaybeJson(activeValue, null);
    if (activeParsed && typeof activeParsed === "object" && !Array.isArray(activeParsed)) {
      activeKAnchor = activeParsed;
    }
  } catch (error) {
    const parsed = parseMaybeJson(error?.message, null);
    if (!isLedgerLookupMiss(error, parsed)) throw error;
  }

  if (activeKAnchor?.k_vector_id) {
    try {
      const rawK = await ssi.revocationReadKVectorFromLedger(
        normalizedGenesisPath,
        normalizedIssuerDid,
        activeKAnchor.k_vector_id
      );
      const parsedK = parseMaybeJson(rawK, rawK);
      const unwrappedK = unwrapLedgerPayload(parsedK);
      if (!isLedgerLookupMiss(parsedK, unwrappedK)) {
        activeKAnchor = unwrappedK?.ledger_anchor || activeKAnchor;
        activeKVector = unwrappedK?.k_vector || null;
      }
    } catch (error) {
      const parsed = parseMaybeJson(error?.message, null);
      if (!isLedgerLookupMiss(error, parsed)) throw error;
    }
  }

  return {
    issuerDid: normalizedIssuerDid,
    activeKAnchor,
    activeKVector,
    manifest: await tryReadRevocationManifestFromLedger(normalizedGenesisPath, normalizedIssuerDid),
    ready: !!activeKAnchor?.k_vector_id,
  };
}

async function refreshProofSequenceManifestAnchorsHeadless(ctx, sequenceObj) {
  const primaryManifest = sequenceObj?.primary_proof?.manifest;
  const issuerDid = firstNonEmpty(
    primaryManifest?.issuer_did,
    sequenceObj?.issuer_did,
    sequenceObj?.primary_proof?.cred_def_id?.split?.(":")?.[0]
  );
  const manifestUrl = firstNonEmpty(primaryManifest?.manifest_url);
  const manifestVersion = firstNonEmpty(primaryManifest?.manifest_version, "1");

  if (!issuerDid || !manifestUrl) {
    return {
      refreshed: false,
      source: "unavailable",
      proofSequence: sequenceObj,
      effectiveManifest: primaryManifest || null,
    };
  }

  let liveManifest = null;
  try {
    liveManifest = (await buildLiveManifestAnchorData(issuerDid, manifestUrl, manifestVersion)).manifestObj;
  } catch (_) {
    liveManifest = null;
  }

  let ledgerManifest = null;
  if (!liveManifest) {
    ledgerManifest = await tryReadRevocationManifestFromLedger(ctx.config.genesisPathResolved, issuerDid);
  }

  const effectiveManifest = liveManifest || ledgerManifest || primaryManifest || null;
  return {
    refreshed: JSON.stringify(effectiveManifest || null) !== JSON.stringify(primaryManifest || null),
    source: liveManifest ? "service_live" : (ledgerManifest ? "ledger" : "original"),
    proofSequence: applyManifestAnchorToProofSequence(sequenceObj, cloneJsonLike(effectiveManifest)),
    effectiveManifest,
    liveManifest,
    ledgerManifest,
  };
}

function diffBloomManifestDiagnostics(before, after) {
  return {
    totalInsertedDelta: Number(after?.totalInsertedCount || 0) - Number(before?.totalInsertedCount || 0),
    activeInsertedDelta: Number(after?.activeInsertedCount || 0) - Number(before?.activeInsertedCount || 0),
    activeFilterChanged: String(before?.activeFilterId || "") !== String(after?.activeFilterId || ""),
  };
}

function logProgress(message) {
  console.log(`[blindrevoke-bench] ${new Date().toISOString()} ${message}`);
}

function buildContext(config, cli) {
  const runId = `blindrevoke-bench-${timestampTag()}`;
  const outputRoot = cli.outputDir
    ? resolvePathFrom(process.cwd(), cli.outputDir)
    : path.join(config.outputRootResolved, runId);
  ensureDirSync(outputRoot);
  return {
    cli,
    config,
    outputRoot,
    runId,
    runStartedAtMs: Date.now(),
    runMetrics: {
      totalElapsedMs: 0,
      stageProgress: [],
    },
    caches: {
      submitter: null,
      identities: null,
      schemaAndCredDef: null,
      revocationSetupByManifest: new Map(),
    },
  };
}

async function ensureWalletOpen(ctx) {
  const walletPath = ctx.config.walletPathResolved;
  const walletPass = String(ctx.config.walletPass || "");
  if (!walletPath || !walletPass) {
    throw new Error("walletPath e walletPass são obrigatórios na configuração.");
  }
  if (!fs.existsSync(walletPath)) {
    await ssi.walletCreate(walletPath, walletPass);
  }
  await ssi.walletOpen(walletPath, walletPass);
}

async function connectLedger(ctx) {
  await ssi.connectNetwork(ctx.config.genesisPathResolved);
}

async function ensureSubmitter(ctx) {
  if (ctx.caches.submitter) return ctx.caches.submitter;

  const submitterSeed = firstNonEmpty(
    ctx.config.identities?.submitter?.seed,
    ctx.config.trusteeSeed,
    "000000000000000000000000Trustee1"
  );
  const submitterDidConfigured = firstNonEmpty(
    ctx.config.identities?.submitter?.did,
    ctx.config.trusteeDid,
    DEFAULT_TRUSTEE_DID
  );
  const submitterRaw = await ssi.importDidFromSeed(submitterSeed);
  const submitterParsed = parseDidTuple(submitterRaw);
  const submitter = {
    did: firstNonEmpty(submitterParsed.did, submitterDidConfigured),
    verkey: firstNonEmpty(submitterParsed.verkey),
    didConfigured: submitterDidConfigured || null,
  };

  ctx.caches.submitter = {
    submitter,
    submitterParsed,
    submitterDidConfigured,
  };
  return ctx.caches.submitter;
}

async function registerIssuerDidOnLedger(ctx, options) {
  const submitter = options?.submitter || {};
  const submitterParsed = options?.submitterParsed || {};
  const submitterDidConfigured = options?.submitterDidConfigured || "";
  const issuerDid = firstNonEmpty(options?.issuerDid);
  const issuerVerkey = firstNonEmpty(options?.issuerVerkey);
  const issuerLedgerRole = firstNonEmpty(options?.issuerLedgerRole, "ENDORSER");

  try {
    await ssi.registerDidOnLedger(
      ctx.config.genesisPathResolved,
      submitter.did,
      issuerDid,
      issuerVerkey,
      issuerLedgerRole
    );
  } catch (err) {
    if (isUnauthorizedLedgerWriteError(err)) {
      const detailLines = [
        "O benchmark tentou registrar automaticamente um novo DID emissor no ledger, mas o submitter configurado não possui permissão suficiente.",
        "",
        `Submitter importado da seed: ${firstNonEmpty(submitterParsed.did, "(não retornado)")}`,
        `Submitter configurado no JSON: ${firstNonEmpty(submitterDidConfigured, "(não informado)")}`,
        `Submitter efetivamente usado: ${firstNonEmpty(submitter.did, "(não resolvido)")}`,
        `Role solicitada para o emissor: ${issuerLedgerRole}`,
        "",
        "Como corrigir:",
        "1. Configure em tests/blindrevoke.config.json uma seed de um DID com papel TRUSTEE, STEWARD ou ENDORSER do seu ledger em identities.submitter.seed.",
        "2. Se você já tem um DID emissor registrado no ledger, informe identities.issuer.did e identities.issuer.verkey e defina identities.issuer.registerOnLedger = false.",
        "3. Se necessário, ajuste também identities.submitter.did para o DID correto derivado da seed usada no seu ambiente.",
        "4. Se o seu ledger exigir outro papel para o emissor, ajuste identities.issuer.role.",
        "",
        `Erro original: ${String(err?.message || err)}`,
      ];
      const wrapped = new Error(detailLines.join("\n"));
      wrapped.code = "BENCH_LEDGER_SUBMITTER_UNAUTHORIZED";
      throw wrapped;
    }
    throw err;
  }
}

async function ensureIdentities(ctx) {
  if (ctx.caches.identities) return ctx.caches.identities;

  const {
    submitter,
    submitterParsed,
    submitterDidConfigured,
  } = await ensureSubmitter(ctx);

  const issuerProvidedDid = firstNonEmpty(ctx.config.identities?.issuer?.did);
  const issuerProvidedVerkey = firstNonEmpty(ctx.config.identities?.issuer?.verkey);
  const issuerLedgerRole = firstNonEmpty(ctx.config.identities?.issuer?.role, "ENDORSER");
  const issuerUsesSubmitter = ctx.config.identities?.issuer?.useSubmitter === true;
  let issuer;
  if (issuerUsesSubmitter) {
    issuer = {
      did: submitter.did,
      verkey: submitter.verkey,
      role: issuerLedgerRole,
      reusedSubmitter: true,
    };
  } else if (issuerProvidedDid && issuerProvidedVerkey) {
    issuer = { did: issuerProvidedDid, verkey: issuerProvidedVerkey, role: issuerLedgerRole };
  } else {
    issuer = parseDidTuple(await ssi.createOwnDid());
    issuer.role = issuerLedgerRole;
    if (ctx.config.identities?.issuer?.registerOnLedger !== false) {
      await registerIssuerDidOnLedger(ctx, {
        submitter,
        submitterParsed,
        submitterDidConfigured,
        issuerDid: issuer.did,
        issuerVerkey: issuer.verkey,
        issuerLedgerRole,
      });
    }
  }

  const holderProvidedDid = firstNonEmpty(ctx.config.identities?.holder?.did);
  const holderProvidedVerkey = firstNonEmpty(ctx.config.identities?.holder?.verkey);
  const holder = holderProvidedDid && holderProvidedVerkey
    ? { did: holderProvidedDid, verkey: holderProvidedVerkey }
    : parseDidTuple(await ssi.createOwnDid());

  const linkSecretId = firstNonEmpty(ctx.config.linkSecretId, "blindrevoke-bench-link-secret");
  try {
    await ssi.createLinkSecret(linkSecretId);
  } catch (err) {
    const message = String(err?.message || err || "");
    if (!message.toLowerCase().includes("duplicate") && !message.toLowerCase().includes("exists")) {
      throw err;
    }
  }

  ctx.caches.identities = {
    submitter,
    issuer,
    holder,
    linkSecretId,
  };
  return ctx.caches.identities;
}

async function createBenchmarkIssuer(ctx) {
  const {
    submitter,
    submitterDidConfigured,
  } = await ensureSubmitter(ctx);
  const issuerLedgerRole = firstNonEmpty(ctx.config.identities?.issuer?.role, "ENDORSER");
  if (ctx.config.identities?.issuer?.useSubmitter === true) {
    return {
      did: submitter.did,
      verkey: submitter.verkey,
      role: issuerLedgerRole,
      reusedSubmitter: true,
    };
  }

  const issuer = parseDidTuple(await ssi.createOwnDid());
  issuer.role = issuerLedgerRole;
  await registerIssuerDidOnLedger(ctx, {
    submitter,
    submitterParsed: { did: submitter.did },
    submitterDidConfigured,
    issuerDid: issuer.did,
    issuerVerkey: issuer.verkey,
    issuerLedgerRole,
  });
  return issuer;
}

function extractSchemaId(rawSchema, issuerDid, name, version) {
  const parsed = parseMaybeJson(rawSchema, null);
  if (typeof rawSchema === "string") {
    const trimmed = rawSchema.trim();
    if (trimmed && trimmed.includes(":2:")) return trimmed;
  }
  return firstNonEmpty(
    rawSchema,
    parsed?.schemaId,
    parsed?.schema_id,
    parsed?.id,
    parsed?.data?.schemaId,
    parsed?.data?.schema_id,
    parsed?.result?.id,
    parsed?.result?.schemaId,
    `${issuerDid}:2:${name}:${version}`
  );
}

function extractCredDefId(rawCredDef) {
  const parsed = parseMaybeJson(rawCredDef, null);
  if (typeof rawCredDef === "string") {
    const trimmed = rawCredDef.trim();
    if (trimmed && trimmed.includes(":3:CL:")) return trimmed;
  }
  return firstNonEmpty(
    rawCredDef,
    parsed?.credDefId,
    parsed?.cred_def_id,
    parsed?.id,
    parsed?.data?.credDefId,
    parsed?.data?.cred_def_id,
    parsed?.result?.id,
    parsed?.result?.credDefId
  );
}

async function ensureSchemaAndCredDef(ctx) {
  if (ctx.caches.schemaAndCredDef) return ctx.caches.schemaAndCredDef;

  const { issuer } = await ensureIdentities(ctx);
  const schemaNamePrefix = firstNonEmpty(ctx.config.schema?.namePrefix, "BlindRevokeBench");
  const schemaVersion = firstNonEmpty(ctx.config.schema?.version, "1.0");
  const attrNames = withRequiredRevocationControlAttributes(
    Array.isArray(ctx.config.schema?.attributes) && ctx.config.schema.attributes.length > 0
      ? ctx.config.schema.attributes.map(String)
      : ["nome", "doc", "perfil"]
  );

  const schemaName = `${schemaNamePrefix}-${timestampTag()}`;
  const schemaRaw = await ssi.createAndRegisterSchema(
    ctx.config.genesisPathResolved,
    issuer.did,
    schemaName,
    schemaVersion,
    attrNames
  );
  const schemaId = extractSchemaId(schemaRaw, issuer.did, schemaName, schemaVersion);
  if (!schemaId) {
    throw new Error(
      `Nao foi possivel extrair schemaId do retorno createAndRegisterSchema. Retorno bruto: ${typeof schemaRaw === "string" ? schemaRaw : JSON.stringify(schemaRaw)}`
    );
  }

  const credDefTag = firstNonEmpty(ctx.config.credDefTag, "BENCH");
  const credDefRaw = await ssi.createAndRegisterCredDef(
    ctx.config.genesisPathResolved,
    issuer.did,
    schemaId,
    credDefTag
  );
  const credDefId = extractCredDefId(credDefRaw);
  if (!credDefId) {
    throw new Error(
      `Nao foi possivel extrair credDefId do retorno createAndRegisterCredDef. schemaId=${schemaId}. Retorno bruto: ${typeof credDefRaw === "string" ? credDefRaw : JSON.stringify(credDefRaw)}`
    );
  }

  ctx.caches.schemaAndCredDef = {
    schemaId,
    schemaRaw,
    schemaName,
    schemaVersion,
    attrNames,
    credDefId,
    credDefRaw,
  };
  return ctx.caches.schemaAndCredDef;
}

async function ensureRevocationSetup(ctx, manifestUrl) {
  const { issuer } = await ensureIdentities(ctx);
  const key = `${issuer.did}|${manifestUrl}`;
  if (ctx.caches.revocationSetupByManifest.has(key)) {
    return ctx.caches.revocationSetupByManifest.get(key);
  }

  const manifestVersion = firstNonEmpty(ctx.config.manifestVersion, "1");
  const existingSetup = await readRevocationSetupFromLedger(ctx.config.genesisPathResolved, issuer.did);
  let kSetup = null;
  let kWrite = null;
  let kLedgerAnchor = existingSetup?.activeKAnchor || null;
  let kVector = existingSetup?.activeKVector || null;

  if (!kLedgerAnchor?.k_vector_id) {
    const kSetupRaw = await ssi.revocationSetupCreateK(issuer.did, null, null);
    kSetup = parseMaybeJson(kSetupRaw, null);
    kVector = kSetup?.k_vector || kSetup?.active_k_vector || kSetup?.activeKVector;
    if (!kVector) {
      throw new Error("O addon não retornou k_vector no setup de revogação.");
    }

    const kWriteRaw = await ssi.revocationWriteKVectorOnLedger(
      ctx.config.genesisPathResolved,
      issuer.did,
      JSON.stringify(kVector),
      null
    );
    kWrite = parseMaybeJson(kWriteRaw, null);
    kLedgerAnchor = kWrite?.ledger_anchor || kWrite?.active_k_ledger_anchor || null;
  } else if (!kVector && kLedgerAnchor?.k_vector_id) {
    kVector = {
      k_vector_id: kLedgerAnchor.k_vector_id,
      vector_hash: firstNonEmpty(kLedgerAnchor.vector_hash),
    };
  }

  const liveManifest = await buildLiveManifestAnchorData(issuer.did, manifestUrl, manifestVersion);
  const manifestWriteRaw = await ssi.revocationWriteManifestAnchorOnLedger(
    ctx.config.genesisPathResolved,
    issuer.did,
    liveManifest.manifestJson
  );
  const manifestWrite = unwrapLedgerPayload(parseMaybeJson(manifestWriteRaw, manifestWriteRaw));

  const setup = {
    manifestUrl,
    manifestVersion,
    liveManifest,
    kSetup,
    kWrite,
    kLedgerAnchor,
    kVector,
    reusedExistingK: !!existingSetup?.activeKAnchor?.k_vector_id,
    manifestWrite,
  };
  ctx.caches.revocationSetupByManifest.set(key, setup);
  return setup;
}

function collectManifestUrlsForCommand(ctx, command) {
  if (command === "k-vector-ledger-write") {
    return [];
  }

  const manifestUrls = new Set();
  const addManifest = (value) => {
    const normalized = String(firstNonEmpty(value, "")).trim();
    if (normalized) manifestUrls.add(normalized);
  };

  addManifest(firstNonEmpty(ctx.config.filterProfiles?.default?.manifestUrl, ctx.config.manifestUrl));

  return Array.from(manifestUrls);
}

async function bootstrapManifestState(ctx, manifestUrl, profileOverride = null) {
  const { issuer } = await ensureIdentities(ctx);
  const resetResult = await resetBloomFilterService(ctx, manifestUrl, profileOverride);
  ctx.caches.revocationSetupByManifest.delete(`${issuer.did}|${manifestUrl}`);
  const revocationSetup = await ensureRevocationSetup(ctx, manifestUrl);
  return {
    manifestUrl,
    resetUrl: resetResult.resetUrl,
    manifestHash: revocationSetup.liveManifest?.manifestHash || null,
    manifestBytes: revocationSetup.liveManifest?.manifestBytes || null,
  };
}

async function bootstrapBloomAndManifestState(ctx, command) {
  if (ctx.config.bloomBootstrap?.resetBeforeRun === false) {
    return [];
  }

  const manifestUrls = collectManifestUrlsForCommand(ctx, command);
  if (manifestUrls.length === 0) return [];

  const results = [];
  for (const manifestUrl of manifestUrls) {
    results.push(await bootstrapManifestState(ctx, manifestUrl, findFilterProfileByManifestUrl(ctx, manifestUrl)));
  }
  return results;
}

async function createRevocableFixture(ctx, options) {
  const windowCount = Number(options.windowCount);
  if (!Number.isInteger(windowCount) || windowCount <= 0) {
    throw new Error(`windowCount inválido: ${options.windowCount}`);
  }
  const persistHolderCredential = options.persistHolderCredential === true;
  const requireHolderWalletCredential = options.requireHolderWalletCredential === true;

  const { issuer, holder, linkSecretId } = await ensureIdentities(ctx);
  const schemaAndCredDef = await ensureSchemaAndCredDef(ctx);
  const manifestUrl = firstNonEmpty(options.manifestUrl, ctx.config.manifestUrl);
  const revocationSetup = await ensureRevocationSetup(ctx, manifestUrl);
  const offerId = uniqueId("offer");
  const issuerLocalCredentialId = uniqueId(options.fixtureLabel || "issued-revocable");
  const baseValues = buildBenchmarkValues(
    ctx.config.credentialValues,
    issuerLocalCredentialId.slice(-10)
  );

  const credDefJsonLedgerRaw = await ssi.fetchCredDefFromLedger(
    ctx.config.genesisPathResolved,
    schemaAndCredDef.credDefId
  );
  const credDefJsonLedger = unwrapLedgerPayload(parseMaybeJson(credDefJsonLedgerRaw, null));

  const offerJson = await ssi.createCredentialOffer(schemaAndCredDef.credDefId, offerId);
  let walletOfferStoreError = null;
  if (persistHolderCredential) {
    try {
      await ssi.storeReceivedOffer(offerJson);
    } catch (error) {
      walletOfferStoreError = String(error?.message || error || "erro desconhecido");
    }
  }
  const requestJson = await ssi.createCredentialRequest(
    linkSecretId,
    holder.did,
    credDefJsonLedgerRaw,
    offerJson
  );
  const offerObj = parseMaybeJson(offerJson, null);
  const requestObj = parseMaybeJson(requestJson, null);

  const unitOfTime = firstNonEmpty(options.unitOfTime, ctx.config.time?.unitOfTime, "day");
  const timeWindow = Number(options.timeWindow ?? ctx.config.time?.timeWindow ?? 1);
  const startTime = Number(options.startTime ?? ctx.config.time?.startTimeEpoch ?? Math.floor(Date.now() / 1000));
  const extraWindowsForFp = Number(
    options.extraWindowsForFp
    ?? ctx.config.extraWindowsForFp
    ?? DEFAULT_EXTRA_WINDOWS_FOR_FP
  );
  const validityEnd = computeValidityEndFromBaseWindowCount(startTime, unitOfTime, timeWindow, windowCount);

  const issueMeasured = await measureAsync(() => ssi.issueRevocableCredential(
    ctx.config.genesisPathResolved,
    issuerLocalCredentialId,
    holder.did,
    schemaAndCredDef.credDefId,
    schemaAndCredDef.schemaId,
    offerJson,
    requestJson,
    JSON.stringify(baseValues),
    startTime,
    validityEnd,
    unitOfTime,
    timeWindow,
    extraWindowsForFp,
    JSON.stringify(revocationSetup.liveManifest.manifestObj),
    firstNonEmpty(revocationSetup.kLedgerAnchor?.k_vector_id, revocationSetup.kVector?.k_vector_id),
    null
  ));

  const issuePackage = parseMaybeJson(issueMeasured.value, null);
  if (!issuePackage || typeof issuePackage !== "object") {
    throw new Error("Pacote revogável inválido retornado pelo addon.");
  }

  const holderBundle = issuePackage.holder_bundle;
  const controlValues = issuePackage.control_values || {};
  const credentialJson = issuePackage.credential_json;
  const credentialJsonObject = parseMaybeJson(credentialJson, null);
  const requestMetadataCandidates = [];
  const requestMetadataSeen = new Set();
  const pushRequestMetadataCandidate = (value, source) => {
    const id = String(value || "").trim();
    if (!id || requestMetadataSeen.has(id)) return;
    requestMetadataSeen.add(id);
    requestMetadataCandidates.push({
      id,
      source: firstNonEmpty(source, "unknown"),
    });
  };
  pushRequestMetadataCandidate(extractRequestMetadataIdFromCredential(credentialJsonObject), "credential_json");
  pushRequestMetadataCandidate(extractNonceFromRequest(requestObj), "request_json");
  pushRequestMetadataCandidate(extractNonceFromOffer(offerObj), "offer_json");

  const requestMetadataIdResolved = firstNonEmpty(
    requestMetadataCandidates[0]?.id,
    issuerLocalCredentialId
  );
  pushRequestMetadataCandidate(requestMetadataIdResolved, "fallback");
  let holderCredentialIdLocal = "";
  let holderCredentialStoreError = null;
  let holderCredentialRecord = null;
  if (persistHolderCredential) {
    const holderCredentialStoreErrors = [];
    const tryStoreCredential = async (credentialIdLocal, requestMetadataId) => extractStoredCredentialId(await ssi.storeCredential(
      credentialIdLocal,
      credentialJson,
      requestMetadataId,
      credDefJsonLedgerRaw,
      null
    ));

    for (const candidate of requestMetadataCandidates) {
      try {
        holderCredentialIdLocal = await tryStoreCredential(issuerLocalCredentialId, candidate.id);
        if (holderCredentialIdLocal) break;
      } catch (error) {
        const errorMessage = String(error?.message || error || "erro desconhecido");
        holderCredentialStoreErrors.push(`${candidate.source}:${candidate.id}:${errorMessage}`);

        if (isLikelyDuplicateError(error)) {
          const existingId = await findMatchingStoredCredentialId(
            credentialJsonObject,
            schemaAndCredDef.credDefId,
            issuerLocalCredentialId
          );
          if (existingId) {
            holderCredentialIdLocal = existingId;
            break;
          }

          try {
            holderCredentialIdLocal = await tryStoreCredential(`${issuerLocalCredentialId}-holder`, candidate.id);
            if (holderCredentialIdLocal) break;
          } catch (retryError) {
            holderCredentialStoreErrors.push(
              `${candidate.source}:${candidate.id}:retry:${String(retryError?.message || retryError || "erro desconhecido")}`
            );
          }
        }

        if (!isMissingRequestMetadataError(error) && !isInvalidSignatureProofError(error)) {
          break;
        }
      }
    }
    if (!holderCredentialIdLocal) {
      holderCredentialIdLocal = await findMatchingStoredCredentialId(
        credentialJsonObject,
        schemaAndCredDef.credDefId,
        issuerLocalCredentialId
      );
    }
    holderCredentialStoreError = holderCredentialStoreErrors.length > 0
      ? holderCredentialStoreErrors.join(" | ")
      : null;
    holderCredentialRecord = await getStoredCredentialRecordById(holderCredentialIdLocal);
    if (requireHolderWalletCredential && !holderCredentialRecord) {
      throw new Error(
        `Credencial do holder não foi armazenada na wallet para ${issuerLocalCredentialId}.`
        + (holderCredentialStoreError ? ` storeCredential: ${holderCredentialStoreError}` : "")
        + (walletOfferStoreError ? ` storeReceivedOffer: ${walletOfferStoreError}` : "")
      );
    }
  }
  const resolvedCredentialIdForBundle = firstNonEmpty(holderCredentialRecord?.id_local, holderCredentialIdLocal, issuerLocalCredentialId);
  const bundleIdLocal = `revocation-bundle-${resolvedCredentialIdForBundle}`;

  const revStoreRaw = await ssi.storeReceivedRevocableCredential(
    bundleIdLocal,
    JSON.stringify(holderBundle),
    resolvedCredentialIdForBundle
  );
  parseMaybeJson(revStoreRaw, null);
  holderCredentialIdLocal = firstNonEmpty(holderCredentialRecord?.id_local, holderCredentialIdLocal);

  const envelopeMeasured = await measureAsync(() => ssi.envelopePackAuthcrypt(
    issuer.did,
    holder.verkey,
    "anoncreds/revocable-credential-package-v2",
    uniqueId("thread"),
    JSON.stringify(issuePackage),
    null,
    null
  ));

  const storedBundleRaw = await ssi.getHolderRevocationBundle(bundleIdLocal);
  const storedBundle = parseMaybeJson(storedBundleRaw, null);
  const layout = deriveBundleWindowLayout(storedBundle);

  return {
    fixtureLabel: options.fixtureLabel || issuerLocalCredentialId,
    issuerLocalCredentialId,
    bundleIdLocal,
    windowCountRequested: windowCount,
    schemaId: schemaAndCredDef.schemaId,
    issueElapsedMs: round(issueMeasured.elapsedMs),
    envelopeElapsedMs: round(envelopeMeasured.elapsedMs),
    revocablePackageBytes: byteLengthUtf8(issuePackage),
    credentialJsonBytes: byteLengthUtf8(credentialJson),
    holderCredentialIdLocal,
    holderCredentialStoreError,
    walletOfferStoreError,
    credentialJsonObject,
    credDefId: schemaAndCredDef.credDefId,
    baseValues,
    holderBundleBytes: byteLengthUtf8(holderBundle),
    holderEnvelopeBytes: byteLengthUtf8(envelopeMeasured.value),
    manifestBytes: revocationSetup.liveManifest.manifestBytes,
    chunkCount: Number(revocationSetup.kLedgerAnchor?.chunk_count ?? 0),
    kVectorId: firstNonEmpty(revocationSetup.kLedgerAnchor?.k_vector_id, revocationSetup.kVector?.k_vector_id),
    controlValues,
    storedBundle,
    bundleLayout: layout,
    manifestUrl,
  };
}

async function revokeFixtureCredential(ctx, fixture, revokeFromWindow) {
  const manifestBefore = await fetchBloomManifestDiagnostics(fixture.manifestUrl);
  const preflightRaw = await ssi.preflightRevokeIssuedCredential(
    fixture.issuerLocalCredentialId,
    revokeFromWindow
  );
  const preflight = parseMaybeJson(preflightRaw, null);

  const revokeMeasured = await measureAsync(() => ssi.revokeIssuedCredentialFromWindow(
    fixture.issuerLocalCredentialId,
    String(ctx.config.bloomAdminToken || ""),
    revokeFromWindow,
    "blindrevoke-bench",
    "tests/blindrevoke-bench.js"
  ));
  const revokeResult = parseMaybeJson(revokeMeasured.value, null);
  const manifestAfter = await fetchBloomManifestDiagnostics(fixture.manifestUrl);
  const issuerDid = firstNonEmpty(
    revokeResult?.issuer_record?.manifest?.issuer_did,
    fixture.storedBundle?.manifest?.issuer_did,
    fixture.credDefId?.split?.(":")?.[0]
  );
  const manifestVersion = firstNonEmpty(
    revokeResult?.issuer_record?.manifest?.manifest_version,
    fixture.storedBundle?.manifest?.manifest_version,
    ctx.config.manifestVersion,
    "1"
  );
  let manifestWrite = null;
  const shouldAnchorManifestAfterWrite = ctx.config.revocation?.anchorManifestAfterWrite === true;
  if (shouldAnchorManifestAfterWrite && issuerDid && fixture.manifestUrl) {
    try {
      const liveManifest = await buildLiveManifestAnchorData(issuerDid, fixture.manifestUrl, manifestVersion);
      const manifestWriteRaw = await ssi.revocationWriteManifestAnchorOnLedger(
        ctx.config.genesisPathResolved,
        issuerDid,
        liveManifest.manifestJson
      );
      manifestWrite = unwrapLedgerPayload(parseMaybeJson(manifestWriteRaw, manifestWriteRaw));
    } catch (error) {
      manifestWrite = {
        ok: false,
        issuerDid,
        manifestUrl: fixture.manifestUrl,
        error: String(error?.message || error || "erro desconhecido"),
      };
    }
  }

  return {
    revokeFromWindow,
    elapsedMs: round(revokeMeasured.elapsedMs),
    preflight,
    revokeResult,
    manifestBefore,
    manifestAfter,
    manifestWrite,
    manifestDelta: diffBloomManifestDiagnostics(manifestBefore, manifestAfter),
    expectedKeysToWrite: Number(
      preflight?.preflight?.revocation_keys_to_write
      ?? preflight?.revocation_keys_to_write
      ?? 0
    ),
    actualKeysWritten: Number(revokeResult?.revocation_keys_written || 0),
    bloomInserted: Number(revokeResult?.bloom?.inserted || 0),
  };
}

async function verifyWindowScanStep(
  ctx,
  bundleIdLocal,
  credentialIdLocal,
  expectedRootMerkleL,
  step,
  policyJson,
  manifestOverride
) {
  const buildMeasured = await measureAsync(() => ssi.buildPresentationRevocationProofV2(
    bundleIdLocal,
    step.primaryWindowIndex,
    step.additionalWindowCount,
    credentialIdLocal || null
  ));

  const buildData = parseMaybeJson(buildMeasured.value, null);
  const proofSequence = buildData?.proof_sequence || buildData;
  if (!proofSequence || typeof proofSequence !== "object") {
    return {
      ok: false,
      error: "Falha montando proof_sequence.",
      proofSequence: null,
      status: null,
      run: {
        primaryWindowIndex: step.primaryWindowIndex,
        additionalWindowCount: step.additionalWindowCount,
        buildElapsedMs: round(buildMeasured.elapsedMs),
        verifyElapsedMs: null,
        status: null,
      },
    };
  }

  const normalizedProofSequence = manifestOverride
    ? applyManifestAnchorToProofSequence(proofSequence, cloneJsonLike(manifestOverride))
    : proofSequence;

  const verifyMeasured = await measureAsync(() => ssi.verifyPresentationRevocationProofV2(
    JSON.stringify(normalizedProofSequence),
    expectedRootMerkleL || null,
    policyJson ? JSON.stringify(policyJson) : null,
    false
  ));
  const verifyData = parseMaybeJson(verifyMeasured.value, null);
  const status = verifyData?.status || verifyData;

  return {
    ok: !!status,
    error: status ? null : "Falha verificando proof_sequence.",
    proofSequence: normalizedProofSequence,
    status,
    run: {
      primaryWindowIndex: step.primaryWindowIndex,
      additionalWindowCount: step.additionalWindowCount,
      buildElapsedMs: round(buildMeasured.elapsedMs),
      verifyElapsedMs: round(verifyMeasured.elapsedMs),
      totalElapsedMs: round(buildMeasured.elapsedMs + verifyMeasured.elapsedMs),
      status: compactStatus(status),
    },
  };
}

function classifyProbeStatus(status) {
  if (!status?.verified) return "invalid";
  if (status?.revoked) return "candidate";
  if (status?.requires_more_windows) return "candidate";
  if (Number(status?.consecutive_hits ?? 0) > 0) return "candidate";
  if (status?.accepted && !status?.revoked) return "clean";
  if (status?.decision === "valid_not_revoked") return "clean";
  if (status?.decision === "false_positive_confirmed") return "clean";
  return "invalid";
}

async function runTailConfirmationCheck(scanPlan, getConfirmationResult) {
  const endWindowIndex = Math.trunc(Number(scanPlan.lastValidWindowIndex || 0));
  const checkedWindows = Math.min(DEFAULT_TAIL_CONFIRMATION_WINDOWS, endWindowIndex + 1);
  const startWindowIndex = Math.max(0, endWindowIndex - checkedWindows + 1);

  let suspiciousResult = null;
  for (let windowIndex = startWindowIndex; windowIndex <= endWindowIndex; windowIndex += 1) {
    const entry = await getConfirmationResult(windowIndex);
    const status = entry?.result?.status || null;
    if (!entry?.result?.ok || !status?.verified) {
      return {
        outcome: "invalid",
        checkedWindows,
        startWindowIndex,
        endWindowIndex,
      };
    }
    if (
      status.revoked
      || status.requires_more_windows
      || Number(status.consecutive_hits ?? 0) > 0
    ) {
      suspiciousResult = entry?.result;
      break;
    }
  }

  return suspiciousResult
    ? {
      outcome: "needs_more_windows",
      status: suspiciousResult.status || null,
      checkedWindows,
      startWindowIndex,
      endWindowIndex,
    }
    : {
      outcome: "clean",
      checkedWindows,
      startWindowIndex,
      endWindowIndex,
    };
}

async function verifyBundleStatusHeadless(ctx, params) {
  const bundle = params.bundle;
  const bundleIdLocal = params.bundleIdLocal;
  const credentialIdLocal = params.credentialIdLocal || null;
  const expectedRootMerkleL = firstNonEmpty(
    params.expectedRootMerkleL,
    bundle?.control?.root_merkle_l,
    bundle?.control?.root_merkle_L
  );
  const policyJson = params.policyJson || null;
  const binaryThreshold = Number(params.binaryThreshold ?? DEFAULT_BINARY_THRESHOLD);
  const additionalWindowCap = Number(params.additionalWindowCap ?? DEFAULT_EXTRA_WINDOWS_FOR_FP);
  const concurrency = Number(params.concurrency ?? DEFAULT_VERIFY_CONCURRENCY);
  const manifestSeedSequence = {
    issuer_did: bundle?.manifest?.issuer_did || null,
    primary_proof: {
      manifest: bundle?.manifest || null,
      cred_def_id: bundle?.cred_def_id || null,
    },
  };
  const manifestRefresh = await refreshProofSequenceManifestAnchorsHeadless(ctx, manifestSeedSequence);
  const effectiveManifest = manifestRefresh?.effectiveManifest || bundle?.manifest || null;

  const scanPlan = buildExhaustiveWindowScanPlan(bundle, additionalWindowCap);
  const startedAtNs = process.hrtime.bigint();
  const scanRuns = [];

  if (scanPlan.steps.length >= binaryThreshold) {
    const cachedProbeResults = new Map();
    const cachedConfirmationResults = new Map();
    let fallbackToExhaustive = false;
    let fallbackReason = "";

    const getProbeResult = async (windowIndex) => {
      const key = Math.max(0, Math.trunc(Number(windowIndex) || 0));
      if (cachedProbeResults.has(key)) return cachedProbeResults.get(key);
      const step = {
        primaryWindowIndex: key,
        additionalWindowCount: 0,
        lastConfirmationWindowIndex: scanPlan.lastConfirmationWindowIndex,
      };
      const result = await verifyWindowScanStep(
        ctx,
        bundleIdLocal,
        credentialIdLocal,
        expectedRootMerkleL,
        step,
        policyJson,
        effectiveManifest
      );
      const entry = { index: key, step, result };
      cachedProbeResults.set(key, entry);
      scanRuns.push(result.run);
      return entry;
    };

    const getConfirmationResult = async (windowIndex) => {
      const key = Math.max(0, Math.trunc(Number(windowIndex) || 0));
      if (cachedConfirmationResults.has(key)) return cachedConfirmationResults.get(key);
      const step = buildWindowScanStep(scanPlan, key, additionalWindowCap);
      const result = await verifyWindowScanStep(
        ctx,
        bundleIdLocal,
        credentialIdLocal,
        expectedRootMerkleL,
        step,
        policyJson,
        effectiveManifest
      );
      const entry = { index: key, step, result };
      cachedConfirmationResults.set(key, entry);
      scanRuns.push(result.run);
      return entry;
    };

    let low = 0;
    let high = scanPlan.lastValidWindowIndex;
    let candidateEntry = null;

    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      const entry = await getProbeResult(mid);
      const probeClass = classifyProbeStatus(entry?.result?.status || null);

      if (!entry?.result?.ok || probeClass === "invalid") {
        fallbackToExhaustive = true;
        fallbackReason = entry?.result?.error || entry?.result?.status?.details || "resposta inconclusiva";
        break;
      }

      if (probeClass === "clean") {
        low = mid + 1;
      } else {
        const confirmationEntry = await getConfirmationResult(mid);
        const confirmationStatus = confirmationEntry?.result?.status || null;
        if (!confirmationEntry?.result?.ok || !confirmationStatus?.verified || confirmationStatus?.requires_more_windows) {
          fallbackToExhaustive = true;
          fallbackReason = confirmationEntry?.result?.error || confirmationStatus?.details || "confirmação inconclusiva";
          break;
        }

        if (confirmationStatus?.revoked) {
          candidateEntry = confirmationEntry;
          high = mid - 1;
        } else {
          low = mid + 1;
        }
      }
    }

    if (!fallbackToExhaustive) {
      if (candidateEntry) {
        let refinedCandidate = candidateEntry;
        while (refinedCandidate.index > 0) {
          const previousProbeEntry = await getProbeResult(refinedCandidate.index - 1);
          const previousProbeClass = classifyProbeStatus(previousProbeEntry?.result?.status || null);
          if (!previousProbeEntry?.result?.ok || previousProbeClass === "invalid") {
            fallbackToExhaustive = true;
            fallbackReason = previousProbeEntry?.result?.error || "refino binário inconclusivo";
            break;
          }
          if (previousProbeClass === "clean") break;

          const previousConfirmationEntry = await getConfirmationResult(refinedCandidate.index - 1);
          const previousConfirmationStatus = previousConfirmationEntry?.result?.status || null;
          if (!previousConfirmationEntry?.result?.ok || !previousConfirmationStatus?.verified || previousConfirmationStatus?.requires_more_windows) {
            fallbackToExhaustive = true;
            fallbackReason = previousConfirmationEntry?.result?.error || "refino binário inconclusivo";
            break;
          }
          if (!previousConfirmationStatus?.revoked) break;
          refinedCandidate = previousConfirmationEntry;
        }

        if (!fallbackToExhaustive) {
          const elapsedMs = Number(process.hrtime.bigint() - startedAtNs) / 1_000_000;
          const orderedRuns = scanRuns.slice().sort((a, b) => a.primaryWindowIndex - b.primaryWindowIndex);
          return {
            mode: "binary_window_search",
            ok: true,
            elapsedMs: round(elapsedMs),
            scannedWindows: orderedRuns.length,
            decision: "revoked",
            revoked: true,
            accepted: false,
            decisiveWindowIndex: refinedCandidate?.result?.run?.primaryWindowIndex
              ?? refinedCandidate?.step?.primaryWindowIndex
              ?? null,
            runs: orderedRuns,
          };
        }
      } else {
        const tail = await runTailConfirmationCheck(scanPlan, getConfirmationResult);
        if (tail.outcome === "clean") {
          const elapsedMs = Number(process.hrtime.bigint() - startedAtNs) / 1_000_000;
          const orderedRuns = scanRuns.slice().sort((a, b) => a.primaryWindowIndex - b.primaryWindowIndex);
          return {
            mode: "binary_window_search",
            ok: true,
            elapsedMs: round(elapsedMs),
            scannedWindows: orderedRuns.length,
            decision: "not_revoked",
            revoked: false,
            accepted: true,
            falsePositiveConfirmed: orderedRuns.some((run) => run?.status?.decision === "false_positive_confirmed"),
            runs: orderedRuns,
            tailConfirmation: tail,
          };
        }
        fallbackToExhaustive = true;
        fallbackReason = "tail confirmation inconclusiva";
      }
    }

    if (fallbackToExhaustive) {
      scanRuns.length = 0;
      params._fallbackReason = fallbackReason;
    }
  }

  for (let offset = 0; offset < scanPlan.steps.length; offset += concurrency) {
    const batch = scanPlan.steps.slice(offset, offset + concurrency);
    const batchResults = await Promise.all(batch.map((step) => verifyWindowScanStep(
      ctx,
      bundleIdLocal,
      credentialIdLocal,
      expectedRootMerkleL,
      step,
      policyJson,
      effectiveManifest
    )));
    batchResults.forEach((item) => scanRuns.push(item.run));

    const revokedItem = batchResults.find((item) => item.ok && item.status?.revoked);
    if (revokedItem) {
      const elapsedMs = Number(process.hrtime.bigint() - startedAtNs) / 1_000_000;
      const orderedRuns = scanRuns.slice().sort((a, b) => a.primaryWindowIndex - b.primaryWindowIndex);
      return {
        mode: "full_window_scan",
        ok: true,
        elapsedMs: round(elapsedMs),
        scannedWindows: orderedRuns.length,
        decision: "revoked",
        revoked: true,
        accepted: false,
        decisiveWindowIndex: revokedItem.run.primaryWindowIndex,
        runs: orderedRuns,
        fallbackReason: params._fallbackReason || null,
      };
    }

    const failedItem = batchResults.find((item) => !item.ok);
    if (failedItem) {
      const elapsedMs = Number(process.hrtime.bigint() - startedAtNs) / 1_000_000;
      return {
        mode: "full_window_scan",
        ok: false,
        elapsedMs: round(elapsedMs),
        scannedWindows: scanRuns.length,
        decision: "error",
        revoked: false,
        accepted: false,
        error: failedItem.error,
        runs: scanRuns,
        fallbackReason: params._fallbackReason || null,
      };
    }
  }

  const elapsedMs = Number(process.hrtime.bigint() - startedAtNs) / 1_000_000;
  const orderedRuns = scanRuns.slice().sort((a, b) => a.primaryWindowIndex - b.primaryWindowIndex);
  return {
    mode: "full_window_scan",
    ok: true,
    elapsedMs: round(elapsedMs),
    scannedWindows: orderedRuns.length,
    decision: "not_revoked",
    revoked: false,
    accepted: true,
    falsePositiveConfirmed: orderedRuns.some((run) => run?.status?.decision === "false_positive_confirmed"),
    runs: orderedRuns,
    fallbackReason: params._fallbackReason || null,
  };
}

function summarizeRuns(rawRuns, extra = {}) {
  const elapsedValues = rawRuns.map((item) => item.elapsedMs);
  const scannedWindowValues = rawRuns.map((item) => item.scannedWindows);
  return {
    ...extra,
    latencyMs: summarizeNumbers(elapsedValues),
    scannedWindows: summarizeNumbers(scannedWindowValues),
    decisions: rawRuns.reduce((acc, item) => {
      const key = firstNonEmpty(item.decision, "unknown");
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {}),
  };
}

function scenarioToWindow(windowCount, scenario) {
  switch (scenario) {
    case "revoked_early":
      return 0;
    case "revoked_middle":
      return Math.max(0, Math.floor(windowCount / 2));
    case "revoked_late":
      return Math.max(0, windowCount - 1);
    default:
      return null;
  }
}

async function runIssueMetricsBenchmark(ctx) {
  const iterations = Math.max(1, Number(ctx.config.issueIterations || 1));
  const windowCounts = Array.from(new Set(
    [
      ...(Array.isArray(ctx.config.issueWindowCounts) ? ctx.config.issueWindowCounts : []),
      ...(Array.isArray(ctx.config.verifyWindowCounts) ? ctx.config.verifyWindowCounts : []),
    ]
      .map((value) => Number(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  )).sort((a, b) => a - b);

  const rows = [];
  for (const windowCount of windowCounts) {
    logProgress(`issue-metrics: emitindo credencial para ${windowCount} janelas`);
    const runs = [];
    for (let iteration = 1; iteration <= iterations; iteration += 1) {
      const fixture = await createRevocableFixture(ctx, {
        fixtureLabel: `issue-${windowCount}-iter-${iteration}`,
        windowCount,
        manifestUrl: firstNonEmpty(ctx.config.filterProfiles?.default?.manifestUrl, ctx.config.manifestUrl),
      });
      runs.push(fixture);
    }
    const firstFixture = runs[0];
    rows.push({
      windowCountRequested: windowCount,
      experimentCount: iterations,
      baseWindowCount: firstFixture.bundleLayout.baseWindowCount,
      totalWindowCount: firstFixture.bundleLayout.totalWindowCount,
      confirmationWindowCount: firstFixture.bundleLayout.confirmationWindowCount,
      issueElapsedMs: summarizeNumbers(runs.map((item) => item.issueElapsedMs)).median,
      holderEnvelopeBytes: summarizeNumbers(runs.map((item) => item.holderEnvelopeBytes)).median,
      revocablePackageBytes: summarizeNumbers(runs.map((item) => item.revocablePackageBytes)).median,
      credentialJsonBytes: summarizeNumbers(runs.map((item) => item.credentialJsonBytes)).median,
      holderBundleBytes: summarizeNumbers(runs.map((item) => item.holderBundleBytes)).median,
      manifestBytes: summarizeNumbers(runs.map((item) => item.manifestBytes)).median,
      chunkCount: summarizeNumbers(runs.map((item) => item.chunkCount)).median,
      kVectorId: firstFixture.kVectorId,
    });
  }

  const result = {
    benchmark: "issue-metrics",
    generatedAt: new Date().toISOString(),
    configPath: ctx.config._configPath,
    iterations,
    rows,
  };
  writeJson(path.join(ctx.outputRoot, "issue-metrics.json"), result);
  writeCsv(path.join(ctx.outputRoot, "issue-metrics.csv"), rows);
  return result;
}

async function runVerifyLatencyBenchmark(ctx) {
  const scenarios = ["not_revoked", "revoked_early", "revoked_middle", "revoked_late"];
  const iterations = Math.max(1, Number(ctx.config.verifyIterations || 3));
  const warmupIterations = Math.max(0, Number(ctx.config.verifyWarmups || 1));
  const outputRows = [];
  const raw = [];

  for (const windowCount of ctx.config.verifyWindowCounts || []) {
    for (const scenario of scenarios) {
      logProgress(`verify-latency: preparando cenario ${scenario} com ${windowCount} janelas`);
      const fixture = await createRevocableFixture(ctx, {
        fixtureLabel: `verify-${windowCount}-${scenario}`,
        windowCount: Number(windowCount),
        manifestUrl: firstNonEmpty(ctx.config.filterProfiles?.default?.manifestUrl, ctx.config.manifestUrl),
      });

      const revokeFromWindow = scenarioToWindow(Number(windowCount), scenario);
      let revokeMetrics = null;
      if (revokeFromWindow !== null) {
        logProgress(`verify-latency: revogando cenario ${scenario} em ${windowCount} janelas a partir de ${revokeFromWindow}`);
        revokeMetrics = await revokeFixtureCredential(ctx, fixture, revokeFromWindow);
      }

      for (let i = 0; i < warmupIterations; i += 1) {
        await verifyBundleStatusHeadless(ctx, {
          bundle: fixture.storedBundle,
          bundleIdLocal: fixture.bundleIdLocal,
          credentialIdLocal: fixture.issuerLocalCredentialId,
          expectedRootMerkleL: firstNonEmpty(
            fixture.controlValues?.root_merkle_l,
            fixture.controlValues?.root_merkle_L
          ),
          binaryThreshold: Number(ctx.config.binarySearchThreshold ?? DEFAULT_BINARY_THRESHOLD),
        });
      }

      const runs = [];
      for (let iteration = 1; iteration <= iterations; iteration += 1) {
        const verifyResult = await verifyBundleStatusHeadless(ctx, {
          bundle: fixture.storedBundle,
          bundleIdLocal: fixture.bundleIdLocal,
          credentialIdLocal: fixture.issuerLocalCredentialId,
          expectedRootMerkleL: firstNonEmpty(
            fixture.controlValues?.root_merkle_l,
            fixture.controlValues?.root_merkle_L
          ),
          binaryThreshold: Number(ctx.config.binarySearchThreshold ?? DEFAULT_BINARY_THRESHOLD),
        });
        runs.push({
          iteration,
          elapsedMs: verifyResult.elapsedMs,
          scannedWindows: verifyResult.scannedWindows,
          mode: verifyResult.mode,
          decision: verifyResult.decision,
          revoked: verifyResult.revoked,
          accepted: verifyResult.accepted,
          decisiveWindowIndex: verifyResult.decisiveWindowIndex ?? null,
          falsePositiveConfirmed: !!verifyResult.falsePositiveConfirmed,
          fallbackReason: verifyResult.fallbackReason || null,
        });
      }

      const summary = summarizeRuns(runs, {
        windowCountRequested: Number(windowCount),
        scenario,
        revokedWindowIndex: revokeFromWindow,
        issueElapsedMs: fixture.issueElapsedMs,
        revokeElapsedMs: revokeMetrics?.elapsedMs ?? null,
      });
      raw.push({
        windowCountRequested: Number(windowCount),
        scenario,
        fixture,
        revokeMetrics,
        runs,
        summary,
      });
      outputRows.push({
        windowCountRequested: Number(windowCount),
        scenario,
        revokedWindowIndex: revokeFromWindow,
        warmupRunCount: warmupIterations,
        medianLatencyMs: summary.latencyMs.median,
        p95LatencyMs: summary.latencyMs.p95,
        medianScannedWindows: summary.scannedWindows.median,
        dominantMode: getDominantValue(runs.map((item) => item.mode)),
        verifyRunCount: summary.latencyMs.count,
        decisionHistogram: JSON.stringify(summary.decisions),
      });
    }
  }

  const result = {
    benchmark: "verify-latency",
    generatedAt: new Date().toISOString(),
    iterations,
    warmupIterations,
    rows: outputRows,
    raw,
  };
  writeJson(path.join(ctx.outputRoot, "verify-latency.json"), result);
  writeCsv(path.join(ctx.outputRoot, "verify-latency.csv"), outputRows);
  return result;
}

async function runFalsePositiveBenchmark(ctx) {
  const profile = ctx.config.filterProfiles?.falsePositive || {};
  const manifestUrl = firstNonEmpty(profile.manifestUrl, ctx.config.falsePositive?.manifestUrl);
  if (!manifestUrl) {
    throw new Error("O benchmark de falso positivo exige filterProfiles.falsePositive.manifestUrl na configuração.");
  }

  if (ctx.config.bloomBootstrap?.resetBeforeRun !== false) {
    try {
      const bootstrapResult = await bootstrapManifestState(ctx, manifestUrl, profile);
      writeJson(path.join(ctx.outputRoot, "false-positive-bootstrap.json"), {
        benchmark: "false-positive",
        generatedAt: new Date().toISOString(),
        bootstrap: bootstrapResult,
      });
    } catch (error) {
      const shouldSkip =
        (ctx.cli.command === "all" || ctx.cli.command === "campaign")
        && ctx.config.falsePositive?.skipIfServiceUnavailable !== false;
      if (shouldSkip) {
        const skippedResult = {
          benchmark: "false-positive",
          generatedAt: new Date().toISOString(),
          manifestUrl,
          skipped: true,
          skipReason: String(error?.message || error || "serviço Bloom indisponível"),
          fillerCount: 0,
          targetCount: 0,
          windowCount: Math.max(1, Number(ctx.config.falsePositive?.windowCount || 365)),
          observedFalsePositives: 0,
          observedFalsePositiveRate: 0,
          escapedFalsePositives: 0,
          escapedFalsePositiveRate: 0,
          latencyMs: summarizeNumbers([]),
          scannedWindows: summarizeNumbers([]),
          fillers: [],
          runs: [],
        };
        writeJson(path.join(ctx.outputRoot, "false-positive.json"), skippedResult);
        writeCsv(path.join(ctx.outputRoot, "false-positive.csv"), []);
        return skippedResult;
      }
      throw error;
    }
  }

  const fillerCount = Math.max(0, Number(ctx.config.falsePositive?.fillerCredentialCount || 0));
  const targetCount = Math.max(1, Number(ctx.config.falsePositive?.trialCredentialCount || 20));
  const windowCount = Math.max(1, Number(ctx.config.falsePositive?.windowCount || 365));
  logProgress(`false-positive: fillerCount=${fillerCount}, targetCount=${targetCount}, windowCount=${windowCount}`);

  const fillers = [];
  for (let i = 0; i < fillerCount; i += 1) {
    const fixture = await createRevocableFixture(ctx, {
      fixtureLabel: `fp-filler-${i + 1}`,
      windowCount,
      manifestUrl,
    });
    const revokeMetrics = await revokeFixtureCredential(ctx, fixture, 0);
    fillers.push({
      issuerLocalCredentialId: fixture.issuerLocalCredentialId,
      revokeElapsedMs: revokeMetrics.elapsedMs,
      expectedKeysToWrite: revokeMetrics.expectedKeysToWrite,
      actualKeysWritten: revokeMetrics.actualKeysWritten,
    });
  }

  const runs = [];
  for (let i = 0; i < targetCount; i += 1) {
    const fixture = await createRevocableFixture(ctx, {
      fixtureLabel: `fp-target-${i + 1}`,
      windowCount,
      manifestUrl,
    });
    const verifyResult = await verifyBundleStatusHeadless(ctx, {
      bundle: fixture.storedBundle,
      bundleIdLocal: fixture.bundleIdLocal,
      credentialIdLocal: fixture.issuerLocalCredentialId,
      expectedRootMerkleL: firstNonEmpty(
        fixture.controlValues?.root_merkle_l,
        fixture.controlValues?.root_merkle_L
      ),
      binaryThreshold: Number(ctx.config.binarySearchThreshold ?? DEFAULT_BINARY_THRESHOLD),
    });
    runs.push({
      trial: i + 1,
      elapsedMs: verifyResult.elapsedMs,
      scannedWindows: verifyResult.scannedWindows,
      mode: verifyResult.mode,
      decision: verifyResult.decision,
      revoked: verifyResult.revoked,
      accepted: verifyResult.accepted,
      falsePositiveConfirmed: !!verifyResult.falsePositiveConfirmed,
      escapedFalsePositive: !!verifyResult.revoked,
    });
  }

  const observedFalsePositives = runs.filter((item) => item.falsePositiveConfirmed).length;
  const escapedFalsePositives = runs.filter((item) => item.escapedFalsePositive).length;
  const result = {
    benchmark: "false-positive",
    generatedAt: new Date().toISOString(),
    manifestUrl,
    fillerCount,
    targetCount,
    windowCount,
    observedFalsePositives,
    observedFalsePositiveRate: round(observedFalsePositives / targetCount, 6),
    escapedFalsePositives,
    escapedFalsePositiveRate: round(escapedFalsePositives / targetCount, 6),
    latencyMs: summarizeNumbers(runs.map((item) => item.elapsedMs)),
    scannedWindows: summarizeNumbers(runs.map((item) => item.scannedWindows)),
    fillers,
    runs,
  };
  writeJson(path.join(ctx.outputRoot, "false-positive.json"), result);
  writeCsv(path.join(ctx.outputRoot, "false-positive.csv"), runs);
  return result;
}

async function runProofPayloadSizeBenchmark(ctx) {
  const iterations = Math.max(1, Number(ctx.config.proofIterations || 1));
  const proofWindowCounts = Array.isArray(ctx.config.proofWindowCounts) && ctx.config.proofWindowCounts.length > 0
    ? ctx.config.proofWindowCounts.map(Number)
    : [1, 10, 100, 365, 1000, 5000, 10000, 25000];

  const rows = [];
  const deliveredRows = [];
  for (const baseWindowCount of proofWindowCounts) {
    logProgress(`proof-payload-size: montando pacote completo com ${baseWindowCount} janelas válidas`);
    const fixture = await createRevocableFixture(ctx, {
      fixtureLabel: `presentation-package-${baseWindowCount}`,
      windowCount: baseWindowCount,
      manifestUrl: firstNonEmpty(ctx.config.filterProfiles?.default?.manifestUrl, ctx.config.manifestUrl),
      persistHolderCredential: true,
      requireHolderWalletCredential: true,
    });
    const fullRuns = [];
    const deliveredRuns = [];
    const deliveredWindowCount = computeDeliveredWindowCountFromTotal(fixture.bundleLayout.totalWindowCount);
    for (let iteration = 1; iteration <= iterations; iteration += 1) {
      fullRuns.push(await buildFullPresentationEnvelopeForFixture(ctx, fixture));
      deliveredRuns.push(await buildPresentationEnvelopeForFixture(ctx, fixture, {
        deliveredWindowCount,
      }));
    }
    rows.push({
      baseWindowCount,
      experimentCount: iterations,
      totalWindowCount: fixture.bundleLayout.totalWindowCount,
      confirmationWindowCount: fixture.bundleLayout.confirmationWindowCount,
      buildElapsedMs: summarizeNumbers(fullRuns.map((item) => item.buildElapsedMs)).median,
      anoncredsPresentationElapsedMs: summarizeNumbers(fullRuns.map((item) => item.anoncredsPresentationElapsedMs)).median,
      primaryProofOnlyElapsedMs: summarizeNumbers(fullRuns.map((item) => item.primaryProofOnlyElapsedMs)).median,
      fullProofSequenceElapsedMs: summarizeNumbers(fullRuns.map((item) => item.fullProofSequenceElapsedMs)).median,
      confirmationProofsEstimatedElapsedMs: summarizeNumbers(fullRuns.map((item) => item.confirmationProofsEstimatedElapsedMs)).median,
      packageBuildElapsedMs: summarizeNumbers(fullRuns.map((item) => item.packageBuildElapsedMs)).median,
      payloadSerializeElapsedMs: summarizeNumbers(fullRuns.map((item) => item.payloadSerializeElapsedMs)).median,
      envelopeEncryptElapsedMs: summarizeNumbers(fullRuns.map((item) => item.envelopeEncryptElapsedMs)).median,
      presentationPayloadBytes: summarizeNumbers(fullRuns.map((item) => byteLengthUtf8(item.presentationPayloadJson))).median,
      encryptedEnvelopeBytes: summarizeNumbers(fullRuns.map((item) => byteLengthUtf8(item.envelopeJson))).median,
      revocationProofSequencesCount: summarizeNumbers(fullRuns.map((item) => Number(item.revocationProofSequencesCount || 0))).median,
    });
    deliveredRows.push({
      baseWindowCount,
      experimentCount: iterations,
      totalWindowCount: fixture.bundleLayout.totalWindowCount,
      deliveredWindowCount,
      confirmationWindowCount: fixture.bundleLayout.confirmationWindowCount,
      buildElapsedMs: summarizeNumbers(deliveredRuns.map((item) => item.buildElapsedMs)).median,
      packageBuildElapsedMs: summarizeNumbers(deliveredRuns.map((item) => item.packageBuildElapsedMs)).median,
      payloadSerializeElapsedMs: summarizeNumbers(deliveredRuns.map((item) => item.payloadSerializeElapsedMs)).median,
      envelopeEncryptElapsedMs: summarizeNumbers(deliveredRuns.map((item) => item.envelopeEncryptElapsedMs)).median,
      presentationPayloadBytes: summarizeNumbers(deliveredRuns.map((item) => byteLengthUtf8(item.presentationPayloadJson))).median,
      encryptedEnvelopeBytes: summarizeNumbers(deliveredRuns.map((item) => byteLengthUtf8(item.envelopeJson))).median,
      revocationProofSequencesCount: summarizeNumbers(deliveredRuns.map((item) => Number(item.revocationProofSequencesCount || 0))).median,
    });
  }

  const result = {
    benchmark: "proof-payload-size",
    generatedAt: new Date().toISOString(),
    packageMode: "full_presentation_envelope_with_all_windows",
    iterations,
    rows,
    deliveredRows,
  };
  writeJson(path.join(ctx.outputRoot, "proof-payload-size.json"), result);
  writeCsv(path.join(ctx.outputRoot, "proof-payload-size.csv"), rows);
  return result;
}

async function runBloomThroughputBenchmark(ctx) {
  const sampleCredentialCount = Math.max(1, Number(ctx.config.throughput?.sampleCredentialCount || 20));
  const sampleWindowCount = Math.max(1, Number(ctx.config.throughput?.windowCount || 100));
  const revokeFromWindow = Math.max(0, Number(ctx.config.throughput?.revokeFromWindow || 0));
  const manifestUrl = firstNonEmpty(ctx.config.filterProfiles?.default?.manifestUrl, ctx.config.manifestUrl);
  logProgress(`bloom-throughput: ${sampleCredentialCount} credenciais, ${sampleWindowCount} janelas, revogacao a partir de ${revokeFromWindow}`);

  const fixtures = [];
  for (let i = 0; i < sampleCredentialCount; i += 1) {
    fixtures.push(await createRevocableFixture(ctx, {
      fixtureLabel: `throughput-${i + 1}`,
      windowCount: sampleWindowCount,
      manifestUrl,
    }));
  }

  const writeRuns = [];
  const writeStartedNs = process.hrtime.bigint();
  for (const fixture of fixtures) {
    const revokeMetrics = await revokeFixtureCredential(ctx, fixture, revokeFromWindow);
    writeRuns.push({
      issuerLocalCredentialId: fixture.issuerLocalCredentialId,
      elapsedMs: revokeMetrics.elapsedMs,
      expectedKeysToWrite: revokeMetrics.expectedKeysToWrite,
      actualKeysWritten: revokeMetrics.actualKeysWritten,
      bloomInserted: revokeMetrics.bloomInserted,
    });
  }
  const writeElapsedMs = Number(process.hrtime.bigint() - writeStartedNs) / 1_000_000;
  const totalBloomWrites = writeRuns.reduce(
    (sum, item) => sum + Math.max(0, Number(item.actualKeysWritten || item.bloomInserted || 0)),
    0
  );
  const writePerBloomOpLatencies = writeRuns
    .map((item) => {
      const writes = Math.max(0, Number(item.actualKeysWritten || item.bloomInserted || 0));
      return writes > 0 ? Number(item.elapsedMs) / writes : null;
    })
    .filter((value) => Number.isFinite(value));

  const proofs = [];
  for (const fixture of fixtures) {
    const buildData = parseMaybeJson(await ssi.buildPresentationRevocationProofV2(
      fixture.bundleIdLocal,
      0,
      0,
      fixture.issuerLocalCredentialId
    ), null);
    const proofSequence = buildData?.proof_sequence || buildData;
    proofs.push({
      fixture,
      proofSequence,
      expectedRootMerkleL: firstNonEmpty(
        fixture.controlValues?.root_merkle_l,
        fixture.controlValues?.root_merkle_L
      ),
    });
  }

  const readRuns = [];
  const readStartedNs = process.hrtime.bigint();
  for (const item of proofs) {
    const manifestRefresh = await refreshProofSequenceManifestAnchorsHeadless(ctx, item.proofSequence);
    const normalizedProofSequence = manifestRefresh?.proofSequence || item.proofSequence;
    const verifyMeasured = await measureAsync(() => ssi.verifyPresentationRevocationProofV2(
      JSON.stringify(normalizedProofSequence),
      item.expectedRootMerkleL,
      null,
      false
    ));
    const verifyData = parseMaybeJson(verifyMeasured.value, null);
    const status = verifyData?.status || verifyData;
    readRuns.push({
      issuerLocalCredentialId: item.fixture.issuerLocalCredentialId,
      elapsedMs: round(verifyMeasured.elapsedMs),
      decision: firstNonEmpty(status?.decision, "unknown"),
      revoked: !!status?.revoked,
      manifestSource: manifestRefresh?.source || "original",
    });
  }
  const readElapsedMs = Number(process.hrtime.bigint() - readStartedNs) / 1_000_000;

  const result = {
    benchmark: "bloom-throughput",
    generatedAt: new Date().toISOString(),
    sampleCredentialCount,
    sampleWindowCount,
    revokeFromWindow,
    totalBloomWrites,
    writesPerCredential: summarizeNumbers(writeRuns.map(
      (item) => Number(item.actualKeysWritten || item.bloomInserted || 0)
    )),
    writeCredentialLatencyMs: summarizeNumbers(writeRuns.map((item) => item.elapsedMs)),
    writeCredentialOpsPerSecond: round(sampleCredentialCount / Math.max(writeElapsedMs / 1000, 0.000001), 6),
    writeLatencyMs: summarizeNumbers(writePerBloomOpLatencies),
    writeOpsPerSecond: round(totalBloomWrites / Math.max(writeElapsedMs / 1000, 0.000001), 6),
    readLatencyMs: summarizeNumbers(readRuns.map((item) => item.elapsedMs)),
    readOpsPerSecond: round(sampleCredentialCount / Math.max(readElapsedMs / 1000, 0.000001), 6),
    writeRuns,
    readRuns,
  };
  writeJson(path.join(ctx.outputRoot, "bloom-throughput.json"), result);
  writeCsv(path.join(ctx.outputRoot, "bloom-throughput-write.csv"), writeRuns);
  writeCsv(path.join(ctx.outputRoot, "bloom-throughput-read.csv"), readRuns);
  return result;
}

async function runKVectorLedgerWriteBenchmark(ctx) {
  const benchmarkConfig = ctx.config.kVectorLedger && typeof ctx.config.kVectorLedger === "object"
    ? ctx.config.kVectorLedger
    : {};
  const iterations = Math.max(1, Number(benchmarkConfig.iterations || 1));
  const requestedChunkSizes = normalizeKVectorChunkSizeList(benchmarkConfig);

  const rows = [];
  const runs = [];
  for (const requestedChunkSizeBytes of requestedChunkSizes) {
    const requestedChunkSizeLabel = formatChunkSizeLabel(requestedChunkSizeBytes);
    logProgress(
      `k-vector-ledger-write: chunk ${requestedChunkSizeLabel}, ${iterations} registro(s) do vetor K`
    );

    const caseRuns = [];
    for (let iteration = 1; iteration <= iterations; iteration += 1) {
      const issuer = await createBenchmarkIssuer(ctx);
      const existingSetup = await readRevocationSetupFromLedger(ctx.config.genesisPathResolved, issuer.did);
      const existingAnchor = existingSetup?.activeKAnchor || null;
      const reusedExistingK = !!existingAnchor?.k_vector_id;

      let kSetupMeasured = null;
      let kSetup = null;
      let kVector = existingSetup?.activeKVector || null;
      let kWriteMeasured = null;
      let kWrite = null;
      let writeAnchor = null;
      let ledgerSetup = existingSetup;
      let writeStatus = "reused_existing";

      if (reusedExistingK) {
        logProgress(
          `k-vector-ledger-write: DID ${issuer.did} ja possui K ativo (${existingAnchor.k_vector_id}); reutilizando sem nova escrita`
        );
      } else {
        kSetupMeasured = await measureAsync(() => ssi.revocationSetupCreateK(
          issuer.did,
          null,
          requestedChunkSizeBytes
        ));
        kSetup = unwrapLedgerPayload(parseMaybeJson(kSetupMeasured.value, kSetupMeasured.value));
        kVector = kSetup?.k_vector || kSetup?.active_k_vector || kSetup?.activeKVector;
        if (!kVector) {
          throw new Error("O addon não retornou k_vector durante o benchmark de registro do vetor K.");
        }

        kWriteMeasured = await measureAsync(() => ssi.revocationWriteKVectorOnLedger(
          ctx.config.genesisPathResolved,
          issuer.did,
          JSON.stringify(kVector),
          requestedChunkSizeBytes
        ));
        kWrite = unwrapLedgerPayload(parseMaybeJson(kWriteMeasured.value, kWriteMeasured.value));
        writeAnchor = kWrite?.ledger_anchor || kWrite?.active_k_ledger_anchor || null;
        ledgerSetup = await readRevocationSetupFromLedger(ctx.config.genesisPathResolved, issuer.did);
        writeStatus = "written";
      }

      const resolvedAnchor = ledgerSetup?.activeKAnchor || writeAnchor || null;

      const run = {
        requestedChunkSizeBytes: requestedChunkSizeBytes ?? null,
        requestedChunkSizeLabel,
        iteration,
        issuerDid: issuer.did,
        issuerRole: issuer.role,
        reusedExistingK,
        writeStatus,
        setupCreateElapsedMs: kSetupMeasured ? round(kSetupMeasured.elapsedMs) : null,
        writeElapsedMs: kWriteMeasured ? round(kWriteMeasured.elapsedMs) : null,
        kVectorId: firstNonEmpty(resolvedAnchor?.k_vector_id, kVector?.k_vector_id, existingAnchor?.k_vector_id),
        vectorHash: firstNonEmpty(resolvedAnchor?.vector_hash, kVector?.vector_hash, existingAnchor?.vector_hash),
        chunkCount: Number(resolvedAnchor?.chunk_count ?? 0),
        effectiveChunkSizeBytes: Number(resolvedAnchor?.chunk_size_bytes ?? 0),
        totalBytes: Number(resolvedAnchor?.total_bytes ?? 0),
        valueCount: Number(resolvedAnchor?.value_count ?? 0),
        estimatedAttribWrites: estimateKVectorAttribWrites(resolvedAnchor),
        writeVerifiedOnLedger: !!ledgerSetup?.ready,
      };
      caseRuns.push(run);
      runs.push(run);
    }

    rows.push({
      requestedChunkSizeBytes: requestedChunkSizeBytes ?? null,
      requestedChunkSizeLabel,
      experimentCount: iterations,
      writeCount: caseRuns.filter((item) => item.writeStatus === "written").length,
      reusedExistingCount: caseRuns.filter((item) => item.reusedExistingK).length,
      status: caseRuns.every((item) => item.reusedExistingK)
        ? "reused_existing"
        : (caseRuns.some((item) => item.reusedExistingK) ? "mixed" : "written"),
      writeElapsedMs: summarizeNumbers(caseRuns.map((item) => item.writeElapsedMs)).median,
      setupCreateElapsedMs: summarizeNumbers(caseRuns.map((item) => item.setupCreateElapsedMs)).median,
      estimatedAttribWrites: summarizeNumbers(caseRuns.map((item) => item.estimatedAttribWrites)).median,
      chunkCount: summarizeNumbers(caseRuns.map((item) => item.chunkCount)).median,
      effectiveChunkSizeBytes: summarizeNumbers(caseRuns.map((item) => item.effectiveChunkSizeBytes)).median,
      totalBytes: summarizeNumbers(caseRuns.map((item) => item.totalBytes)).median,
      valueCount: summarizeNumbers(caseRuns.map((item) => item.valueCount)).median,
    });
  }

  const result = {
    benchmark: "k-vector-ledger-write",
    generatedAt: new Date().toISOString(),
    iterations,
    rows,
    runs,
  };
  writeJson(path.join(ctx.outputRoot, "k-vector-ledger-write.json"), result);
  writeCsv(path.join(ctx.outputRoot, "k-vector-ledger-write.csv"), rows);
  writeCsv(path.join(ctx.outputRoot, "k-vector-ledger-write-runs.csv"), runs);
  return result;
}

async function runIssuerRevocationBenchmark(ctx) {
  const iterations = Math.max(1, Number(ctx.config.issuerRevocationIterations || 1));
  const scenarios = ["revoked_early", "revoked_middle", "revoked_late"];
  const windowCounts = Array.from(new Set(
    (
      Array.isArray(ctx.config.issuerRevocationWindowCounts)
        ? ctx.config.issuerRevocationWindowCounts
        : (Array.isArray(ctx.config.verifyWindowCounts) ? ctx.config.verifyWindowCounts : [100, 365, 1000, 5000, 10000])
    )
      .map((value) => Number(value))
      .filter((value) => Number.isInteger(value) && value > 0)
  )).sort((a, b) => a - b);
  const manifestUrl = firstNonEmpty(ctx.config.filterProfiles?.default?.manifestUrl, ctx.config.manifestUrl);

  const rows = [];
  for (const windowCount of windowCounts) {
    for (const scenario of scenarios) {
      const revokeFromWindow = scenarioToWindow(windowCount, scenario);
      if (revokeFromWindow === null) continue;
      logProgress(`issuer-revocation: revogando credencial com ${windowCount} janelas no cenario ${scenario} (janela ${revokeFromWindow})`);
      const runs = [];
      for (let iteration = 1; iteration <= iterations; iteration += 1) {
        const fixture = await createRevocableFixture(ctx, {
          fixtureLabel: `issuer-revocation-${windowCount}-${scenario}-iter-${iteration}`,
          windowCount,
          manifestUrl,
        });
        const revokeMetrics = await revokeFixtureCredential(ctx, fixture, revokeFromWindow);
        runs.push(revokeMetrics);
      }
      rows.push({
        windowCountRequested: windowCount,
        scenario,
        experimentCount: iterations,
        revokeFromWindow,
        elapsedMs: summarizeNumbers(runs.map((item) => item.elapsedMs)).median,
        expectedKeysToWrite: summarizeNumbers(runs.map((item) => item.expectedKeysToWrite)).median,
        actualKeysWritten: summarizeNumbers(runs.map((item) => item.actualKeysWritten)).median,
        bloomInserted: summarizeNumbers(runs.map((item) => item.bloomInserted)).median,
      });
    }
  }

  const result = {
    benchmark: "issuer-revocation",
    generatedAt: new Date().toISOString(),
    iterations,
    rows,
  };
  writeJson(path.join(ctx.outputRoot, "issuer-revocation.json"), result);
  writeCsv(path.join(ctx.outputRoot, "issuer-revocation.csv"), rows);
  return result;
}

async function runCommand(ctx, command) {
  const commands = {
    "issue-metrics": runIssueMetricsBenchmark,
    "verify-latency": runVerifyLatencyBenchmark,
    "false-positive": runFalsePositiveBenchmark,
    "proof-payload-size": runProofPayloadSizeBenchmark,
    "bloom-throughput": runBloomThroughputBenchmark,
    "k-vector-ledger-write": runKVectorLedgerWriteBenchmark,
    "issuer-revocation": runIssuerRevocationBenchmark,
  };

  if (command === "all" || command === "campaign") {
    const results = {};
    const entries = Object.entries(commands);
    const totalStages = entries.length;
    for (let index = 0; index < entries.length; index += 1) {
      const [key, fn] = entries[index];
      const stageStartedAtMs = Date.now();
      logProgress(`iniciando benchmark ${key}`);
      results[key] = await fn(ctx);
      const stageElapsedMs = Date.now() - stageStartedAtMs;
      const percentComplete = round(((index + 1) / totalStages) * 100, 1);
      const stageItem = {
        benchmark: key,
        index: index + 1,
        totalStages,
        percentComplete,
        elapsedMs: round(stageElapsedMs),
        elapsedLabel: formatDurationMs(stageElapsedMs),
      };
      ctx.runMetrics.stageProgress.push(stageItem);
      logProgress(
        `benchmark ${key} concluido (${index + 1}/${totalStages}, ${percentComplete}% do total, etapa ${formatDurationMs(stageElapsedMs)})`
      );
    }
    return results;
  }

  const handler = commands[command];
  if (!handler) {
    throw new Error(`Comando desconhecido: ${command}`);
  }
  logProgress(`iniciando benchmark ${command}`);
  const stageStartedAtMs = Date.now();
  const result = await handler(ctx);
  const stageElapsedMs = Date.now() - stageStartedAtMs;
  ctx.runMetrics.stageProgress.push({
    benchmark: command,
    index: 1,
    totalStages: 1,
    percentComplete: 100,
    elapsedMs: round(stageElapsedMs),
    elapsedLabel: formatDurationMs(stageElapsedMs),
  });
  logProgress(`benchmark ${command} concluido (1/1, 100% do total, etapa ${formatDurationMs(stageElapsedMs)})`);
  return result;
}

async function main() {
  const cli = parseCliArgs(process.argv.slice(2));
  const config = loadConfig(cli.configPath);
  const ctx = buildContext(config, cli);

  const metadata = {
    command: cli.command,
    configPath: config._configPath,
    outputRoot: ctx.outputRoot,
    generatedAt: new Date().toISOString(),
    startedAt: new Date(ctx.runStartedAtMs).toISOString(),
  };
  writeJson(path.join(ctx.outputRoot, "_run.json"), metadata);

  try {
    await ensureWalletOpen(ctx);
    await connectLedger(ctx);
    const bootstrap = await bootstrapBloomAndManifestState(ctx, cli.command);
    if (bootstrap.length > 0) {
      writeJson(path.join(ctx.outputRoot, "_bootstrap.json"), {
        command: cli.command,
        generatedAt: new Date().toISOString(),
        bloomBootstrap: bootstrap,
      });
    }
    const result = await runCommand(ctx, cli.command);
    ctx.runMetrics.totalElapsedMs = Date.now() - ctx.runStartedAtMs;
    const resultWithMeta = {
      ...normalizeReportInput(result),
      _meta: {
        command: cli.command,
        totalElapsedMs: round(ctx.runMetrics.totalElapsedMs),
        totalElapsedLabel: formatDurationMs(ctx.runMetrics.totalElapsedMs),
        startedAt: new Date(ctx.runStartedAtMs).toISOString(),
        completedAt: new Date().toISOString(),
        stageProgress: ctx.runMetrics.stageProgress,
      },
    };
    writeJson(path.join(ctx.outputRoot, "_summary.json"), resultWithMeta);
    const reportIndex = writeReportArtifacts(ctx, result);
    writeJson(path.join(ctx.outputRoot, "_report.json"), reportIndex);
    writeJson(path.join(ctx.outputRoot, "_run.json"), {
      ...metadata,
      completedAt: new Date().toISOString(),
      totalElapsedMs: round(ctx.runMetrics.totalElapsedMs),
      totalElapsedLabel: formatDurationMs(ctx.runMetrics.totalElapsedMs),
      stageProgress: ctx.runMetrics.stageProgress,
    });
    writeJson(path.join(path.dirname(ctx.outputRoot), "latest-run.json"), {
      command: cli.command,
      outputRoot: ctx.outputRoot,
      reportDir: reportIndex.reportDir,
      paperSummary: path.join(reportIndex.reportDir, "paper-summary.md"),
      generatedAt: new Date().toISOString(),
      totalElapsedMs: round(ctx.runMetrics.totalElapsedMs),
      totalElapsedLabel: formatDurationMs(ctx.runMetrics.totalElapsedMs),
    });
    logProgress(`processamento total concluido em ${formatDurationMs(ctx.runMetrics.totalElapsedMs)}`);
    console.log(JSON.stringify({
      ok: true,
      command: cli.command,
      outputRoot: ctx.outputRoot,
      reportDir: reportIndex.reportDir,
      paperSummary: path.join(reportIndex.reportDir, "paper-summary.md"),
      totalElapsedMs: round(ctx.runMetrics.totalElapsedMs),
      totalElapsedLabel: formatDurationMs(ctx.runMetrics.totalElapsedMs),
    }, null, 2));
  } finally {
    try {
      await ssi.walletClose();
    } catch (_) {
      // ignora erro de cleanup
    }
  }
}

main().catch((error) => {
  const message = error?.stack || error?.message || String(error);
  console.error(message);
  process.exitCode = 1;
});
