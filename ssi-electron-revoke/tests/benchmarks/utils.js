const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

function parseMaybeJson(raw, fallback = null) {
  if (raw === undefined || raw === null) return fallback;
  if (typeof raw === "object") return raw;
  if (typeof raw !== "string") return fallback;
  try {
    return JSON.parse(raw);
  } catch (_) {
    return fallback;
  }
}

function firstNonEmpty(...values) {
  for (const value of values) {
    if (value === undefined || value === null) continue;
    const text = String(value).trim();
    if (text) return text;
  }
  return "";
}

function ensureDirSync(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function timestampTag(date = new Date()) {
  const pad = (n) => String(n).padStart(2, "0");
  return [
    date.getUTCFullYear(),
    pad(date.getUTCMonth() + 1),
    pad(date.getUTCDate()),
    "-",
    pad(date.getUTCHours()),
    pad(date.getUTCMinutes()),
    pad(date.getUTCSeconds()),
  ].join("");
}

function resolvePathFrom(baseDir, inputPath) {
  if (!inputPath) return "";
  if (path.isAbsolute(inputPath)) return inputPath;
  return path.resolve(baseDir, inputPath);
}

function sha256Base64(input) {
  return crypto.createHash("sha256").update(String(input), "utf-8").digest("base64");
}

function byteLengthUtf8(input) {
  if (input === undefined || input === null) return 0;
  if (typeof input === "string") return Buffer.byteLength(input, "utf-8");
  return Buffer.byteLength(JSON.stringify(input), "utf-8");
}

function round(value, decimals = 3) {
  const n = Number(value);
  if (!Number.isFinite(n)) return null;
  const factor = 10 ** decimals;
  return Math.round(n * factor) / factor;
}

function percentile(sortedValues, p) {
  if (!Array.isArray(sortedValues) || sortedValues.length === 0) return null;
  if (sortedValues.length === 1) return Number(sortedValues[0]);
  const rank = (sortedValues.length - 1) * p;
  const lower = Math.floor(rank);
  const upper = Math.ceil(rank);
  if (lower === upper) return Number(sortedValues[lower]);
  const weight = rank - lower;
  return Number(sortedValues[lower]) * (1 - weight) + Number(sortedValues[upper]) * weight;
}

function summarizeNumbers(values) {
  const numbers = (Array.isArray(values) ? values : [])
    .map((value) => Number(value))
    .filter((value) => Number.isFinite(value));

  if (numbers.length === 0) {
    return {
      count: 0,
      min: null,
      max: null,
      mean: null,
      median: null,
      p95: null,
      stdev: null,
    };
  }

  const sorted = numbers.slice().sort((a, b) => a - b);
  const sum = sorted.reduce((acc, value) => acc + value, 0);
  const mean = sum / sorted.length;
  const variance = sorted.length <= 1
    ? 0
    : sorted.reduce((acc, value) => acc + ((value - mean) ** 2), 0) / (sorted.length - 1);

  return {
    count: sorted.length,
    min: round(sorted[0]),
    max: round(sorted[sorted.length - 1]),
    mean: round(mean),
    median: round(percentile(sorted, 0.5)),
    p95: round(percentile(sorted, 0.95)),
    stdev: round(Math.sqrt(variance)),
  };
}

async function measureAsync(fn) {
  const startedAtNs = process.hrtime.bigint();
  const value = await fn();
  const elapsedNs = process.hrtime.bigint() - startedAtNs;
  const elapsedMs = Number(elapsedNs) / 1_000_000;
  return {
    value,
    elapsedMs,
    elapsedNs: elapsedNs.toString(),
  };
}

function writeJson(filePath, data) {
  ensureDirSync(path.dirname(filePath));
  fs.writeFileSync(filePath, `${JSON.stringify(data, null, 2)}\n`, "utf-8");
}

function csvEscape(value) {
  if (value === undefined || value === null) return "";
  const text = String(value);
  if (!text.includes(",") && !text.includes("\"") && !text.includes("\n")) return text;
  return `"${text.replace(/"/g, "\"\"")}"`;
}

function writeCsv(filePath, rows) {
  ensureDirSync(path.dirname(filePath));
  const records = Array.isArray(rows) ? rows : [];
  if (records.length === 0) {
    fs.writeFileSync(filePath, "", "utf-8");
    return;
  }
  const headers = Array.from(
    records.reduce((acc, row) => {
      Object.keys(row || {}).forEach((key) => acc.add(key));
      return acc;
    }, new Set())
  );
  const lines = [
    headers.map(csvEscape).join(","),
    ...records.map((row) => headers.map((header) => csvEscape(row?.[header])).join(",")),
  ];
  fs.writeFileSync(filePath, `${lines.join("\n")}\n`, "utf-8");
}

module.exports = {
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
};
