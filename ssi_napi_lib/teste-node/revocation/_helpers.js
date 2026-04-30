const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const base = require("../credentials/_helpers");

function makeKValues(count = 1024) {
  return Array.from({ length: count }, () => crypto.randomBytes(32).toString("base64"));
}

function cleanupWalletFamily(dbPath) {
  for (const p of [
    dbPath,
    dbPath + "-wal",
    dbPath + "-shm",
    dbPath + ".sidecar",
    dbPath + ".sidecar.json",
    dbPath + ".kdf.json",
  ]) {
    base.rmIfExists(p);
  }
}

function ensureWalletDir() {
  const walletDir = path.join(__dirname, "..", "wallets");
  fs.mkdirSync(walletDir, { recursive: true });
  return walletDir;
}

function sampleManifest(issuerDid) {
  return {
    issuer_did: issuerDid,
    manifest_url: "https://example.org/revocation/manifest.json",
    manifest_hash: crypto.randomBytes(32).toString("base64"),
    manifest_version: "1",
    updated_at: Math.floor(Date.now() / 1000),
  };
}

function sampleCredentialJson(overrides = {}) {
  return JSON.stringify({
    schema_id: "mock:schema:1",
    cred_def_id: "mock:creddef:1",
    values: {
      nome: "Alice",
      cpf: "12345678900",
      idade: "29",
    },
    ...overrides,
  });
}

function sampleKLedgerAnchor(issuerDid, overrides = {}) {
  return {
    issuer_did: issuerDid,
    k_vector_id: "k-vector-mock-001",
    version: 1,
    hash_algorithm: "sha3-256",
    vector_hash: crypto.randomBytes(32).toString("base64"),
    value_count: 1024,
    value_size_bytes: 32,
    total_bytes: 32768,
    chunk_count: 11,
    chunk_size_bytes: 3045,
    index_key: "REVOC_K_TEST_INDEX",
    chunk_prefix: "REVOC_K_TEST",
    created_at: Math.floor(Date.now() / 1000),
    ...overrides,
  };
}

module.exports = {
  ...base,
  makeKValues,
  cleanupWalletFamily,
  ensureWalletDir,
  sampleManifest,
  sampleCredentialJson,
  sampleKLedgerAnchor,
};
