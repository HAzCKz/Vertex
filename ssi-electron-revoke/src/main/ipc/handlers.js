const { ipcMain, dialog, BrowserWindow } = require("electron");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const { getWalletsDir } = require("../storage/paths");

const CH = require("./channels");

const { ok, fail } = require("../utll/result");
const { validateNonEmptyString } = require("../utll/validate");
const { sanitizeError } = require("../utll/sanitize");

const ssi = require("../ssi/ssi-api");

let __ipc_registered = false;
const __offer_cache = [];
const REVOCATION_CONTROL_ATTRIBUTE_CANONICAL_NAMES = [
  "root_merkle_L",
  "seed",
  "start_time",
  "time_window",
  "unit_of_time",
];
const REVOCATION_ACTIVE_K_ATTR_KEY = "REVOCATION_K_ACTIVE";
const REVOCATION_MANIFEST_ATTR_KEY = "REVOCATION_MANIFEST";
const REVOCATION_MANIFEST_REFRESH_CACHE_TTL_MS = 30_000;
const revocationManifestRefreshCache = new Map();
const REVOCATION_CONTROL_ATTRIBUTE_NAMES = new Set([
  "root_merkle_l",
  ...REVOCATION_CONTROL_ATTRIBUTE_CANONICAL_NAMES,
]);

function toJsonString(obj) {
  return obj ? JSON.stringify(obj) : "{}";
}

function formatCredentialIdTimestamp(date = new Date()) {
  const pad = (n, size = 2) => String(n).padStart(size, "0");
  return [
    date.getFullYear(),
    pad(date.getMonth() + 1),
    pad(date.getDate()),
  ].join("") + "-" + [
    pad(date.getHours()),
    pad(date.getMinutes()),
    pad(date.getSeconds()),
  ].join("") + "-" + pad(date.getMilliseconds(), 3);
}

function safeHandler(fn) {
  return async (_evt, input) => {
    try {
      const data = await fn(input || {});
      return ok(data);
    } catch (e) {
      return fail(sanitizeError(e));
    }
  };
}

function getDialogOwnerWindow() {
  try {
    return BrowserWindow.getFocusedWindow() || null;
  } catch (_) {
    return null;
  }
}

function showSaveDialog(options) {
  const owner = getDialogOwnerWindow();
  return owner
    ? dialog.showSaveDialog(owner, options)
    : dialog.showSaveDialog(options);
}

function showOpenDialog(options) {
  const owner = getDialogOwnerWindow();
  return owner
    ? dialog.showOpenDialog(owner, options)
    : dialog.showOpenDialog(options);
}

function parseJsonMaybeString(raw, fallbackValue = null) {
  if (raw === undefined || raw === null) return fallbackValue;
  if (typeof raw === "object") return raw;
  if (typeof raw === "string") {
    try {
      return JSON.parse(raw);
    } catch (_) {
      return fallbackValue;
    }
  }
  return fallbackValue;
}

function sha256Base64(input) {
  return crypto.createHash("sha256").update(String(input || ""), "utf-8").digest("base64");
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

function extractDidImportRows(rawPayload) {
  const payload = parseJsonMaybeString(rawPayload, rawPayload);

  if (Array.isArray(payload)) {
    return { recognized: true, dids: payload };
  }

  if (!payload || typeof payload !== "object") {
    return { recognized: false, dids: [] };
  }

  if (Array.isArray(payload.dids)) {
    return { recognized: true, dids: payload.dids };
  }

  const nestedCandidates = [payload.data, payload.payload, payload.result, payload.value];
  for (const candidateRaw of nestedCandidates) {
    const candidate = parseJsonMaybeString(candidateRaw, candidateRaw);
    if (Array.isArray(candidate)) {
      return { recognized: true, dids: candidate };
    }
    if (candidate && typeof candidate === "object" && Array.isArray(candidate.dids)) {
      return { recognized: true, dids: candidate.dids };
    }
  }

  return { recognized: false, dids: [] };
}

function normalizeDidImportItem(item) {
  const rec = parseJsonMaybeString(item, item);
  if (!rec || typeof rec !== "object") {
    return { did: "", verkey: "", alias: "" };
  }
  return {
    did: firstNonEmpty(rec.did, rec.id, rec.did_id, rec.didId),
    verkey: firstNonEmpty(
      rec.verkey,
      rec.verKey,
      rec.ver_key,
      rec.verification_key,
      rec.verificationKey,
      rec.key
    ),
    alias: firstNonEmpty(rec.alias, rec.name, rec.label),
  };
}

function isDidNotFoundMessage(msg) {
  const text = String(msg || "").toLowerCase();
  return text.includes("not found")
    || text.includes("não encontrado")
    || text.includes("nao encontrado")
    || text.includes("unknown did")
    || text.includes("wallet item not found")
    || text.includes("record not found");
}

function extractDidFromGetDidResponse(raw, expectedDid) {
  if (raw === undefined || raw === null) return "";

  if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (!trimmed) return "";

    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      const parsed = parseJsonMaybeString(trimmed, null);
      return extractDidFromGetDidResponse(parsed, expectedDid);
    }

    if (isDidNotFoundMessage(trimmed)) return "";
    return trimmed === String(expectedDid || "").trim() ? trimmed : "";
  }

  if (Array.isArray(raw)) {
    for (const item of raw) {
      const found = extractDidFromGetDidResponse(item, expectedDid);
      if (found) return found;
    }
    return "";
  }

  if (typeof raw === "object") {
    const errText = firstNonEmpty(raw?.error, raw?.message, raw?.reason);
    if (isDidNotFoundMessage(errText)) return "";
    return firstNonEmpty(raw?.did, raw?.id, raw?.did_id, raw?.didId);
  }

  return "";
}

function shouldTreatAsDidAlreadyExists(err) {
  const msg = String(err?.message || err || "").toLowerCase();
  return isLikelyDuplicateError(err)
    || msg.includes("already exists")
    || msg.includes("did already exists");
}

function isCategoryTypeError(err) {
  const msg = String(err?.message || err || "").toLowerCase();
  return msg.includes("category_type");
}

async function didExistsInWallet(did, existingDidsSet) {
  const didTrimmed = String(did || "").trim();
  if (!didTrimmed) return false;

  if (existingDidsSet?.has(didTrimmed)) return true;

  try {
    const got = await ssi.getDid(didTrimmed);
    const foundDid = extractDidFromGetDidResponse(got, didTrimmed);
    if (foundDid) {
      existingDidsSet?.add(foundDid);
      return true;
    }
    return false;
  } catch (e) {
    if (isDidNotFoundMessage(e?.message || e)) return false;
    throw e;
  }
}

async function storeDidAsExternal(did, verkey, alias = "") {
  try {
    return await ssi.storeTheirDid(did, verkey, alias);
  } catch (e) {
    if (!isCategoryTypeError(e)) throw e;

    // Fallback para addons que exigem category_type explícito na importação batch.
    const payload = [{
      did: String(did),
      verkey: String(verkey),
      alias: String(alias || ""),
      type: "external",
      category_type: "external",
    }];
    return ssi.importDidsBatch(JSON.stringify(payload));
  }
}

function unwrapLedgerPayload(raw) {
  let current = raw;
  for (let i = 0; i < 6; i += 1) {
    if (typeof current === "string") {
      const parsed = parseJsonMaybeString(current, null);
      if (!parsed || parsed === current) break;
      current = parsed;
      continue;
    }

    if (!current || typeof current !== "object") break;

    if (typeof current.json === "string") {
      const parsed = parseJsonMaybeString(current.json, null);
      if (parsed) {
        current = parsed;
        continue;
      }
    }
    if (typeof current.data === "string") {
      const parsed = parseJsonMaybeString(current.data, null);
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
      const parsed = parseJsonMaybeString(current.result, null);
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
      const parsed = parseJsonMaybeString(current.value, null);
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

async function tryReadRevocationManifestFromLedger(genesisPath, issuerDid) {
  try {
    const raw = await ssi.revocationReadManifestAnchorFromLedger(genesisPath, issuerDid);
    const parsed = parseJsonMaybeString(raw, raw);
    const unwrapped = unwrapLedgerPayload(parsed);
    if (isLedgerLookupMiss(parsed, unwrapped)) return null;
    return unwrapped?.manifest || parsed?.manifest || null;
  } catch (e) {
    const parsed = parseJsonMaybeString(e?.message, null);
    if (isLedgerLookupMiss(e, parsed)) return null;
    throw e;
  }
}

async function buildLiveManifestAnchorData(issuerDid, manifestUrl, manifestVersionOpt) {
  const normalizedIssuerDid = String(issuerDid || "").trim();
  const normalizedManifestUrl = String(manifestUrl || "").trim();
  const manifestVersion = firstNonEmpty(manifestVersionOpt, "1");

  validateNonEmptyString(normalizedIssuerDid, "issuerDid");
  validateNonEmptyString(normalizedManifestUrl, "manifestUrl");

  const manifestResp = await fetch(normalizedManifestUrl);
  if (!manifestResp.ok) {
    const e = new Error(`Falha ao ler manifesto em ${normalizedManifestUrl}: HTTP ${manifestResp.status}`);
    e.code = "MANIFEST_FETCH_FAILED";
    e.details = { manifestUrl: normalizedManifestUrl, httpStatus: manifestResp.status };
    throw e;
  }

  const manifestBodyText = await manifestResp.text();
  const manifestHash = sha256Base64(manifestBodyText);
  const manifestEnvelope = parseJsonMaybeString(manifestBodyText, null);
  const manifestJson = await ssi.revocationBuildManifestAnchor(
    normalizedIssuerDid,
    normalizedManifestUrl,
    manifestHash,
    manifestVersion
  );
  const manifestObj = parseJsonMaybeString(manifestJson, null);
  if (!manifestObj || typeof manifestObj !== "object" || Array.isArray(manifestObj)) {
    const e = new Error("Não foi possível construir o manifesto de revogação.");
    e.code = "INVALID_MANIFEST_ANCHOR";
    throw e;
  }

  return {
    manifestObj,
    manifestJson: JSON.stringify(manifestObj),
    manifestSourceUrl: normalizedManifestUrl,
    manifestHashLocal: manifestHash,
    manifestEnvelope,
    manifestBytes: Buffer.byteLength(manifestBodyText, "utf-8"),
  };
}

async function writeLatestManifestAnchorToLedger(genesisPath, issuerDid, manifestUrl, manifestVersionOpt) {
  const liveManifest = await buildLiveManifestAnchorData(issuerDid, manifestUrl, manifestVersionOpt);
  const writeRaw = await ssi.revocationWriteManifestAnchorOnLedger(
    String(genesisPath || "").trim(),
    String(issuerDid || "").trim(),
    liveManifest.manifestJson
  );
  const writeParsed = parseJsonMaybeString(writeRaw, writeRaw);
  const writeData = unwrapLedgerPayload(writeParsed);

  return {
    ...writeData,
    manifestSourceUrl: liveManifest.manifestSourceUrl,
    manifestHashLocal: liveManifest.manifestHashLocal,
    manifestEnvelope: liveManifest.manifestEnvelope,
    manifestBytes: liveManifest.manifestBytes,
  };
}

async function checkManifestAnchorStatus(genesisPath, issuerDid, manifestUrl, manifestVersionOpt) {
  const normalizedGenesisPath = String(genesisPath || "").trim();
  const normalizedIssuerDid = String(issuerDid || "").trim();
  const normalizedManifestUrl = String(manifestUrl || "").trim();
  const manifestVersion = firstNonEmpty(manifestVersionOpt, "1");

  validateNonEmptyString(normalizedGenesisPath, "genesisPath");
  validateNonEmptyString(normalizedIssuerDid, "issuerDid");
  validateNonEmptyString(normalizedManifestUrl, "manifestUrl");

  const ledgerManifest = await tryReadRevocationManifestFromLedger(
    normalizedGenesisPath,
    normalizedIssuerDid
  );
  const liveManifest = await buildLiveManifestAnchorData(
    normalizedIssuerDid,
    normalizedManifestUrl,
    manifestVersion
  );

  const effectiveLiveManifest = liveManifest?.manifestObj || null;
  const differences = [];

  if (!ledgerManifest) {
    differences.push("Manifesto ainda não ancorado no ledger.");
  } else {
    if (firstNonEmpty(ledgerManifest?.issuer_did) !== firstNonEmpty(effectiveLiveManifest?.issuer_did)) {
      differences.push("issuer_did divergente.");
    }
    if (firstNonEmpty(ledgerManifest?.manifest_url) !== firstNonEmpty(effectiveLiveManifest?.manifest_url)) {
      differences.push("manifest_url divergente.");
    }
    if (firstNonEmpty(ledgerManifest?.manifest_hash) !== firstNonEmpty(effectiveLiveManifest?.manifest_hash)) {
      differences.push("manifest_hash divergente.");
    }
    if (firstNonEmpty(ledgerManifest?.manifest_version, "1") !== firstNonEmpty(effectiveLiveManifest?.manifest_version, "1")) {
      differences.push("manifest_version divergente.");
    }
  }

  return {
    issuerDid: normalizedIssuerDid,
    manifestUrl: normalizedManifestUrl,
    manifestVersion,
    ledgerManifest: ledgerManifest || null,
    liveManifest: effectiveLiveManifest,
    manifestSourceUrl: liveManifest.manifestSourceUrl,
    manifestHashLocal: liveManifest.manifestHashLocal,
    manifestEnvelope: liveManifest.manifestEnvelope,
    manifestBytes: liveManifest.manifestBytes,
    upToDate: differences.length === 0,
    needsAnchor: differences.length > 0,
    differences,
  };
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

function cloneJsonLike(value) {
  if (value === undefined || value === null) return value;
  return JSON.parse(JSON.stringify(value));
}

function makeRevocationManifestRefreshCacheKey({
  genesisPath,
  issuerDid,
  manifestUrl,
  manifestVersion,
  previousManifestHash,
}) {
  return [
    String(genesisPath || "").trim(),
    String(issuerDid || "").trim(),
    String(manifestUrl || "").trim(),
    String(manifestVersion || "").trim(),
    String(previousManifestHash || "").trim(),
  ].join("|");
}

function getCachedRevocationManifestRefresh(cacheKey) {
  const cached = revocationManifestRefreshCache.get(cacheKey);
  if (!cached) return null;
  if (Date.now() - cached.cachedAtMs > REVOCATION_MANIFEST_REFRESH_CACHE_TTL_MS) {
    revocationManifestRefreshCache.delete(cacheKey);
    return null;
  }
  return cloneJsonLike(cached.value);
}

function storeCachedRevocationManifestRefresh(cacheKey, value) {
  if (!value || value.source === "original") return;
  const { proofSequence: _proofSequence, ...cacheableValue } = value;
  revocationManifestRefreshCache.set(cacheKey, {
    cachedAtMs: Date.now(),
    value: cloneJsonLike(cacheableValue),
  });
}

async function refreshProofSequenceManifestAnchors(genesisPath, sequenceObj) {
  const primaryManifest = sequenceObj?.primary_proof?.manifest;
  const issuerDid = firstNonEmpty(
    primaryManifest?.issuer_did,
    sequenceObj?.issuer_did,
    sequenceObj?.primary_proof?.cred_def_id?.split?.(":")?.[0]
  );
  const manifestUrl = firstNonEmpty(primaryManifest?.manifest_url);
  const manifestVersion = firstNonEmpty(primaryManifest?.manifest_version, "1");
  const normalizedGenesisPath = String(genesisPath || "").trim();

  if (!issuerDid || !manifestUrl) {
    return {
      refreshed: false,
      source: "unavailable",
      issuerDid: issuerDid || null,
      manifestUrl: manifestUrl || null,
      proofSequence: sequenceObj,
    };
  }

  const cacheKey = makeRevocationManifestRefreshCacheKey({
    genesisPath: normalizedGenesisPath,
    issuerDid,
    manifestUrl,
    manifestVersion,
    previousManifestHash: primaryManifest?.manifest_hash || null,
  });
  const cachedRefresh = getCachedRevocationManifestRefresh(cacheKey);
  if (cachedRefresh) {
    return {
      ...cachedRefresh,
      fromCache: true,
      proofSequence: applyManifestAnchorToProofSequence(sequenceObj, cachedRefresh.effectiveManifest),
    };
  }

  let ledgerManifest = null;
  if (normalizedGenesisPath) {
    try {
      ledgerManifest = await tryReadRevocationManifestFromLedger(normalizedGenesisPath, issuerDid);
    } catch (_) {
      ledgerManifest = null;
    }
  }

  let liveManifest = null;
  try {
    liveManifest = (await buildLiveManifestAnchorData(issuerDid, manifestUrl, manifestVersion)).manifestObj;
  } catch (_) {
    liveManifest = null;
  }

  const effectiveManifest = liveManifest || ledgerManifest || primaryManifest || null;
  const refreshed = !!effectiveManifest
    && JSON.stringify(effectiveManifest) !== JSON.stringify(primaryManifest || null);

  const refreshResult = {
    refreshed,
    source: liveManifest ? "service_live" : (ledgerManifest ? "ledger" : "original"),
    fromCache: false,
    issuerDid,
    manifestUrl,
    previousManifestHash: primaryManifest?.manifest_hash || null,
    effectiveManifestHash: effectiveManifest?.manifest_hash || null,
    effectiveManifest,
    ledgerManifest,
    liveManifest,
    proofSequence: applyManifestAnchorToProofSequence(sequenceObj, effectiveManifest),
  };
  storeCachedRevocationManifestRefresh(cacheKey, refreshResult);
  return refreshResult;
}

async function readRevocationSetupFromLedger(genesisPath, issuerDid) {
  let activeKAnchor = null;
  let activeKVector = null;
  let manifest = null;

  try {
    const rawActive = await ssi.readAttribFromLedger(
      genesisPath,
      issuerDid,
      REVOCATION_ACTIVE_K_ATTR_KEY
    );
    const activeValue = extractAttribReadValue(rawActive);
    const activeParsed = parseJsonMaybeString(activeValue, null);
    if (activeParsed && typeof activeParsed === "object") {
      activeKAnchor = activeParsed;
    }
  } catch (e) {
    const parsed = parseJsonMaybeString(e?.message, null);
    if (!isLedgerLookupMiss(e, parsed)) throw e;
  }

  if (activeKAnchor?.k_vector_id) {
    try {
      const rawK = await ssi.revocationReadKVectorFromLedger(
        genesisPath,
        issuerDid,
        activeKAnchor.k_vector_id
      );
      const parsedK = parseJsonMaybeString(rawK, rawK);
      const unwrappedK = unwrapLedgerPayload(parsedK);
      if (!isLedgerLookupMiss(parsedK, unwrappedK)) {
        activeKAnchor = unwrappedK?.ledger_anchor || activeKAnchor;
        activeKVector = unwrappedK?.k_vector || null;
      }
    } catch (e) {
      const parsed = parseJsonMaybeString(e?.message, null);
      if (!isLedgerLookupMiss(e, parsed)) throw e;
    }
  }

  manifest = await tryReadRevocationManifestFromLedger(genesisPath, issuerDid);

  return {
    issuerDid,
    activeKAttrKey: REVOCATION_ACTIVE_K_ATTR_KEY,
    manifestAttrKey: REVOCATION_MANIFEST_ATTR_KEY,
    activeKAnchor,
    activeKVector,
    manifest,
    ready: !!(activeKAnchor?.k_vector_id && manifest?.manifest_url),
  };
}

function getNativeAddonPath() {
  const root = path.join(__dirname, "..", "..", "..");
  return path.join(root, "native", "index.node");
}

function getNativeAddonInfo() {
  const nativePath = getNativeAddonPath();
  try {
    const stat = fs.statSync(nativePath);
    const bytes = fs.readFileSync(nativePath);
    return {
      path: nativePath,
      sizeBytes: stat.size,
      mtimeMs: stat.mtimeMs,
      mtimeIso: new Date(stat.mtimeMs).toISOString(),
      sha256Base64: crypto.createHash("sha256").update(bytes).digest("base64"),
    };
  } catch (e) {
    return {
      path: nativePath,
      error: String(e?.message || e || "erro desconhecido"),
    };
  }
}

function extractManifestUrlFromIssuedSummary(summaryObj) {
  return firstNonEmpty(
    summaryObj?.summary?.manifest_url,
    summaryObj?.revocation_summary?.manifest_url,
    summaryObj?.issuer_record?.manifest?.manifest_url,
    summaryObj?.manifest_url
  );
}

async function fetchBloomManifestDiagnostics(manifestUrl) {
  const trimmed = String(manifestUrl || "").trim();
  if (!trimmed) return null;

  const resp = await fetch(trimmed);
  if (!resp.ok) {
    return {
      ok: false,
      manifestUrl: trimmed,
      status: resp.status,
      statusText: resp.statusText,
    };
  }

  const bodyText = await resp.text();
  const parsed = parseJsonMaybeString(bodyText, null);
  const manifest = parsed?.manifest || parsed;
  const filters = Array.isArray(manifest?.filters) ? manifest.filters : [];
  const activeFilterId = String(manifest?.active_filter_id || "").trim();
  const activeFilter = filters.find((item) => String(item?.filter_id || "").trim() === activeFilterId) || null;

  return {
    ok: true,
    manifestUrl: trimmed,
    activeFilterId,
    filterCount: filters.length,
    totalInsertedCount: filters.reduce((sum, item) => sum + Number(item?.inserted_count || 0), 0),
    activeInsertedCount: Number(activeFilter?.inserted_count || 0),
    activeWindowStartMin: activeFilter?.window_start_min ?? null,
    activeWindowStartMax: activeFilter?.window_start_max ?? null,
  };
}

function diffBloomManifestDiagnostics(before, after) {
  if (!before?.ok || !after?.ok) return null;
  return {
    totalInsertedDelta: Number(after.totalInsertedCount || 0) - Number(before.totalInsertedCount || 0),
    activeInsertedDelta: Number(after.activeInsertedCount || 0) - Number(before.activeInsertedCount || 0),
    activeFilterChanged: String(before.activeFilterId || "") !== String(after.activeFilterId || ""),
    activeWindowStartMinBefore: before.activeWindowStartMin ?? null,
    activeWindowStartMinAfter: after.activeWindowStartMin ?? null,
    activeWindowStartMaxBefore: before.activeWindowStartMax ?? null,
    activeWindowStartMaxAfter: after.activeWindowStartMax ?? null,
  };
}

function firstNonEmpty(...values) {
  for (const v of values) {
    const s = String(v || "").trim();
    if (s) return s;
  }
  return "";
}

function buildAutoOfferId() {
  return `offer-${Date.now()}-${Math.floor(Math.random() * 1_000_000_000)}`;
}

function isDuplicateEntryError(err) {
  const msg = String(err?.message || err || "").toLowerCase();
  return msg.includes("duplicate entry");
}

function isLikelyDuplicateError(err) {
  const msg = String(err?.message || err || "").toLowerCase();
  return msg.includes("duplicate")
    || msg.includes("já existe")
    || msg.includes("already exists");
}

function isInvalidSignatureProofError(err) {
  const msg = String(err?.message || err || "").toLowerCase();
  return msg.includes("invalid signature correctness proof")
    || msg.includes("q != q'")
    || msg.includes("q != q\\'");
}

function isWeakRequestMetadataSource(source) {
  const s = String(source || "").toLowerCase();
  return s.includes("nonce_fallback");
}

async function createCredentialOfferWithRetry(credDefId, offerIdInput) {
  const credDefIdStr = String(credDefId || "").trim();
  const explicitOfferId = String(offerIdInput || "").trim();
  let offerId = explicitOfferId || buildAutoOfferId();

  for (let attempt = 1; attempt <= 4; attempt += 1) {
    try {
      const offerJson = await ssi.createCredentialOffer(credDefIdStr, offerId);
      return { offerJson, offerId };
    } catch (e) {
      if (!isDuplicateEntryError(e)) throw e;

      if (explicitOfferId) {
        const err = new Error(`Offer ID já existe: "${explicitOfferId}". Informe outro Offer ID ou deixe em branco para gerar automaticamente.`);
        err.code = "DUPLICATE_OFFER_ID";
        err.details = { offerId: explicitOfferId, credDefId: credDefIdStr };
        throw err;
      }

      if (attempt >= 4) throw e;
      offerId = buildAutoOfferId();
    }
  }

  const e = new Error("Falha ao gerar oferta de credencial.");
  e.code = "CREATE_OFFER_FAILED";
  throw e;
}

function normalizeEnvelopeSummary(rawSummary) {
  const summary = parseJsonMaybeString(rawSummary, {}) || {};
  const kind = firstNonEmpty(
    summary?.kind,
    summary?.envelope?.kind,
    summary?.msg?.kind,
    summary?.type
  );
  const threadId = firstNonEmpty(
    summary?.thread_id,
    summary?.threadId,
    summary?.envelope?.thread_id,
    summary?.envelope?.threadId,
    summary?.thid,
    summary?.thread?.id
  );
  const senderVerkey = firstNonEmpty(
    summary?.crypto?.sender_verkey,
    summary?.crypto?.senderVerkey,
    summary?.from?.verkey,
    summary?.sender_verkey,
    summary?.senderVerkey,
    summary?.sender?.verkey
  );
  const recipientVerkey = firstNonEmpty(
    summary?.crypto?.recipient_verkey,
    summary?.crypto?.recipientVerkey,
    summary?.to?.verkey,
    summary?.recipient_verkey,
    summary?.recipientVerkey,
    summary?.recipient?.verkey
  );
  return {
    ...summary,
    kind: kind || null,
    thread_id: threadId || null,
    sender_verkey: senderVerkey || null,
    recipient_verkey: recipientVerkey || null,
  };
}

function extractRecipientVerkeyFromEnvelope(envelopeSummary) {
  return firstNonEmpty(
    envelopeSummary?.recipient_verkey,
    envelopeSummary?.crypto?.recipient_verkey,
    envelopeSummary?.crypto?.recipientVerkey,
    envelopeSummary?.to?.verkey,
    envelopeSummary?.recipient?.verkey
  );
}

function extractDidFromUnknownRecord(raw) {
  if (!raw) return "";
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (!trimmed) return "";
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      const parsed = parseJsonMaybeString(trimmed, null);
      return extractDidFromUnknownRecord(parsed);
    }
    return trimmed;
  }
  if (Array.isArray(raw)) {
    for (const item of raw) {
      const did = extractDidFromUnknownRecord(item);
      if (did) return did;
    }
    return "";
  }
  if (typeof raw === "object") {
    return firstNonEmpty(raw?.did, raw?.id, raw?.did_id, raw?.didId);
  }
  return "";
}

function extractVerkeyFromUnknownRecord(raw) {
  if (!raw) return "";
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (!trimmed) return "";
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      const parsed = parseJsonMaybeString(trimmed, null);
      return extractVerkeyFromUnknownRecord(parsed);
    }
    return trimmed;
  }
  if (Array.isArray(raw)) {
    for (const item of raw) {
      const verkey = extractVerkeyFromUnknownRecord(item);
      if (verkey) return verkey;
    }
    return "";
  }
  if (typeof raw === "object") {
    return firstNonEmpty(
      raw?.verkey,
      raw?.verKey,
      raw?.ver_key,
      raw?.verification_key,
      raw?.verificationKey,
      raw?.key
    );
  }
  return "";
}

async function resolveRecipientForPresentation(recipientDidInput, recipientVerkeyInput) {
  const recipientDid = String(recipientDidInput || "").trim();
  const verkeyInput = String(recipientVerkeyInput || "").trim();
  if (verkeyInput) {
    return {
      recipientDid: recipientDid || null,
      recipientVerkey: verkeyInput,
      recipientVerkeySource: "input",
    };
  }
  if (recipientDid) {
    const didRecord = await ssi.getDid(recipientDid);
    const resolvedVerkey = extractVerkeyFromUnknownRecord(didRecord);
    if (resolvedVerkey) {
      return {
        recipientDid,
        recipientVerkey: resolvedVerkey,
        recipientVerkeySource: "did_record",
      };
    }
  }

  const e = new Error(
    "Informe a verkey de destino ou selecione um DID de destino com verkey registrada."
  );
  e.code = "MISSING_RECIPIENT_VERKEY";
  e.details = {
    recipientDid: recipientDid || null,
    recipientVerkey: verkeyInput || null,
  };
  throw e;
}

async function resolveReceiverDidForEnvelope(holderDidInput, envelopeSummary) {
  const providedDid = String(holderDidInput || "").trim();
  const recipientVerkey = extractRecipientVerkeyFromEnvelope(envelopeSummary);

  if (providedDid) {
    try {
      await ssi.getDid(providedDid);
      return { receiverDid: providedDid, source: "input", recipientVerkey };
    } catch (_) {
      // tenta fallback por verkey do envelope
    }
  }

  if (recipientVerkey) {
    try {
      const byVerkey = await ssi.getDidByVerkey(recipientVerkey);
      const didFromVk = extractDidFromUnknownRecord(byVerkey);
      if (didFromVk) {
        return { receiverDid: didFromVk, source: "recipient_verkey", recipientVerkey };
      }
    } catch (_) {
      // sem mapeamento local por verkey
    }
  }

  const e = new Error(
    "Não foi possível determinar o DID receptor deste envelope. Abra a wallet do holder e informe um DID compatível com a recipient_verkey."
  );
  e.code = "RECEIVER_DID_NOT_FOUND";
  e.details = {
    holderDidInput: providedDid || null,
    recipientVerkey: recipientVerkey || null,
  };
  throw e;
}

function extractCredDefIdFromOffer(offerObj) {
  if (!offerObj || typeof offerObj !== "object") return "";
  return firstNonEmpty(
    offerObj?.cred_def_id,
    offerObj?.credDefId,
    offerObj?.offer?.cred_def_id,
    offerObj?.offer?.credDefId,
    offerObj?.body?.cred_def_id,
    offerObj?.body?.credDefId,
    offerObj?.cred_def?.id,
    offerObj?.credDef?.id
  );
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

function looksLikeAnoncredsOfferObject(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return false;
  const credDefId = firstNonEmpty(
    obj?.cred_def_id,
    obj?.credDefId
  );
  const nonce = firstNonEmpty(
    obj?.nonce,
    obj?.offer_nonce,
    obj?.offerNonce,
    obj?.req_meta_id,
    obj?.reqMetaId
  );
  const keyCorrectnessProof = obj?.key_correctness_proof || obj?.keyCorrectnessProof;
  return !!(credDefId && nonce && keyCorrectnessProof && typeof keyCorrectnessProof === "object");
}

function looksLikePackedEnvelopeObject(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return false;
  const hasCrypto = !!(obj?.crypto && typeof obj.crypto === "object" && !Array.isArray(obj.crypto));
  const hasPayload = Object.prototype.hasOwnProperty.call(obj, "payload");
  const hasEnvelopeHeader = !!firstNonEmpty(obj?.kind, obj?.id, obj?.v);
  return hasCrypto && hasPayload && hasEnvelopeHeader;
}

function extractAnoncredsOfferObject(raw, depth = 0) {
  if (depth > 6 || raw === undefined || raw === null) return null;
  if (typeof raw === "string") {
    const parsed = parseJsonMaybeString(raw, null);
    if (!parsed) return null;
    return extractAnoncredsOfferObject(parsed, depth + 1);
  }
  if (Array.isArray(raw)) {
    for (const item of raw) {
      const found = extractAnoncredsOfferObject(item, depth + 1);
      if (found) return found;
    }
    return null;
  }
  if (typeof raw !== "object") return null;
  if (looksLikeAnoncredsOfferObject(raw)) return raw;

  const candidates = [
    raw.offerObj,
    raw.offer,
    raw.offer_json,
    raw.offerJson,
    raw.value,
    raw.data,
    raw.result,
    raw.payload,
    raw.body,
    raw.plaintext,
    raw.message,
  ];
  for (const candidate of candidates) {
    const found = extractAnoncredsOfferObject(candidate, depth + 1);
    if (found) return found;
  }
  return null;
}

function normalizeOfferJsonForRevocableIssue(offerJson, credDefId, schemaId) {
  const offerObj = extractAnoncredsOfferObject(offerJson);
  if (!offerObj || typeof offerObj !== "object" || Array.isArray(offerObj)) {
    return typeof offerJson === "string" ? offerJson : JSON.stringify(offerJson);
  }

  const normalized = {
    ...offerObj,
    cred_def_id: firstNonEmpty(
      offerObj?.cred_def_id,
      offerObj?.credDefId,
      credDefId
    ),
    schema_id: firstNonEmpty(
      offerObj?.schema_id,
      offerObj?.schemaId,
      schemaId
    ),
  };

  return JSON.stringify(normalized);
}

function extractCredDefIdFromRequest(reqObj) {
  if (!reqObj || typeof reqObj !== "object") return "";
  return firstNonEmpty(
    reqObj?.cred_def_id,
    reqObj?.credDefId,
    reqObj?.offer?.cred_def_id,
    reqObj?.offer?.credDefId,
    reqObj?.body?.cred_def_id,
    reqObj?.body?.credDefId
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

function extractCredDefIdFromCredential(credentialObj) {
  if (!credentialObj || typeof credentialObj !== "object") return "";
  return firstNonEmpty(
    credentialObj?.cred_def_id,
    credentialObj?.credDefId,
    credentialObj?.credential?.cred_def_id,
    credentialObj?.credential?.credDefId,
    credentialObj?.body?.cred_def_id,
    credentialObj?.body?.credDefId
  );
}

function extractRequestMetadataIdFromCredential(credentialObj, envelopeSummary) {
  const fromCredential = firstNonEmpty(
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
  if (fromCredential) return fromCredential;

  const fromSummary = firstNonEmpty(
    envelopeSummary?.meta?.request_metadata_id,
    envelopeSummary?.meta?.requestMetadataId,
    envelopeSummary?.meta?.request_nonce,
    envelopeSummary?.meta?.requestNonce,
    envelopeSummary?.payload?.meta?.request_metadata_id,
    envelopeSummary?.payload?.meta?.requestMetadataId,
    envelopeSummary?.payload?.meta?.request_nonce,
    envelopeSummary?.payload?.meta?.requestNonce
  );
  if (fromSummary) return fromSummary;

  return "";
}

function extractRequestMetadataIdFromEnvelopeSummary(envelopeSummary) {
  if (!envelopeSummary || typeof envelopeSummary !== "object") return "";
  return firstNonEmpty(
    envelopeSummary?.meta?.request_metadata_id,
    envelopeSummary?.meta?.requestMetadataId,
    envelopeSummary?.meta?.offer_nonce,
    envelopeSummary?.meta?.offerNonce,
    envelopeSummary?.meta?.request_nonce,
    envelopeSummary?.meta?.requestNonce,
    envelopeSummary?.payload?.meta?.request_metadata_id,
    envelopeSummary?.payload?.meta?.requestMetadataId,
    envelopeSummary?.payload?.meta?.offer_nonce,
    envelopeSummary?.payload?.meta?.offerNonce,
    envelopeSummary?.payload?.meta?.request_nonce,
    envelopeSummary?.payload?.meta?.requestNonce
  );
}

function buildOfferEnvelopeCandidatesFromCredentialFile(credentialFilePath, explicitOfferFilePath) {
  const out = [];
  const seen = new Set();
  const credPath = String(credentialFilePath || "").trim();
  const credNorm = credPath ? path.normalize(credPath) : "";

  const pushCandidate = (p) => {
    const c = String(p || "").trim();
    if (!c) return;
    const norm = path.normalize(c);
    if (!norm || seen.has(norm)) return;
    if (credNorm && norm === credNorm) return;
    seen.add(norm);
    out.push(norm);
  };

  pushCandidate(explicitOfferFilePath);

  if (!credPath) return out;

  // Caso padrão atual:
  // offer:   <base>.env.json | <base>.json
  // request: <base>_request.env.json | <base>_request.json
  // cred:    <base>_request_credential.env.json | <base>_request_credential.json
  // cred rev: <base>_request_revocable_credential.env.json | <base>_request_revocable_credential.json
  const reqRevCredEnv = credPath.match(/^(.*)_request_revocable_credential\.env\.json$/i);
  if (reqRevCredEnv && reqRevCredEnv[1]) {
    const base = reqRevCredEnv[1];
    pushCandidate(`${base}.env.json`);
    pushCandidate(`${base}.json`);
    pushCandidate(`${base}_request.env.json`);
    pushCandidate(`${base}_request.json`);
    return out;
  }

  const reqRevCredPlain = credPath.match(/^(.*)_request_revocable_credential\.json$/i);
  if (reqRevCredPlain && reqRevCredPlain[1]) {
    const base = reqRevCredPlain[1];
    pushCandidate(`${base}.env.json`);
    pushCandidate(`${base}.json`);
    pushCandidate(`${base}_request.env.json`);
    pushCandidate(`${base}_request.json`);
    return out;
  }

  const reqCredEnv = credPath.match(/^(.*)_request_credential\.env\.json$/i);
  if (reqCredEnv && reqCredEnv[1]) {
    const base = reqCredEnv[1];
    pushCandidate(`${base}.env.json`);
    pushCandidate(`${base}.json`);
    pushCandidate(`${base}_request.env.json`);
    pushCandidate(`${base}_request.json`);
    return out;
  }

  const reqCredPlain = credPath.match(/^(.*)_request_credential\.json$/i);
  if (reqCredPlain && reqCredPlain[1]) {
    const base = reqCredPlain[1];
    pushCandidate(`${base}.env.json`);
    pushCandidate(`${base}.json`);
    pushCandidate(`${base}_request.env.json`);
    pushCandidate(`${base}_request.json`);
    return out;
  }

  const byRequestCredential = credPath.replace(/_request_credential\.env\.json$/i, ".env.json");
  if (byRequestCredential !== credPath) pushCandidate(byRequestCredential);

  const byRequestRevocableCredential = credPath.replace(/_request_revocable_credential\.env\.json$/i, ".env.json");
  if (byRequestRevocableCredential !== credPath) pushCandidate(byRequestRevocableCredential);

  const byRequestRevocableCredentialPlain = credPath.replace(/_request_revocable_credential\.json$/i, ".json");
  if (byRequestRevocableCredentialPlain !== credPath) pushCandidate(byRequestRevocableCredentialPlain);

  const requestCandidate = credPath.replace(/_credential\.env\.json$/i, ".env.json");
  if (requestCandidate !== credPath) {
    pushCandidate(requestCandidate);
    const byRequestSuffix = requestCandidate.replace(/_request\.env\.json$/i, ".env.json");
    if (byRequestSuffix !== requestCandidate) pushCandidate(byRequestSuffix);
  }

  const plainCandidate = credPath.replace(/_credential\.json$/i, ".json");
  if (plainCandidate !== credPath) {
    pushCandidate(plainCandidate);
    const byRequestSuffixPlain = plainCandidate.replace(/_request\.json$/i, ".json");
    if (byRequestSuffixPlain !== plainCandidate) pushCandidate(byRequestSuffixPlain);
  }

  const requestRevocableCandidate = credPath.replace(/_revocable_credential\.env\.json$/i, ".env.json");
  if (requestRevocableCandidate !== credPath) {
    pushCandidate(requestRevocableCandidate);
    const byRequestSuffix = requestRevocableCandidate.replace(/_request\.env\.json$/i, ".env.json");
    if (byRequestSuffix !== requestRevocableCandidate) pushCandidate(byRequestSuffix);
  }

  const plainRevocableCandidate = credPath.replace(/_revocable_credential\.json$/i, ".json");
  if (plainRevocableCandidate !== credPath) {
    pushCandidate(plainRevocableCandidate);
    const byRequestSuffixPlain = plainRevocableCandidate.replace(/_request\.json$/i, ".json");
    if (byRequestSuffixPlain !== plainRevocableCandidate) pushCandidate(byRequestSuffixPlain);
  }

  return out;
}

async function inferRequestMetadataFromCompanionOffer(holderDid, credentialFilePath, explicitOfferFilePath) {
  const candidates = buildOfferEnvelopeCandidatesFromCredentialFile(
    credentialFilePath,
    explicitOfferFilePath
  );
  let weakFallback = null;

  for (const candidatePath of candidates) {
    try {
      if (!fs.existsSync(candidatePath)) continue;
      const offerEnvelopeJson = fs.readFileSync(candidatePath, "utf-8");
      const offerEnvelopeSummary = normalizeEnvelopeSummary(ssi.envelopeParse(offerEnvelopeJson));
      const kind = firstNonEmpty(offerEnvelopeSummary?.kind).toLowerCase();
      const offerPlain = await ssi.envelopeUnpackAuto(String(holderDid), offerEnvelopeJson);
      const offerObj = parseJsonMaybeString(offerPlain, null);

      let requestMetadataId = "";
      let source = "";

      if (!kind || kind.includes("offer")) {
        requestMetadataId = firstNonEmpty(
          extractNonceFromOffer(offerObj),
          extractRequestMetadataIdFromEnvelopeSummary(offerEnvelopeSummary)
        );
        source = "companion_offer_file";
      } else if (kind.includes("request")) {
        requestMetadataId = firstNonEmpty(
          extractRequestMetadataIdFromEnvelopeSummary(offerEnvelopeSummary)
        );
        source = "companion_request_file";
        if (!requestMetadataId) {
          const weak = firstNonEmpty(extractNonceFromRequest(offerObj));
          if (weak && !weakFallback) {
            weakFallback = {
              requestMetadataId: weak,
              source: "companion_request_file:nonce_fallback",
              offerFilePath: candidatePath,
              candidatesChecked: candidates,
            };
          }
          continue;
        }
      }

      if (!requestMetadataId) continue;

      return {
        requestMetadataId,
        source,
        offerFilePath: candidatePath,
        candidatesChecked: candidates,
      };
    } catch (_) {
      // ignora candidato inválido e tenta próximo
    }
  }

  if (weakFallback) return weakFallback;

  return {
    requestMetadataId: "",
    source: "",
    offerFilePath: null,
    candidatesChecked: candidates,
  };
}

function extractHolderDidFromRequest(reqObj) {
  if (!reqObj || typeof reqObj !== "object") return "";
  return firstNonEmpty(
    reqObj?.prover_did,
    reqObj?.proverDid,
    reqObj?.holder_did,
    reqObj?.holderDid,
    reqObj?.did
  );
}

function extractSchemaIdFromCredDef(credDefObj) {
  if (!credDefObj || typeof credDefObj !== "object") return "";
  return firstNonEmpty(
    credDefObj?.schema_id,
    credDefObj?.schemaId,
    credDefObj?.ref_schema_id,
    credDefObj?.schema?.schema_id,
    credDefObj?.schema?.id
  );
}

function extractSchemaRefFromCredDef(credDefObj) {
  if (!credDefObj || typeof credDefObj !== "object") return "";
  return firstNonEmpty(
    credDefObj?.ref,
    credDefObj?.schema_ref,
    credDefObj?.schemaRef
  );
}

function deriveSchemaIdFromCredDefId(credDefId) {
  const id = String(credDefId || "").trim();
  if (!id) return "";
  const marker = ":3:CL:";
  const idx = id.indexOf(marker);
  if (idx < 0) return "";
  const rest = id.slice(idx + marker.length);
  if (!rest) return "";

  // Formato com schema completo no credDefId: did:3:CL:did:2:name:version:tag
  if (rest.includes(":2:")) {
    const lastColon = rest.lastIndexOf(":");
    if (lastColon > 0) return rest.slice(0, lastColon);
    return rest;
  }

  // Formato com seqNo de schema: did:3:CL:123:TAG
  const parts = rest.split(":");
  if (parts.length >= 1) return String(parts[0] || "").trim();
  return "";
}

function parseIssuerDidFromCredDefId(credDefId) {
  const id = String(credDefId || "").trim();
  const idx = id.indexOf(":3:CL:");
  if (idx <= 0) return "";
  return id.slice(0, idx);
}

function parseCredDefIdParts(credDefId) {
  const id = String(credDefId || "").trim();
  if (!id) return null;
  const marker = ":3:CL:";
  const idx = id.indexOf(marker);
  if (idx <= 0) return null;
  const issuerDid = id.slice(0, idx);
  const rest = id.slice(idx + marker.length);
  if (!rest) return { full: id, issuerDid, schemaRef: "", tag: "" };
  const lastColon = rest.lastIndexOf(":");
  if (lastColon < 0) return { full: id, issuerDid, schemaRef: rest, tag: "" };
  return {
    full: id,
    issuerDid,
    schemaRef: rest.slice(0, lastColon),
    tag: rest.slice(lastColon + 1),
  };
}

function parseCredDefLocalRecord(raw) {
  const unwrapped = unwrapLedgerPayload(raw);
  if (!unwrapped || typeof unwrapped !== "object") return null;
  return unwrapped;
}

function parseSchemaLocalRecord(raw) {
  const unwrapped = unwrapLedgerPayload(raw);
  if (!unwrapped || typeof unwrapped !== "object") return null;
  return unwrapped;
}

function normalizeRecordList(rawList) {
  const parsed = parseJsonMaybeString(rawList, rawList);
  if (Array.isArray(parsed)) return parsed;
  if (parsed && typeof parsed === "object") {
    if (Array.isArray(parsed.items)) return parsed.items;
    if (Array.isArray(parsed.data)) return parsed.data;
    if (Array.isArray(parsed.value)) return parsed.value;
    if (Array.isArray(parsed.records)) return parsed.records;
  }
  return [];
}

function extractCredDefIdFromLocalRecord(raw) {
  const rec = parseCredDefLocalRecord(raw);
  if (!rec || typeof rec !== "object") return "";
  return firstNonEmpty(rec?.cred_def_id, rec?.credDefId, rec?.id, rec?.id_local);
}

function normalizeAttrNamesList(items) {
  const seen = new Set();
  const out = [];
  for (const item of Array.isArray(items) ? items : []) {
    const attr = String(item || "").trim();
    if (!attr || seen.has(attr)) continue;
    seen.add(attr);
    out.push(attr);
  }
  out.sort();
  return out;
}

function areSameAttrNameSet(left, right) {
  const a = normalizeAttrNamesList(left);
  const b = normalizeAttrNamesList(right);
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return a.length > 0;
}

function scoreEquivalentCredDefId(inputCredDefId, candidateCredDefId) {
  const input = parseCredDefIdParts(inputCredDefId);
  const candidate = parseCredDefIdParts(candidateCredDefId);
  if (!input || !candidate) return -1;
  if (candidate.full === input.full) return Number.MAX_SAFE_INTEGER;
  if (candidate.issuerDid !== input.issuerDid) return -1;
  if (candidate.schemaRef !== input.schemaRef) return -1;
  if (!input.tag || !candidate.tag) return -1;
  if (candidate.tag === input.tag) return 1000;
  if (candidate.tag.startsWith(`${input.tag}_`)) {
    const suffix = candidate.tag.slice(input.tag.length + 1);
    const suffixNum = Number.parseInt(suffix, 10);
    return Number.isFinite(suffixNum) ? 2000 + suffixNum : 1500;
  }
  if (candidate.full.startsWith(`${input.full}_`)) return 1400;
  if (candidate.tag.startsWith(input.tag)) return 1200;
  return -1;
}

async function tryFetchCredDefFromLedger(genesisPath, credDefId) {
  try {
    const raw = await ssi.fetchCredDefFromLedger(String(genesisPath), String(credDefId));
    const obj = unwrapLedgerPayload(raw);
    if (!obj || typeof obj !== "object") return null;
    if (isLedgerLookupMiss(raw, obj)) return null;
    return {
      credDefIdResolved: String(credDefId),
      credDefJsonLedger: raw,
      credDefObj: obj,
      aliasUsed: false,
    };
  } catch (_) {
    return null;
  }
}

async function resolveLedgerCredDef(genesisPath, credDefId) {
  const inputId = String(credDefId || "").trim();
  if (!inputId) return null;

  const exact = await tryFetchCredDefFromLedger(genesisPath, inputId);
  if (exact) return exact;

  const candidateMap = new Map();
  const pushCandidate = (rawId) => {
    const candidateId = String(rawId || "").trim();
    if (!candidateId || candidateId === inputId) return;
    const score = scoreEquivalentCredDefId(inputId, candidateId);
    if (score < 0) return;
    const prev = candidateMap.get(candidateId);
    if (!prev || score > prev.score) {
      candidateMap.set(candidateId, { credDefId: candidateId, score });
    }
  };

  try {
    const onLedgerRaw = await ssi.creddefListLocal(true, null, null, null, null);
    for (const item of normalizeRecordList(onLedgerRaw)) {
      pushCandidate(extractCredDefIdFromLocalRecord(item));
    }
  } catch (_) {
    // ignora falha do catálogo local
  }

  try {
    const allRaw = await ssi.creddefListLocal(null, null, null, null, null);
    for (const item of normalizeRecordList(allRaw)) {
      pushCandidate(extractCredDefIdFromLocalRecord(item));
    }
  } catch (_) {
    // ignora falha do catálogo local
  }

  const ranked = Array.from(candidateMap.values()).sort((left, right) => {
    if (right.score !== left.score) return right.score - left.score;
    return String(right.credDefId).localeCompare(String(left.credDefId));
  });

  for (const candidate of ranked) {
    const resolved = await tryFetchCredDefFromLedger(genesisPath, candidate.credDefId);
    if (resolved) {
      return {
        ...resolved,
        aliasUsed: true,
        requestedCredDefId: inputId,
      };
    }
  }

  return null;
}

async function resolveSchemaIdForCredDef(genesisPath, credDefId, credDefObj) {
  const candidates = [];
  const credDef = unwrapLedgerPayload(credDefObj);
  const direct = extractSchemaIdFromCredDef(credDef);
  const byRef = extractSchemaRefFromCredDef(credDef);
  const byId = deriveSchemaIdFromCredDefId(credDefId);
  const byObjId = deriveSchemaIdFromCredDefId(firstNonEmpty(
    credDef?.id,
    credDef?.cred_def_id,
    credDef?.credDefId
  ));
  if (direct) candidates.push(direct);
  if (byRef) candidates.push(byRef);
  if (byId) candidates.push(byId);
  if (byObjId) candidates.push(byObjId);

  // tenta resolver diretamente no ledger para aceitar também seqNo/ref
  for (const c of candidates) {
    const cand = String(c || "").trim();
    if (!cand) continue;
    try {
      const schemaRaw = await ssi.fetchSchemaFromLedger(String(genesisPath), cand);
      const schemaObj = unwrapLedgerPayload(schemaRaw);
      const schemaIdResolved = firstNonEmpty(
        schemaObj?.id,
        schemaObj?.schema_id,
        schemaObj?.schemaId,
        schemaObj?.schema?.id,
        schemaObj?.schema?.schema_id,
        cand
      );
      if (schemaIdResolved) return schemaIdResolved;
    } catch (_) {
      // tenta próximo candidato
    }
  }

  // fallback: tenta catálogo local de creddefs e mapeia pelo id da creddef
  try {
    const byCredDefIdRaw = await ssi.creddefGetLocalByCredDefId(String(credDefId));
    const rec = parseCredDefLocalRecord(byCredDefIdRaw);
    const schemaId = firstNonEmpty(rec?.schema_id, rec?.schemaId);
    if (schemaId) return schemaId;
  } catch (_) {
    // ignora se não existir vínculo local com este cred_def_id
  }

  // fallback: tenta catálogo local de creddefs e mapeia pelo id da creddef
  try {
    const localRaw = await ssi.creddefListLocal(null, null, null, null, null);
    const localRecords = normalizeRecordList(localRaw);
    for (const it of localRecords) {
      const rec = parseCredDefLocalRecord(it);
      if (!rec || typeof rec !== "object") continue;
      const recId = firstNonEmpty(rec?.id_local, rec?.id, rec?.cred_def_id, rec?.credDefId);
      if (!recId || recId !== String(credDefId)) continue;
      const schemaId = firstNonEmpty(rec?.schema_id, rec?.schemaId);
      if (schemaId) return schemaId;
    }
  } catch (_) {
    // ignora fallback local
  }

  // fallback extra: consulta direta no catálogo local por id exato da creddef
  try {
    const localOneRaw = await ssi.creddefGetLocal(String(credDefId));
    const rec = parseCredDefLocalRecord(localOneRaw);
    const schemaId = firstNonEmpty(rec?.schema_id, rec?.schemaId);
    if (schemaId) return schemaId;
  } catch (_) {
    // ignora se o id local não existir
  }

  // fallback extra: tenta catálogo local de schemas por ref/seqNo e issuer do credDefId
  const refTarget = String(byRef || "").trim();
  const issuerDid = parseIssuerDidFromCredDefId(credDefId);
  if (refTarget) {
    try {
      const schemasRaw = await ssi.schemaListLocal(null, null, null);
      const schemaRecords = normalizeRecordList(schemasRaw);
      for (const item of schemaRecords) {
        const rec = parseSchemaLocalRecord(item);
        if (!rec || typeof rec !== "object") continue;
        const seqNo = firstNonEmpty(rec?.seq_no, rec?.seqNo, rec?.ref, rec?.schema_ref, rec?.schemaRef);
        if (!seqNo || seqNo !== refTarget) continue;
        const recIssuer = firstNonEmpty(rec?.issuer_did, rec?.issuerDid);
        if (issuerDid && recIssuer && recIssuer !== issuerDid) continue;
        const schemaIdLocal = firstNonEmpty(rec?.id_local, rec?.id, rec?.schema_id, rec?.schemaId);
        if (schemaIdLocal) return schemaIdLocal;
      }
    } catch (_) {
      // ignora fallback local de schemas
    }
  }

  // fallback final: tenta casar schema local pelo mesmo emissor e mesmo conjunto de atributos
  try {
    const credDefAttrNames = extractCredDefAttrNames(credDef);
    if (credDefAttrNames.length) {
      const schemasRaw = await ssi.schemaListLocal(null, null, null);
      const schemaRecords = normalizeRecordList(schemasRaw);
      for (const item of schemaRecords) {
        const rec = parseSchemaLocalRecord(item);
        if (!rec || typeof rec !== "object") continue;
        const recIssuer = firstNonEmpty(rec?.issuer_did, rec?.issuerDid, rec?.schema?.issuer_did, rec?.schema?.issuerDid);
        if (issuerDid && recIssuer && recIssuer !== issuerDid) continue;
        const recAttrNames = extractSchemaAttrNames(rec);
        if (!areSameAttrNameSet(recAttrNames, credDefAttrNames)) continue;
        const schemaIdLocal = firstNonEmpty(
          rec?.schema_id,
          rec?.schemaId,
          rec?.id,
          rec?.id_local,
          rec?.schema?.id,
          rec?.schema?.schema_id
        );
        if (schemaIdLocal) return schemaIdLocal;
      }
    }
  } catch (_) {
    // ignora fallback por similaridade de atributos
  }

  return "";
}

async function fetchLedgerCredDefOrThrow(genesisPath, credDefId) {
  const resolved = await resolveLedgerCredDef(genesisPath, credDefId);
  if (resolved) return resolved;

  const credDefRaw = await ssi.fetchCredDefFromLedger(String(genesisPath), String(credDefId));
  const credDefObj = unwrapLedgerPayload(credDefRaw);
  if (!credDefObj || typeof credDefObj !== "object" || isLedgerLookupMiss(credDefRaw, credDefObj)) {
    const errText = firstNonEmpty(
      credDefObj?.message,
      credDefObj?.error,
      credDefRaw?.message,
      credDefRaw?.error,
      "CredDef não encontrada no ledger."
    );
    const e = new Error(errText);
    e.code = "CREDDEF_NOT_FOUND_ON_LEDGER";
    e.details = { credDefId: String(credDefId), rawType: typeof credDefRaw };
    throw e;
  }
  return {
    credDefIdResolved: String(credDefId),
    credDefJsonLedger: credDefRaw,
    credDefObj,
    aliasUsed: false,
  };
}

function extractSchemaAttrNames(schemaObj) {
  if (!schemaObj || typeof schemaObj !== "object") return [];
  const candidate = schemaObj?.attr_names
    || schemaObj?.attrNames
    || schemaObj?.attrs
    || schemaObj?.schema?.attr_names
    || schemaObj?.schema?.attrNames
    || schemaObj?.schema?.attrs
    || [];
  if (!Array.isArray(candidate)) return [];

  const seen = new Set();
  const out = [];
  for (const item of candidate) {
    const attr = String(item || "").trim();
    if (!attr) continue;
    if (seen.has(attr)) continue;
    seen.add(attr);
    out.push(attr);
  }
  return out;
}

function extractCredDefAttrNames(credDefObj) {
  if (!credDefObj || typeof credDefObj !== "object") return [];

  const rMap = credDefObj?.value?.primary?.r
    || credDefObj?.primary?.r
    || credDefObj?.cred_def?.value?.primary?.r
    || credDefObj?.credDef?.value?.primary?.r
    || null;

  if (!rMap || typeof rMap !== "object" || Array.isArray(rMap)) return [];

  const ignored = new Set(["master_secret"]);
  const seen = new Set();
  const out = [];
  for (const key of Object.keys(rMap)) {
    const attr = String(key || "").trim();
    if (!attr) continue;
    if (ignored.has(attr)) continue;
    if (seen.has(attr)) continue;
    seen.add(attr);
    out.push(attr);
  }
  return out;
}

function normalizeOfferCacheRecord(recRaw) {
  let recInput = recRaw;
  if (typeof recInput === "string") {
    recInput = parseJsonMaybeString(recInput, null);
  }
  if (!recInput || typeof recInput !== "object") return null;

  const offerObj = extractAnoncredsOfferObject(recRaw.offerObj)
    || extractAnoncredsOfferObject(recInput.offerObj)
    || extractAnoncredsOfferObject(recInput.offerJson)
    || extractAnoncredsOfferObject(recInput.offer_json)
    || extractAnoncredsOfferObject(recInput.offerJsonStr)
    || extractAnoncredsOfferObject(recInput.offer_json_str)
    || extractAnoncredsOfferObject(recInput.offer)
    || extractAnoncredsOfferObject(recInput.json)
    || extractAnoncredsOfferObject(recInput.record_json)
    || extractAnoncredsOfferObject(recInput.value)
    || extractAnoncredsOfferObject(recInput.data)
    || extractAnoncredsOfferObject(recInput.result);
  const offerJson = firstNonEmpty(
    typeof recInput.offerJson === "string" ? recInput.offerJson : "",
    typeof recInput.offer_json === "string" ? recInput.offer_json : "",
    typeof recInput.offerJsonStr === "string" ? recInput.offerJsonStr : "",
    typeof recInput.offer_json_str === "string" ? recInput.offer_json_str : "",
    typeof recInput.offer === "string" ? recInput.offer : "",
    typeof recInput.json === "string" ? recInput.json : "",
    typeof recInput.record_json === "string" ? recInput.record_json : "",
    typeof recInput.value === "string" ? recInput.value : "",
    offerObj ? JSON.stringify(offerObj) : ""
  );

  const createdAt = Number(
    recInput.createdAt
    || recInput.created_at_ms
    || recInput.created_at
    || recInput.ts
    || recInput.timestamp
    || 0
  ) || 0;
  const threadId = firstNonEmpty(recInput.threadId, recInput.thread_id);
  const offerId = firstNonEmpty(recInput.offerId, recInput.id_local, recInput.id, recInput.local_id);
  const credDefId = firstNonEmpty(
    recInput.credDefId,
    recInput.cred_def_id,
    extractCredDefIdFromOffer(offerObj)
  );
  const nonce = firstNonEmpty(recInput.nonce, extractNonceFromOffer(offerObj));

  if (!offerJson) return null;
  return {
    offerJson,
    offerObj: offerObj || parseJsonMaybeString(offerJson, null),
    createdAt,
    threadId: threadId || null,
    offerId: offerId || null,
    credDefId: credDefId || null,
    nonce: nonce || null,
    source: firstNonEmpty(recInput.source, "memory"),
  };
}

function cacheOfferRecord(recRaw) {
  const rec = normalizeOfferCacheRecord(recRaw);
  if (!rec) return;
  __offer_cache.push(rec);
  if (__offer_cache.length > 300) {
    __offer_cache.splice(0, __offer_cache.length - 300);
  }
}

function findOfferInMemory(credDefId, threadId, offerNonce, strict = true) {
  for (let i = __offer_cache.length - 1; i >= 0; i -= 1) {
    const rec = __offer_cache[i];
    if (!rec) continue;
    if (credDefId && rec.credDefId && rec.credDefId !== credDefId) continue;
    if (strict && threadId && rec.threadId && rec.threadId !== threadId) continue;
    if (strict && offerNonce && rec.nonce && rec.nonce !== offerNonce) continue;
    return rec;
  }
  return null;
}

async function findOfferFromWalletList(credDefId, offerNonce, strict = true) {
  let listRaw;
  try {
    listRaw = await ssi.listCredentialOffers();
  } catch (_) {
    return null;
  }
  let list = parseJsonMaybeString(listRaw, []);
  if (!Array.isArray(list) && list && typeof list === "object") {
    list = list.items || list.offers || list.data || [];
  }
  if (!Array.isArray(list)) return null;

  let best = null;
  for (const item of list) {
    const parsedItem = typeof item === "string" ? parseJsonMaybeString(item, null) : item;
    const rec = normalizeOfferCacheRecord({ ...(parsedItem || {}), source: "wallet_list" });
    if (!rec) continue;
    if (credDefId && rec.credDefId && rec.credDefId !== credDefId) continue;
    if (strict && offerNonce && rec.nonce && rec.nonce !== offerNonce) continue;
    if (!best || rec.createdAt >= best.createdAt) best = rec;
  }
  return best;
}

async function resolveOfferForIssue(credDefId, threadId, offerNonce) {
  const inMemory = findOfferInMemory(credDefId, threadId, offerNonce, true);
  if (inMemory) return inMemory;

  const fromWallet = await findOfferFromWalletList(credDefId, offerNonce, true);
  if (fromWallet) return fromWallet;

  // Fallback menos estrito: ignora threadId/nonce e usa a oferta mais recente da credDef.
  const inMemoryLoose = findOfferInMemory(credDefId, null, null, false);
  if (inMemoryLoose) return { ...inMemoryLoose, source: `${inMemoryLoose.source}:loose` };

  const fromWalletLoose = await findOfferFromWalletList(credDefId, null, false);
  if (fromWalletLoose) return { ...fromWalletLoose, source: `${fromWalletLoose.source}:loose` };

  const e = new Error(
    "Não foi possível localizar a oferta correspondente na wallet/cache do emissor. Gere a oferta nesta mesma wallet antes de emitir a credencial."
  );
  e.code = "OFFER_NOT_FOUND_FOR_REQUEST";
  e.details = {
    credDefId: credDefId || null,
    threadId: threadId || null,
    offerNonce: offerNonce || null,
  };
  throw e;
}

function buildOfferEnvelopeCandidates(requestFilePath, offerFilePathOpt) {
  const out = [];
  const seen = new Set();
  const reqPath = String(requestFilePath || "").trim();
  const reqNorm = reqPath ? path.normalize(reqPath) : "";

  const pushCandidate = (p) => {
    const c = String(p || "").trim();
    if (!c) return;
    const norm = path.normalize(c);
    if (reqNorm && norm === reqNorm) return;
    if (seen.has(norm)) return;
    seen.add(norm);
    out.push(norm);
  };

  const pushOfferCandidate = (p) => {
    const c = String(p || "").trim();
    if (!c) return;
    pushCandidate(c);
    if (/\.env\.json$/i.test(c)) {
      pushCandidate(c.replace(/\.env\.json$/i, ".json"));
    }
    if (/\.json$/i.test(c) && !/\.offer\.json$/i.test(c)) {
      pushCandidate(`${c}.offer.json`);
    }
  };

  pushOfferCandidate(offerFilePathOpt);

  if (!reqPath) return out;

  const reqDir = path.dirname(reqPath);
  const reqBase = path.basename(reqPath);
  const reqStem = reqBase
    .replace(/\.env\.json$/i, "")
    .replace(/\.json$/i, "");

  const baseCandidates = [reqStem];
  if (/_request$/i.test(reqStem)) {
    baseCandidates.push(reqStem.replace(/_request$/i, ""));
  }
  const withSuffix = reqStem.match(/^(.*)_request(\..+)$/i);
  if (withSuffix && withSuffix[1]) {
    const prefix = String(withSuffix[1]).trim();
    const suffix = String(withSuffix[2] || "").trim();
    if (prefix) {
      baseCandidates.push(`${prefix}${suffix}`); // ex.: foo_request.env_cpf -> foo.env_cpf
      baseCandidates.push(prefix); // ex.: foo_request.env_cpf -> foo
    }
  }

  for (const base of baseCandidates) {
    const b = String(base || "").trim();
    if (!b) continue;
    pushOfferCandidate(path.join(reqDir, `${b}.env.json`));
    pushOfferCandidate(path.join(reqDir, `${b}.json`));
    pushCandidate(path.join(reqDir, `${b}.offer.json`));
  }

  return out;
}

async function resolveOfferFromEnvelopeFile(issuerDid, offerFilePath, credDefId, threadId, offerNonce) {
  const p = String(offerFilePath || "").trim();
  if (!p) return null;
  if (!fs.existsSync(p)) return null;

  const buildRecFromPlainOffer = (offerObj, sourceLabel) => {
    if (!offerObj || typeof offerObj !== "object") return null;
    const rec = normalizeOfferCacheRecord({
      source: sourceLabel,
      offerObj,
      offerJson: JSON.stringify(offerObj),
      createdAt: Date.now(),
    });
    if (!rec) return null;
    if (credDefId && rec.credDefId && rec.credDefId !== credDefId) return null;
    if (threadId && rec.threadId && rec.threadId !== threadId) return null;
    if (offerNonce && rec.nonce && rec.nonce !== offerNonce) return null;
    const withSource = { ...rec, source: `${sourceLabel}:${path.basename(p)}`, matchedFilePath: p };
    cacheOfferRecord(withSource);
    return withSource;
  };

  try {
    const raw = fs.readFileSync(p, "utf-8");
    const parsedRaw = parseJsonMaybeString(raw, null);

    if (looksLikeAnoncredsOfferObject(parsedRaw)) {
      return buildRecFromPlainOffer(parsedRaw, "offer_plain_file");
    }

    const nestedOfferObj = extractAnoncredsOfferObject(parsedRaw);
    if (nestedOfferObj) {
      return buildRecFromPlainOffer(nestedOfferObj, "offer_plain_file");
    }

    if (looksLikePackedEnvelopeObject(parsedRaw)) {
      try {
        const envelopeSummary = normalizeEnvelopeSummary(ssi.envelopeParse(raw));
        const envelopeKind = firstNonEmpty(envelopeSummary?.kind).toLowerCase();
        if (envelopeKind && !envelopeKind.includes("offer")) return null;

        const offerPlain = await ssi.envelopeUnpackAuto(String(issuerDid), raw);
        const offerObj = parseJsonMaybeString(offerPlain, null);
        if (!looksLikeAnoncredsOfferObject(offerObj)) return null;

        const rec = normalizeOfferCacheRecord({
          source: "offer_file",
          offerJson: offerPlain,
          offerObj,
          threadId: firstNonEmpty(envelopeSummary?.thread_id, envelopeSummary?.threadId),
          createdAt: Date.now(),
        });
        if (!rec) return null;

        if (credDefId && rec.credDefId && rec.credDefId !== credDefId) return null;
        if (threadId && rec.threadId && rec.threadId !== threadId) return null;
        if (offerNonce && rec.nonce && rec.nonce !== offerNonce) return null;

        const withSource = { ...rec, source: `offer_file:${path.basename(p)}`, matchedFilePath: p };
        cacheOfferRecord(withSource);
        return withSource;
      } catch (_) {
        // envelope do holder: não tentar tratá-lo como oferta plana
        return null;
      }
    }

    return null;
  } catch (_) {
    return null;
  }
}

async function resolveOfferByCompanionFiles(issuerDid, requestFilePath, offerFilePathOpt, credDefId, threadId, offerNonce) {
  const candidates = buildOfferEnvelopeCandidates(requestFilePath, offerFilePathOpt);
  for (const p of candidates) {
    const rec = await resolveOfferFromEnvelopeFile(issuerDid, p, credDefId, threadId, offerNonce);
    if (rec) {
      return { rec, candidatesTried: candidates, matchedFilePath: rec.matchedFilePath || p };
    }
  }
  return { rec: null, candidatesTried: candidates, matchedFilePath: null };
}

function pickIssuerVerkeyHint(envelopeSummary) {
  return firstNonEmpty(
    envelopeSummary?.sender_verkey,
    envelopeSummary?.crypto?.sender_verkey,
    envelopeSummary?.crypto?.senderVerkey,
    envelopeSummary?.from?.verkey,
    envelopeSummary?.sender_verkey,
    envelopeSummary?.senderVerkey,
    envelopeSummary?.from_verkey
  );
}

function extractIssuerDidFromCredDefId(credDefId) {
  const id = String(credDefId || "").trim();
  if (!id) return "";
  const marker = ":3:CL:";
  const idx = id.indexOf(marker);
  if (idx <= 0) return "";
  return id.slice(0, idx).trim();
}

async function resolveIssuerVerkeyHintForOffer(envelopeSummary, credDefId, holderDid) {
  const credDefIdStr = String(credDefId || "").trim();
  const holderDidStr = String(holderDid || "").trim();
  const issuerDid = extractIssuerDidFromCredDefId(credDefIdStr);
  const envelopeSenderVerkey = pickIssuerVerkeyHint(envelopeSummary);
  const recipientVerkey = extractRecipientVerkeyFromEnvelope(envelopeSummary);

  if (issuerDid) {
    try {
      const issuerDidRecord = await ssi.getDid(issuerDid);
      const issuerDidVerkey = extractVerkeyFromUnknownRecord(issuerDidRecord);
      if (issuerDidVerkey) {
        return {
          issuerVerkey: issuerDidVerkey,
          issuerDidHint: issuerDid,
          source: "creddef_issuer_did",
        };
      }
    } catch (_) {
      // fallback para dica do envelope
    }
  }

  if (
    envelopeSenderVerkey
    && recipientVerkey
    && envelopeSenderVerkey === recipientVerkey
    && (!issuerDid || !holderDidStr || issuerDid !== holderDidStr)
  ) {
    return {
      issuerVerkey: "",
      issuerDidHint: issuerDid || null,
      source: "envelope_sender_equals_recipient",
    };
  }

  return {
    issuerVerkey: envelopeSenderVerkey || "",
    issuerDidHint: issuerDid || null,
    source: envelopeSenderVerkey ? "envelope_sender" : "not_found",
  };
}

function parsePositiveEpochMs(value, fieldName) {
  if (value === undefined || value === null || String(value).trim() === "") return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    const e = new Error(`Campo inválido: ${fieldName}`);
    e.code = "VALIDATION_ERROR";
    e.details = { field: fieldName };
    throw e;
  }
  return Math.trunc(parsed);
}

function parsePositiveEpochSeconds(value, fieldName) {
  if (value === undefined || value === null || String(value).trim() === "") {
    const e = new Error(`Campo obrigatório: ${fieldName}`);
    e.code = "VALIDATION_ERROR";
    e.details = { field: fieldName };
    throw e;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    const e = new Error(`Campo inválido: ${fieldName}`);
    e.code = "VALIDATION_ERROR";
    e.details = { field: fieldName };
    throw e;
  }
  return Math.trunc(parsed);
}

function parsePtBrDateToUtcEpochSeconds(value, fieldName) {
  const raw = String(value || "").trim();
  const match = raw.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  if (!match) {
    const e = new Error(`Campo inválido: ${fieldName}`);
    e.code = "VALIDATION_ERROR";
    e.details = { field: fieldName };
    throw e;
  }
  const day = Number(match[1]);
  const month = Number(match[2]);
  const year = Number(match[3]);
  const ms = Date.UTC(year, month - 1, day, 0, 0, 0, 0);
  const date = new Date(ms);
  if (
    date.getUTCFullYear() !== year
    || date.getUTCMonth() !== month - 1
    || date.getUTCDate() !== day
  ) {
    const e = new Error(`Campo inválido: ${fieldName}`);
    e.code = "VALIDATION_ERROR";
    e.details = { field: fieldName };
    throw e;
  }
  return Math.trunc(ms / 1000);
}

function parsePtBrDateTimeToLocalEpochSeconds(dateValue, timeValue, dateFieldName, timeFieldName) {
  const rawDate = String(dateValue || "").trim();
  const rawTime = String(timeValue || "").trim();
  const dateMatch = rawDate.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  const timeMatch = rawTime.match(/^(\d{2}):(\d{2}):(\d{2})$/);
  if (!dateMatch) {
    const e = new Error(`Campo inválido: ${dateFieldName}`);
    e.code = "VALIDATION_ERROR";
    e.details = { field: dateFieldName };
    throw e;
  }
  if (!timeMatch) {
    const e = new Error(`Campo inválido: ${timeFieldName}`);
    e.code = "VALIDATION_ERROR";
    e.details = { field: timeFieldName };
    throw e;
  }
  const day = Number(dateMatch[1]);
  const month = Number(dateMatch[2]);
  const year = Number(dateMatch[3]);
  const hours = Number(timeMatch[1]);
  const minutes = Number(timeMatch[2]);
  const seconds = Number(timeMatch[3]);
  if (
    !Number.isFinite(hours) || hours < 0 || hours > 23
    || !Number.isFinite(minutes) || minutes < 0 || minutes > 59
    || !Number.isFinite(seconds) || seconds < 0 || seconds > 59
  ) {
    const e = new Error(`Campo inválido: ${timeFieldName}`);
    e.code = "VALIDATION_ERROR";
    e.details = { field: timeFieldName };
    throw e;
  }
  const date = new Date(year, month - 1, day, hours, minutes, seconds, 0);
  if (
    date.getFullYear() !== year
    || date.getMonth() !== month - 1
    || date.getDate() !== day
    || date.getHours() !== hours
    || date.getMinutes() !== minutes
    || date.getSeconds() !== seconds
  ) {
    const e = new Error(`Campo inválido: ${dateFieldName}`);
    e.code = "VALIDATION_ERROR";
    e.details = { field: dateFieldName };
    throw e;
  }
  return Math.trunc(date.getTime() / 1000);
}

function addUnitsUtcEpoch(baseEpochSeconds, unitOfTime, amount) {
  const date = new Date(Number(baseEpochSeconds) * 1000);
  const unit = String(unitOfTime || "").trim().toLowerCase();
  switch (unit) {
    case "second":
    case "seconds":
      date.setUTCSeconds(date.getUTCSeconds() + amount);
      break;
    case "minute":
    case "minutes":
      date.setUTCMinutes(date.getUTCMinutes() + amount);
      break;
    case "hour":
    case "hours":
      date.setUTCHours(date.getUTCHours() + amount);
      break;
    case "day":
    case "days":
      date.setUTCDate(date.getUTCDate() + amount);
      break;
    case "week":
    case "weeks":
      date.setUTCDate(date.getUTCDate() + (amount * 7));
      break;
    case "month":
    case "months":
      date.setUTCMonth(date.getUTCMonth() + amount);
      break;
    case "year":
    case "years":
      date.setUTCFullYear(date.getUTCFullYear() + amount);
      break;
    case "decade":
    case "decades":
      date.setUTCFullYear(date.getUTCFullYear() + (amount * 10));
      break;
    default: {
      const e = new Error("Campo inválido: unitOfTime");
      e.code = "VALIDATION_ERROR";
      e.details = { field: "unitOfTime" };
      throw e;
    }
  }
  return Math.trunc(date.getTime() / 1000);
}

function computeSingleWindowValidityEnd(startTime, unitOfTime, timeWindow) {
  const nextBoundaryEpoch = addUnitsUtcEpoch(startTime, unitOfTime, timeWindow);
  const validityEnd = nextBoundaryEpoch - 1;
  if (!Number.isFinite(validityEnd) || validityEnd < startTime) {
    const e = new Error("Não foi possível calcular validityEnd.");
    e.code = "VALIDATION_ERROR";
    throw e;
  }
  return validityEnd;
}

function sanitizeRevocableCredentialValues(valuesObj) {
  if (!valuesObj || typeof valuesObj !== "object" || Array.isArray(valuesObj)) {
    return { sanitized: {}, removedKeys: [] };
  }
  const sanitized = {};
  const removedKeys = new Set();
  Object.entries(valuesObj).forEach(([key, value]) => {
    if (REVOCATION_CONTROL_ATTRIBUTE_NAMES.has(String(key))) {
      removedKeys.add(String(key) === "root_merkle_l" ? "root_merkle_L" : String(key));
      return;
    }
    sanitized[key] = value;
  });
  return { sanitized, removedKeys: Array.from(removedKeys) };
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
  Object.entries(values).forEach(([k, v]) => {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const raw = firstNonEmpty(v?.raw);
      if (raw) out[k] = raw;
    }
  });
  return out;
}

function extractCredentialAttributesForPreview(credentialObj) {
  if (!credentialObj || typeof credentialObj !== "object") return [];

  const values = credentialObj.values;
  if (values && typeof values === "object" && !Array.isArray(values)) {
    return Object.entries(values)
      .map(([name, value]) => {
        if (value && typeof value === "object" && !Array.isArray(value)) {
          const hasRaw = Object.prototype.hasOwnProperty.call(value, "raw");
          return {
            name,
            value: hasRaw ? String(value.raw ?? "") : firstNonEmpty(value?.value, value?.encoded),
            encoded: value?.encoded !== undefined && value?.encoded !== null
              ? String(value.encoded)
              : null,
          };
        }
        return {
          name,
          value: value === undefined || value === null ? "" : String(value),
          encoded: null,
        };
      })
      .sort((a, b) => String(a.name).localeCompare(String(b.name), "pt-BR"));
  }

  const valuesRaw = normalizeCredentialValuesRaw(credentialObj);
  return Object.entries(valuesRaw)
    .map(([name, value]) => ({
      name,
      value: value === undefined || value === null ? "" : String(value),
      encoded: null,
    }))
    .sort((a, b) => String(a.name).localeCompare(String(b.name), "pt-BR"));
}

function parseCredentialsRecords(rawData) {
  const parsed = parseJsonMaybeString(rawData, rawData);
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
    .map((it) => {
      const parsedItem = parseJsonMaybeString(it, it);
      const unwrapped = unwrapLedgerPayload(parsedItem);
      if (!unwrapped || typeof unwrapped !== "object") return null;
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

function normalizeComparableValuesMap(valuesRaw) {
  if (!valuesRaw || typeof valuesRaw !== "object" || Array.isArray(valuesRaw)) return {};
  const out = {};
  Object.keys(valuesRaw)
    .map((k) => String(k || "").trim())
    .filter(Boolean)
    .sort()
    .forEach((k) => {
      out[k] = String(valuesRaw[k] ?? "").trim();
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
  for (const k of aKeys) {
    if (!Object.prototype.hasOwnProperty.call(b, k)) return false;
    if (a[k] !== b[k]) return false;
  }
  return true;
}

async function findMatchingStoredCredentialId(credentialObj, credDefIdHint, preferredIdLocal) {
  const preferred = String(preferredIdLocal || "").trim();
  const targetCredDefId = firstNonEmpty(
    credDefIdHint,
    extractCredDefIdFromCredential(credentialObj)
  );
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
    const foundById = records.find((r) => firstNonEmpty(r?.id_local, r?.id) === preferred);
    if (foundById) {
      const foundFingerprint = fingerprintCredentialObject(foundById);
      if (targetFingerprint && foundFingerprint && foundFingerprint === targetFingerprint) {
        return preferred;
      }
    }
  }

  const byCredDef = targetCredDefId
    ? records.filter((r) => firstNonEmpty(r?.cred_def_id, r?.credDefId) === targetCredDefId)
    : records;

  if (targetFingerprint) {
    const foundByFingerprint = byCredDef.find((r) => {
      const recFingerprint = fingerprintCredentialObject(r);
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

  const found = byCredDef.find((r) => valuesRawMapsEqual(targetValues, r?.values_raw));
  return firstNonEmpty(found?.id_local, found?.id);
}

function parsePredicateType(value) {
  const pType = String(value || "").trim();
  if (pType === ">=" || pType === ">" || pType === "<=" || pType === "<") return pType;
  return "";
}

function parseIntegerStrict(value) {
  const num = Number(value);
  if (!Number.isFinite(num) || !Number.isInteger(num)) return null;
  return num;
}

function buildPresentationArtifacts(selectionRaw, proofName, proofVersion, proofNonce) {
  const selectionList = Array.isArray(selectionRaw) ? selectionRaw : [];
  const requestedAttributes = {};
  const requestedPredicates = {};
  const requestedCredAttributes = {};
  const requestedCredPredicates = {};
  const usedSchemaIds = new Set();
  const usedCredDefIds = new Set();
  let attrRefSeq = 1;
  let predRefSeq = 1;
  const requiredControlAttrs = REVOCATION_CONTROL_ATTRIBUTE_CANONICAL_NAMES;
  const normalizeControlAttrName = (name) => {
    const raw = String(name || "").trim();
    return raw === "root_merkle_l" ? "root_merkle_L" : raw;
  };

  for (const itemRaw of selectionList) {
    const item = itemRaw && typeof itemRaw === "object" ? itemRaw : {};
    const credentialId = firstNonEmpty(
      item?.credentialId,
      item?.credId,
      item?.id_local,
      item?.id
    );
    const schemaId = firstNonEmpty(item?.schemaId, item?.schema_id);
    const credDefId = firstNonEmpty(item?.credDefId, item?.cred_def_id);
    const attributes = Array.isArray(item?.attributes) ? item.attributes : [];
    const valuesRaw = item?.valuesRaw && typeof item.valuesRaw === "object" && !Array.isArray(item.valuesRaw)
      ? item.valuesRaw
      : (item?.values_raw && typeof item.values_raw === "object" && !Array.isArray(item.values_raw)
        ? item.values_raw
        : {});
    const requiredPresent = requiredControlAttrs.filter((attrName) => {
      if (Object.prototype.hasOwnProperty.call(valuesRaw, attrName)) return true;
      if (attrName === "root_merkle_L" && Object.prototype.hasOwnProperty.call(valuesRaw, "root_merkle_l")) return true;
      return false;
    });
    const attributesNormalized = [];
    const seenAttrNames = new Set();

    for (const attrRaw of attributes) {
      const attr = attrRaw && typeof attrRaw === "object" ? attrRaw : {};
      const normalizedName = normalizeControlAttrName(firstNonEmpty(attr?.name, attr?.attrName, attr?.key));
      if (!normalizedName || seenAttrNames.has(normalizedName)) continue;
      seenAttrNames.add(normalizedName);
      if (requiredPresent.includes(normalizedName)) {
        attributesNormalized.push({ name: normalizedName, mode: "revealed" });
      } else {
        attributesNormalized.push({ ...attr, name: normalizedName });
      }
    }

    requiredPresent.forEach((attrName) => {
      if (seenAttrNames.has(attrName)) return;
      seenAttrNames.add(attrName);
      attributesNormalized.push({ name: attrName, mode: "revealed" });
    });

    if (!credentialId || !schemaId || !credDefId || !attributesNormalized.length) continue;

    for (const attrRaw of attributesNormalized) {
      const attr = attrRaw && typeof attrRaw === "object" ? attrRaw : {};
      const attrName = firstNonEmpty(attr?.name, attr?.attrName, attr?.key);
      const mode = String(attr?.mode || "").trim().toLowerCase();
      if (!attrName) continue;

      if (mode === "revealed") {
        const referent = `attr_${attrRefSeq++}`;
        requestedAttributes[referent] = {
          name: attrName,
          restrictions: [{ cred_def_id: credDefId }],
        };
        requestedCredAttributes[referent] = {
          cred_id: credentialId,
          revealed: true,
        };
        usedSchemaIds.add(schemaId);
        usedCredDefIds.add(credDefId);
        continue;
      }

      if (mode === "zkp") {
        const pType = parsePredicateType(firstNonEmpty(attr?.pType, attr?.predicateType));
        const pValue = parseIntegerStrict(firstNonEmpty(attr?.pValue, attr?.predicateValue));
        if (!pType || pValue === null) {
          const e = new Error(
            `Atributo '${attrName}' com modo ZKP exige operador válido (>=, >, <=, <) e valor inteiro.`
          );
          e.code = "INVALID_PREDICATE_CONFIG";
          e.details = {
            attribute: attrName,
            predicateType: firstNonEmpty(attr?.pType, attr?.predicateType) || null,
            predicateValue: firstNonEmpty(attr?.pValue, attr?.predicateValue) || null,
          };
          throw e;
        }

        const referent = `pred_${predRefSeq++}`;
        requestedPredicates[referent] = {
          name: attrName,
          p_type: pType,
          p_value: pValue,
          restrictions: [{ cred_def_id: credDefId }],
        };
        requestedCredPredicates[referent] = { cred_id: credentialId };
        usedSchemaIds.add(schemaId);
        usedCredDefIds.add(credDefId);
      }
    }
  }

  const totalRequested = Object.keys(requestedAttributes).length + Object.keys(requestedPredicates).length;
  if (!totalRequested) {
    const e = new Error("Selecione ao menos um atributo para a apresentação (revelado ou ZKP).");
    e.code = "EMPTY_PRESENTATION_SELECTION";
    throw e;
  }

  return {
    presentationRequest: {
      nonce: proofNonce,
      name: proofName,
      version: proofVersion,
      requested_attributes: requestedAttributes,
      requested_predicates: requestedPredicates,
    },
    requestedCredentials: {
      requested_attributes: requestedCredAttributes,
      requested_predicates: requestedCredPredicates,
    },
    usedSchemaIds: Array.from(usedSchemaIds),
    usedCredDefIds: Array.from(usedCredDefIds),
    counts: {
      requestedAttributes: Object.keys(requestedAttributes).length,
      requestedPredicates: Object.keys(requestedPredicates).length,
      totalRequested,
    },
  };
}

function looksLikePresentationObject(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return false;
  if (obj.proof && typeof obj.proof === "object") return true;
  if (obj.requested_proof && typeof obj.requested_proof === "object") return true;
  if (Array.isArray(obj.identifiers)) return true;
  return false;
}

function looksLikeRevocableCredentialPackage(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return false;
  const credentialCandidate = parseJsonMaybeString(obj.credential_json, obj.credential_json);
  const holderBundle = obj.holder_bundle;
  return !!(
    credentialCandidate
    && typeof credentialCandidate === "object"
    && extractCredDefIdFromCredential(credentialCandidate)
    && holderBundle
    && typeof holderBundle === "object"
  );
}

function looksLikePresentationPackageWithRevocationV2(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return false;
  const presentationCandidate = parseJsonMaybeString(obj.presentation_json, obj.presentation_json);
  return looksLikePresentationObject(presentationCandidate)
    && Array.isArray(obj.revocation_proof_sequences);
}

function collectPresentationIdentifiers(presentationObj) {
  const schemaIds = new Set();
  const credDefIds = new Set();
  const identifiers = Array.isArray(presentationObj?.identifiers)
    ? presentationObj.identifiers
    : [];

  for (const idRaw of identifiers) {
    const idObj = idRaw && typeof idRaw === "object" ? idRaw : {};
    const schemaId = firstNonEmpty(idObj?.schema_id, idObj?.schemaId);
    const credDefId = firstNonEmpty(idObj?.cred_def_id, idObj?.credDefId);
    if (schemaId) schemaIds.add(schemaId);
    if (credDefId) credDefIds.add(credDefId);
  }

  return {
    schemaIds: Array.from(schemaIds),
    credDefIds: Array.from(credDefIds),
  };
}

function buildRevealedAttributesSummary(presentationObj, presentationRequestObj) {
  const reqAttrs = presentationRequestObj?.requested_attributes
    && typeof presentationRequestObj.requested_attributes === "object"
    ? presentationRequestObj.requested_attributes
    : {};
  const reqProof = presentationObj?.requested_proof
    && typeof presentationObj.requested_proof === "object"
    ? presentationObj.requested_proof
    : {};

  const revealedAttrs = reqProof?.revealed_attrs && typeof reqProof.revealed_attrs === "object"
    ? reqProof.revealed_attrs
    : {};
  const revealedGroups = reqProof?.revealed_attr_groups && typeof reqProof.revealed_attr_groups === "object"
    ? reqProof.revealed_attr_groups
    : {};
  const out = [];

  for (const [referent, valueRaw] of Object.entries(revealedAttrs)) {
    const value = valueRaw && typeof valueRaw === "object" ? valueRaw : {};
    const spec = reqAttrs?.[referent] && typeof reqAttrs[referent] === "object"
      ? reqAttrs[referent]
      : {};
    out.push({
      referent,
      name: firstNonEmpty(spec?.name) || null,
      raw: firstNonEmpty(value?.raw) || null,
      encoded: firstNonEmpty(value?.encoded) || null,
      subProofIndex: Number.isFinite(Number(value?.sub_proof_index))
        ? Number(value.sub_proof_index)
        : null,
      source: "revealed_attrs",
    });
  }

  for (const [referent, groupRaw] of Object.entries(revealedGroups)) {
    const group = groupRaw && typeof groupRaw === "object" ? groupRaw : {};
    const values = group?.values && typeof group.values === "object" ? group.values : {};
    const subProofIndex = Number.isFinite(Number(group?.sub_proof_index))
      ? Number(group.sub_proof_index)
      : null;
    for (const [name, vRaw] of Object.entries(values)) {
      const v = vRaw && typeof vRaw === "object" ? vRaw : {};
      out.push({
        referent,
        name: firstNonEmpty(name) || null,
        raw: firstNonEmpty(v?.raw) || null,
        encoded: firstNonEmpty(v?.encoded) || null,
        subProofIndex,
        source: "revealed_attr_groups",
      });
    }
  }

  return out;
}

function buildPredicateProofsSummary(presentationObj, presentationRequestObj, verified) {
  const reqPreds = presentationRequestObj?.requested_predicates
    && typeof presentationRequestObj.requested_predicates === "object"
    ? presentationRequestObj.requested_predicates
    : {};
  const provedPreds = presentationObj?.requested_proof?.predicates
    && typeof presentationObj.requested_proof.predicates === "object"
    ? presentationObj.requested_proof.predicates
    : {};
  const out = [];

  for (const [referent, specRaw] of Object.entries(reqPreds)) {
    const spec = specRaw && typeof specRaw === "object" ? specRaw : {};
    const proofEntry = provedPreds?.[referent] && typeof provedPreds[referent] === "object"
      ? provedPreds[referent]
      : null;
    const subProofIndex = Number.isFinite(Number(proofEntry?.sub_proof_index))
      ? Number(proofEntry.sub_proof_index)
      : null;
    out.push({
      referent,
      name: firstNonEmpty(spec?.name) || null,
      pType: firstNonEmpty(spec?.p_type, spec?.pType) || null,
      pValue: Number.isFinite(Number(spec?.p_value)) ? Number(spec.p_value) : null,
      provedByPresentation: !!proofEntry,
      validAfterVerify: !!verified && !!proofEntry,
      subProofIndex,
    });
  }

  return out;
}

function parseStoredPresentationRecord(rawRecord) {
  const recordObj = parseJsonMaybeString(rawRecord, null);
  if (!recordObj || typeof recordObj !== "object" || Array.isArray(recordObj)) return null;

  const presentationObj = parseJsonMaybeString(recordObj?.presentation, recordObj?.presentation);
  const requestObj = parseJsonMaybeString(
    recordObj?.presentation_request,
    recordObj?.presentation_request
  );
  const metaObj = parseJsonMaybeString(recordObj?.meta, recordObj?.meta);

  if (!presentationObj || typeof presentationObj !== "object") return null;

  return {
    record: recordObj,
    presentation: presentationObj,
    presentationRequest: requestObj && typeof requestObj === "object" ? requestObj : null,
    meta: metaObj && typeof metaObj === "object" ? metaObj : null,
  };
}

function buildStoredPresentationCompactMeta(metaRaw) {
  const metaObj = metaRaw && typeof metaRaw === "object" ? { ...metaRaw } : {};
  const revocationProofSequences = getStoredPresentationRevocationProofSequences(metaObj);
  if (revocationProofSequences.length > 0) {
    metaObj.revocation_proof_sequences = `[omitido ${revocationProofSequences.length} sequência(s) de revogação]`;
  } else {
    delete metaObj.revocation_proof_sequences;
  }
  return metaObj;
}

function buildStoredPresentationCompactRecord(parsed) {
  const recordObj = parsed?.record && typeof parsed.record === "object" ? parsed.record : {};
  const metaObj = buildStoredPresentationCompactMeta(parsed?.meta);
  const presentationObj = parsed?.presentation && typeof parsed.presentation === "object"
    ? parsed.presentation
    : {};
  const presentationRequestObj = parsed?.presentationRequest
    && typeof parsed.presentationRequest === "object"
    ? parsed.presentationRequest
    : {};

  return {
    id_local: firstNonEmpty(recordObj?.id_local, recordObj?.idLocal, recordObj?.id) || null,
    category: firstNonEmpty(recordObj?.category) || null,
    name: firstNonEmpty(recordObj?.name) || null,
    tags: recordObj?.tags && typeof recordObj.tags === "object" ? recordObj.tags : {},
    meta: metaObj,
    presentation_summary: {
      identifiers: Array.isArray(presentationObj?.identifiers) ? presentationObj.identifiers.length : 0,
      revealed_attrs: Object.keys(presentationObj?.requested_proof?.revealed_attrs || {}).length,
      revealed_attr_groups: Object.keys(presentationObj?.requested_proof?.revealed_attr_groups || {}).length,
      predicates: Object.keys(presentationObj?.requested_proof?.predicates || {}).length,
      self_attested_attrs: Object.keys(presentationObj?.requested_proof?.self_attested_attrs || {}).length,
    },
    presentation_request_summary: {
      requested_attributes: Object.keys(presentationRequestObj?.requested_attributes || {}).length,
      requested_predicates: Object.keys(presentationRequestObj?.requested_predicates || {}).length,
    },
  };
}

function getStoredPresentationRevocationProofSequences(metaObj) {
  const seqs = parseJsonMaybeString(
    metaObj?.revocation_proof_sequences,
    metaObj?.revocation_proof_sequences
  );
  return Array.isArray(seqs) ? seqs : [];
}

function getStoredPresentationRevocationProofSequence(raw) {
  const sequence = raw?.proof_sequence || raw?.proofSequence || raw;
  return sequence && typeof sequence === "object" && !Array.isArray(sequence)
    ? sequence
    : null;
}

function getOrderedStoredPresentationRevocationProofs(raw) {
  const sequence = getStoredPresentationRevocationProofSequence(raw);
  if (!sequence) return [];

  const primary = sequence?.primary_proof && typeof sequence.primary_proof === "object"
    ? [sequence.primary_proof]
    : [];
  const confirmations = Array.isArray(sequence?.confirmation_proofs)
    ? sequence.confirmation_proofs.filter((proof) => proof && typeof proof === "object")
    : [];

  return primary.concat(confirmations).sort((a, b) => {
    const aIndex = Number(a?.window_index);
    const bIndex = Number(b?.window_index);
    if (!Number.isFinite(aIndex) && !Number.isFinite(bIndex)) return 0;
    if (!Number.isFinite(aIndex)) return 1;
    if (!Number.isFinite(bIndex)) return -1;
    return aIndex - bIndex;
  });
}

function addRevocationUnitsUtc(baseDate, unitOfTime, amount) {
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

function computeRevocationWindowStartTimestamp(control, windowIndex) {
  const explicit = Number(control?.window_start);
  if (Number.isFinite(explicit) && explicit >= 0) return Math.trunc(explicit);

  const startTime = Number(control?.start_time);
  const timeWindow = Number(control?.time_window);
  const unitOfTime = firstNonEmpty(control?.unit_of_time);
  const idx = Number(windowIndex);
  if (!Number.isFinite(startTime) || startTime < 0 || !Number.isFinite(timeWindow) || timeWindow <= 0 || !unitOfTime) {
    return null;
  }
  if (!Number.isFinite(idx) || idx < 0) return null;

  let cursor = new Date(Math.trunc(startTime) * 1000);
  for (let i = 0; i < Math.trunc(idx); i += 1) {
    const next = addRevocationUnitsUtc(cursor, unitOfTime, Math.trunc(timeWindow));
    if (!next) return null;
    cursor = next;
  }
  return Math.trunc(cursor.getTime() / 1000);
}

function firstPresentRevocationValue(...values) {
  for (const value of values) {
    if (value === undefined || value === null) continue;
    const text = String(value).trim();
    if (text) return text;
  }
  return "";
}

function findStatusForRevocationCoverage(sequenceItem, perCredentialStatus, sequenceIndex) {
  const statuses = Array.isArray(perCredentialStatus) ? perCredentialStatus : [];
  if (!statuses.length) return null;

  const credentialId = firstNonEmpty(sequenceItem?.credential_id_local, sequenceItem?.credentialIdLocal).toLowerCase();
  const credDefId = firstNonEmpty(
    sequenceItem?.cred_def_id,
    sequenceItem?.credDefId,
    sequenceItem?.proof_sequence?.primary_proof?.cred_def_id,
    sequenceItem?.proofSequence?.primary_proof?.cred_def_id
  ).toLowerCase();
  const subProofIndex = firstPresentRevocationValue(sequenceItem?.sub_proof_index, sequenceItem?.subProofIndex);

  if (credentialId || credDefId || subProofIndex) {
    const exact = statuses.find((item) => {
      const itemCredentialId = firstNonEmpty(item?.credential_id_local, item?.credentialIdLocal).toLowerCase();
      const itemCredDefId = firstNonEmpty(item?.cred_def_id, item?.credDefId).toLowerCase();
      const itemSubProofIndex = firstPresentRevocationValue(item?.sub_proof_index, item?.subProofIndex);
      return (
        (!credentialId || itemCredentialId === credentialId)
        && (!credDefId || itemCredDefId === credDefId)
        && (!subProofIndex || itemSubProofIndex === subProofIndex)
      );
    });
    if (exact) return exact;
  }

  const revocableStatuses = statuses.filter((item) => item?.revocable !== false);
  return revocableStatuses[sequenceIndex] || statuses[sequenceIndex] || null;
}

function buildStoredPresentationRevocationWindowCoverage(revocationProofSequences, perCredentialStatus = []) {
  const sequences = Array.isArray(revocationProofSequences) ? revocationProofSequences : [];

  return sequences.map((item, index) => {
    const sequence = getStoredPresentationRevocationProofSequence(item);
    const proofs = getOrderedStoredPresentationRevocationProofs(item);
    const status = findStatusForRevocationCoverage(item, perCredentialStatus, index);
    const primaryProof = proofs[0] || sequence?.primary_proof || {};
    const firstProof = proofs[0] || {};
    const lastProof = proofs[proofs.length - 1] || {};
    const firstWindowIndex = Number(firstProof?.window_index);
    const lastWindowIndex = Number(lastProof?.window_index);
    const uniqueWindowCount = new Set(
      proofs
        .map((proof) => Number(proof?.window_index))
        .filter((windowIndex) => Number.isFinite(windowIndex))
        .map((windowIndex) => Math.trunc(windowIndex))
    ).size;
    const baseControl = {
      ...(item?.control_values || {}),
      ...(item?.controlValues || {}),
      ...(item?.control || {}),
      ...(sequence?.control || {}),
      ...(primaryProof?.control || {}),
    };
    const firstControl = {
      ...baseControl,
      ...(primaryProof?.control || {}),
      ...(firstProof?.control || {}),
      window_start: firstProof?.window_start ?? firstProof?.windowStart,
    };
    const lastControl = {
      ...baseControl,
      ...(primaryProof?.control || {}),
      ...(lastProof?.control || {}),
      window_start: lastProof?.window_start ?? lastProof?.windowStart,
    };
    const firstWindowStart = Number.isFinite(firstWindowIndex)
      ? computeRevocationWindowStartTimestamp(firstControl, firstWindowIndex)
      : null;
    const lastWindowStart = Number.isFinite(lastWindowIndex)
      ? computeRevocationWindowStartTimestamp(lastControl, lastWindowIndex)
      : null;

    return {
      sequence_index: index,
      credential_id_local: firstNonEmpty(
        item?.credential_id_local,
        item?.credentialIdLocal,
        status?.credential_id_local,
        status?.credentialIdLocal
      ) || null,
      sub_proof_index: firstPresentRevocationValue(
        item?.sub_proof_index,
        item?.subProofIndex,
        status?.sub_proof_index,
        status?.subProofIndex
      ) || null,
      cred_def_id: firstNonEmpty(
        item?.cred_def_id,
        item?.credDefId,
        primaryProof?.cred_def_id,
        status?.cred_def_id,
        status?.credDefId
      ) || null,
      delivered_window_count: uniqueWindowCount || proofs.length,
      first_window_index: Number.isFinite(firstWindowIndex) ? Math.trunc(firstWindowIndex) : null,
      first_window_start: firstWindowStart,
      last_window_index: Number.isFinite(lastWindowIndex) ? Math.trunc(lastWindowIndex) : null,
      last_window_start: lastWindowStart,
      proof_count: proofs.length,
      revoked: status?.revoked ?? null,
      requires_more_windows: status?.requires_more_windows ?? null,
      accepted: status?.accepted ?? null,
    };
  });
}

async function loadStoredPresentationRevocationProofSequences(presentationIdLocal, metaObj) {
  const fromMeta = getStoredPresentationRevocationProofSequences(metaObj);
  if (fromMeta.length > 0) return fromMeta;
  if (!presentationIdLocal) return [];

  const raw = await ssi.getStoredPresentationRevocationSequences(String(presentationIdLocal));
  const parsed = parseJsonMaybeString(raw, []);
  return Array.isArray(parsed) ? parsed : [];
}

async function verifyStoredPresentationLiveRevocation(genesisPathInput, parsed, presentationIdLocalInput) {
  const genesisPath = firstNonEmpty(
    genesisPathInput,
    parsed?.meta?.verification_genesis_path,
    parsed?.meta?.verify_genesis_path
  );
  const presentationObj = parsed?.presentation;
  const presentationRequestObj = parsed?.presentationRequest;
  const presentationIdLocal = firstNonEmpty(
    presentationIdLocalInput,
    parsed?.record?.id_local,
    parsed?.record?.idLocal,
    parsed?.record?.id
  );
  const revocationProofSequences = await loadStoredPresentationRevocationProofSequences(
    presentationIdLocal,
    parsed?.meta
  );

  if (!presentationObj || typeof presentationObj !== "object") {
    return {
      attempted: false,
      ok: false,
      reason: "presentation_missing",
      message: "Apresentação armazenada ausente ou inválida.",
    };
  }
  if (!presentationRequestObj || typeof presentationRequestObj !== "object") {
    return {
      attempted: false,
      ok: false,
      reason: "presentation_request_missing",
      message: "Presentation Request armazenada ausente; não é possível revalidar a revogação.",
    };
  }
  if (!revocationProofSequences.length) {
    return {
      attempted: false,
      ok: true,
      reason: "no_revocation_sequences",
      message: "Apresentação salva sem sequências de revogação; nenhuma revalidação viva é necessária.",
      revocableCredentialsPresent: false,
      perCredentialStatus: [],
      revocationProofSequences: [],
    };
  }
  if (!genesisPath) {
    return {
      attempted: false,
      ok: false,
      reason: "genesis_path_missing",
      message: "Genesis path ausente; não é possível revalidar a revogação desta apresentação salva.",
      revocableCredentialsPresent: true,
      perCredentialStatus: [],
    };
  }

  const ids = collectPresentationIdentifiers(presentationObj);
  if (!ids.schemaIds.length || !ids.credDefIds.length) {
    return {
      attempted: false,
      ok: false,
      reason: "missing_identifiers",
      message: "Apresentação armazenada sem identifiers suficientes para revalidação.",
      revocableCredentialsPresent: true,
      perCredentialStatus: [],
    };
  }

  const schemasMap = {};
  for (const schemaId of ids.schemaIds) {
    const schemaRaw = await ssi.fetchSchemaFromLedger(String(genesisPath), schemaId);
    const schemaObj = unwrapLedgerPayload(schemaRaw);
    if (!schemaObj || typeof schemaObj !== "object") {
      const e = new Error(`Schema inválido no ledger: ${schemaId}`);
      e.code = "INVALID_SCHEMA_LEDGER_JSON";
      throw e;
    }
    schemasMap[schemaId] = schemaObj;
  }

  const credDefsMap = {};
  for (const credDefId of ids.credDefIds) {
    const resolvedCredDef = await fetchLedgerCredDefOrThrow(String(genesisPath), credDefId);
    credDefsMap[credDefId] = resolvedCredDef.credDefObj;
  }

  const refreshedProofSequences = [];
  const revocationManifestRefreshes = [];
  for (const item of revocationProofSequences) {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      refreshedProofSequences.push(item);
      continue;
    }
    const proofSequence = item.proof_sequence || item.proofSequence || null;
    if (!proofSequence || typeof proofSequence !== "object" || Array.isArray(proofSequence)) {
      refreshedProofSequences.push(item);
      continue;
    }

    const refresh = await refreshProofSequenceManifestAnchors(String(genesisPath), proofSequence);
    const refreshedProofSequence = refresh?.proofSequence || proofSequence;
    refreshedProofSequences.push({
      ...item,
      proof_sequence: refreshedProofSequence,
    });
    revocationManifestRefreshes.push({
      credentialIdLocal: firstNonEmpty(
        item?.credential_id_local,
        item?.credentialIdLocal,
        refreshedProofSequence?.credential_id_local
      ) || null,
      credDefId: firstNonEmpty(item?.cred_def_id, item?.credDefId) || null,
      issuerDid: refresh?.issuerDid || null,
      manifestUrl: refresh?.manifestUrl || null,
      refreshed: !!refresh?.refreshed,
      source: refresh?.source || null,
      fromCache: !!refresh?.fromCache,
      previousManifestHash: refresh?.previousManifestHash || null,
      effectiveManifestHash: refresh?.effectiveManifestHash || null,
      ledgerManifestHash: refresh?.ledgerManifest?.manifest_hash || null,
      liveManifestHash: refresh?.liveManifest?.manifest_hash || null,
    });
  }

  const verifyMixedRaw = await ssi.verifyMixedPresentationPackageV2(
    JSON.stringify(presentationRequestObj),
    JSON.stringify(presentationObj),
    JSON.stringify(schemasMap),
    JSON.stringify(credDefsMap),
    JSON.stringify(refreshedProofSequences),
    null,
    null
  );
  const verifyMixed = parseJsonMaybeString(verifyMixedRaw, null);
  if (!verifyMixed || typeof verifyMixed !== "object") {
    const e = new Error("Resposta inválida ao revalidar apresentação salva.");
    e.code = "INVALID_VERIFY_STORED_PRESENTATION_RESPONSE";
    throw e;
  }

  return {
    attempted: true,
    ok: true,
    genesisPathUsed: genesisPath,
    cryptographicValid: !!verifyMixed.cryptographic_valid,
    proofsVerified: !!verifyMixed.proofs_verified,
    revoked: !!verifyMixed.revoked,
    requiresMoreWindows: !!verifyMixed.requires_more_windows,
    accepted: !!verifyMixed.accepted,
    policy: verifyMixed.policy ?? null,
    perCredentialStatus: Array.isArray(verifyMixed.per_credential_status)
      ? verifyMixed.per_credential_status
      : [],
    revocationManifestRefreshes,
    revocationProofSequences: refreshedProofSequences,
  };
}

function compactStoredPresentationLiveRevocationCheck(liveRevocationCheck) {
  const live = liveRevocationCheck && typeof liveRevocationCheck === "object"
    ? liveRevocationCheck
    : {};
  const perCredentialStatus = Array.isArray(live.perCredentialStatus)
    ? live.perCredentialStatus
    : [];
  const revocationManifestRefreshes = Array.isArray(live.revocationManifestRefreshes)
    ? live.revocationManifestRefreshes
    : [];
  const revocationProofSequencesCount = Array.isArray(live.revocationProofSequences)
    ? live.revocationProofSequences.length
    : 0;

  return {
    attempted: !!live.attempted,
    ok: live.ok === undefined ? null : !!live.ok,
    reason: firstNonEmpty(live.reason) || null,
    message: firstNonEmpty(live.message) || null,
    genesisPathUsed: firstNonEmpty(live.genesisPathUsed) || null,
    revocableCredentialsPresent: live.revocableCredentialsPresent ?? null,
    cryptographicValid: live.cryptographicValid ?? null,
    proofsVerified: live.proofsVerified ?? null,
    revoked: live.revoked ?? null,
    requiresMoreWindows: live.requiresMoreWindows ?? null,
    accepted: live.accepted ?? null,
    policy: live.policy ?? null,
    perCredentialStatus,
    revocationManifestRefreshes,
    counts: {
      perCredentialStatus: perCredentialStatus.length,
      revocationManifestRefreshes: revocationManifestRefreshes.length,
      revocationProofSequences: revocationProofSequencesCount,
    },
  };
}

function looksLikePresentationRequestObject(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return false;
  const reqAttrs = obj?.requested_attributes;
  const reqPreds = obj?.requested_predicates;
  return (
    reqAttrs
    && typeof reqAttrs === "object"
    && !Array.isArray(reqAttrs)
    && reqPreds
    && typeof reqPreds === "object"
    && !Array.isArray(reqPreds)
  );
}

function buildPresentationRequestCandidates(presentationFilePath, explicitRequestFilePath) {
  const out = [];
  const seen = new Set();
  const presPath = String(presentationFilePath || "").trim();
  const presNorm = presPath ? path.normalize(presPath) : "";

  const pushCandidate = (p) => {
    const c = String(p || "").trim();
    if (!c) return;
    const norm = path.normalize(c);
    if (!norm || seen.has(norm)) return;
    if (presNorm && norm === presNorm) return;
    seen.add(norm);
    out.push(norm);
  };

  pushCandidate(explicitRequestFilePath);
  if (!presPath) return out;

  const dir = path.dirname(presPath);
  const base = path.basename(presPath);
  const stem = base.replace(/\.env\.json$/i, "").replace(/\.json$/i, "");

  const stemVariants = [stem];
  if (/_02_presentation$/i.test(stem)) {
    stemVariants.push(stem.replace(/_02_presentation$/i, "_01_request"));
  }
  if (/_presentation$/i.test(stem)) {
    stemVariants.push(stem.replace(/_presentation$/i, "_request"));
  }
  stemVariants.push(stem.replace(/presentation/gi, "request"));

  for (const s of stemVariants) {
    const txt = String(s || "").trim();
    if (!txt) continue;
    pushCandidate(path.join(dir, `${txt}.env.json`));
    pushCandidate(path.join(dir, `${txt}.json`));
  }

  // Convenções comuns dos testes anexados
  pushCandidate(path.join(dir, "proof_01_request.env.json"));
  pushCandidate(path.join(dir, "proof_request.env.json"));

  return out;
}

async function inferPresentationRequestFromCompanionFile(verifierDid, presentationFilePath, explicitRequestFilePath) {
  const candidates = buildPresentationRequestCandidates(presentationFilePath, explicitRequestFilePath);

  for (const candidatePath of candidates) {
    try {
      if (!fs.existsSync(candidatePath)) continue;

      const raw = fs.readFileSync(candidatePath, "utf-8");
      const parsedRaw = parseJsonMaybeString(raw, null);

      if (looksLikePresentationRequestObject(parsedRaw)) {
        return {
          requestObj: parsedRaw,
          source: "companion_request_file_plain",
          filePath: candidatePath,
          candidatesChecked: candidates,
        };
      }

      // Tenta como envelope authcrypt/anoncrypt contendo proof request no plaintext
      try {
        const summary = normalizeEnvelopeSummary(ssi.envelopeParse(raw));
        const kindHint = firstNonEmpty(summary?.kind).toLowerCase();
        if (kindHint && !kindHint.includes("request") && !kindHint.includes("proof")) {
          // segue: alguns ambientes usam kind custom
        }
      } catch (_) {
        // não é envelope parseável, segue para próximo candidato
      }

      let plain = "";
      try {
        plain = await ssi.envelopeUnpackAuto(String(verifierDid), raw);
      } catch (_) {
        plain = "";
      }
      if (!plain) continue;

      const parsedPlain = parseJsonMaybeString(plain, null);
      if (looksLikePresentationRequestObject(parsedPlain)) {
        return {
          requestObj: parsedPlain,
          source: "companion_request_file_envelope",
          filePath: candidatePath,
          candidatesChecked: candidates,
        };
      }
    } catch (_) {
      // ignora candidato inválido e tenta o próximo
    }
  }

  return {
    requestObj: null,
    source: "",
    filePath: null,
    candidatesChecked: candidates,
  };
}

function registerIpcHandlers() {

  if (__ipc_registered) return;
  __ipc_registered = true;

  ipcMain.handle(CH.APP_PING, safeHandler(async () => ({ pong: true, ts: Date.now() })));

  // Wallet
  ipcMain.handle(CH.WALLET_CREATE, safeHandler(async (i) => {
    validateNonEmptyString(i.walletPath, "walletPath");
    validateNonEmptyString(i.pass, "pass");
    return ssi.walletCreate(i.walletPath, i.pass);
  }));

  ipcMain.handle(CH.WALLET_OPEN, safeHandler(async (i) => {
    validateNonEmptyString(i.walletPath, "walletPath");
    validateNonEmptyString(i.pass, "pass");
    return ssi.walletOpen(i.walletPath, i.pass);
  }));

  ipcMain.handle(CH.WALLET_CLOSE, safeHandler(async () => {
    return ssi.walletLock();
  }));

  ipcMain.handle(CH.WALLET_CHANGE_PASS, safeHandler(async (i) => {
    validateNonEmptyString(i.walletPath, "walletPath");
    validateNonEmptyString(i.oldPass, "oldPass");
    validateNonEmptyString(i.newPass, "newPass");
    return ssi.walletChangePass(i.walletPath, i.oldPass, i.newPass);
  }));

  // Ledger (exemplo mínimo)
  ipcMain.handle(CH.LEDGER_CONNECT, safeHandler(async (i) => {
    validateNonEmptyString(i.genesisPath, "genesisPath");
    return ssi.connectNetwork(i.genesisPath);
  }));

  ipcMain.handle(CH.LEDGER_HEALTH, safeHandler(async () => {
    return ssi.networkHealthcheck();
  }));

  ipcMain.handle(CH.ATTRIB_WRITE_ON_LEDGER, safeHandler(async (i) => {
    validateNonEmptyString(i.genesisPath, "genesisPath");
    validateNonEmptyString(i.did, "did");
    validateNonEmptyString(i.key, "key");
    validateNonEmptyString(i.value, "value");
    return ssi.writeAttribOnLedger(i.genesisPath, i.did, i.key, i.value);
  }));

  ipcMain.handle(CH.ATTRIB_READ_FROM_LEDGER, safeHandler(async (i) => {
    validateNonEmptyString(i.genesisPath, "genesisPath");
    validateNonEmptyString(i.did, "did");
    validateNonEmptyString(i.key, "key");
    return ssi.readAttribFromLedger(i.genesisPath, i.did, i.key);
  }));

  ipcMain.handle(CH.ATTRIB_CHECK_EXISTS, safeHandler(async (i) => {
    validateNonEmptyString(i.genesisPath, "genesisPath");
    validateNonEmptyString(i.did, "did");
    validateNonEmptyString(i.key, "key");
    return ssi.checkAttribExists(i.genesisPath, i.did, i.key);
  }));

  ipcMain.handle(CH.WALLET_PICK_PATH, safeHandler(async (i) => {
    const mode = (i && i.mode) || "open"; // "open" ou "save"
    const walletsDir = getWalletsDir();

    if (mode === "save") {
      const r = await showSaveDialog({
        title: "Criar/Selecionar Wallet SQLite (.db)",
        defaultPath: path.join(walletsDir, "wallet.db"),
        filters: [{ name: "SQLite DB", extensions: ["db"] }],
        properties: ["createDirectory", "showOverwriteConfirmation"]
      });

      if (r.canceled || !r.filePath) return { canceled: true };
      return { canceled: false, walletPath: r.filePath };
    }

    // open
    const r = await showOpenDialog({
      title: "Selecionar Wallet SQLite (.db)",
      defaultPath: walletsDir,
      filters: [{ name: "SQLite DB", extensions: ["db"] }],
      properties: ["openFile"]
    });

    if (r.canceled || !r.filePaths || !r.filePaths[0]) return { canceled: true };
    return { canceled: false, walletPath: r.filePaths[0] };
  }));


  // CRIAR DID próprio (sem registrar no ledger, só criar e guardar localmente)
  ipcMain.handle(CH.DID_CREATE_OWN, safeHandler(async () => {
    return ssi.createOwnDid();
  }));

  // DID: listar DIDs
  ipcMain.handle(CH.DID_LIST, safeHandler(async (i) => {
    const category = (i?.category || "own");
    return ssi.listDids(category); // <-- STRING direta
  }));

  // DID: exportar lote (somente did+verkey se você filtrar no opts)
  ipcMain.handle(CH.DID_EXPORT_BATCH, safeHandler(async (i) => {
    const optsJson = toJsonString(i.opts || {});
    return ssi.exportDidsBatch(optsJson);
  }));

  // DID: importar lote
  ipcMain.handle(CH.DID_IMPORT_BATCH, safeHandler(async (i) => {
    // aqui normalmente você manda array de itens ou { items: [{did, verkey, ...}] }
    const optsJson = toJsonString(i.opts || {});
    return ssi.importDidsBatch(optsJson);
  }));

  ipcMain.handle(CH.DID_STORE_THEIR, safeHandler(async (i) => {
    validateNonEmptyString(i.did, "did");
    validateNonEmptyString(i.verkey, "verkey");
    const alias = String(i?.alias || "");
    return ssi.storeTheirDid(i.did, i.verkey, alias);
  }));

  ipcMain.handle(CH.WALLET_INFO, safeHandler(async (i) => {
    // i.walletPath é opcional; se não vier, usa a ativa
    const walletPath = i?.walletPath;
    return ssi.walletInfo(walletPath);
  }));

  ipcMain.handle(CH.WALLET_VERIFY_PASS, safeHandler(async (i) => {
    validateNonEmptyString(i.walletPath, "walletPath");
    validateNonEmptyString(i.pass, "pass");
    return ssi.walletVerifyPass(i.walletPath, i.pass);
  }));

  ipcMain.handle(CH.WALLET_LOCK, safeHandler(async () => {
    return ssi.walletLock();
  }));

  ipcMain.handle(CH.WALLET_GET_SESSION, safeHandler(async () => {
    return ssi.walletGetSession();
  }));

  ipcMain.handle(CH.DID_IMPORT_TRUSTEE, safeHandler(async (i) => {
    validateNonEmptyString(i.seed, "seed");

    console.log("[IPC] did:importTrustee start, seedLen=", String(i.seed).length);

    // Se você tiver wallet session, logue também
    if (ssi.walletGetSession) console.log("[IPC] session:", ssi.walletGetSession());

    const r = await ssi.importDidFromSeed(i.seed);

    console.log("[IPC] did:importTrustee done");
    return r;
  }));

  ipcMain.handle(CH.DID_REGISTER_ON_LEDGER, safeHandler(async (i) => {
    validateNonEmptyString(i.genesisPath, "genesisPath");
    validateNonEmptyString(i.submitterDid, "submitterDid");
    validateNonEmptyString(i.targetDid, "targetDid");
    validateNonEmptyString(i.verkey, "verkey");
    // role pode ser ""/null
    const role = (i.role === undefined) ? null : i.role;
    return ssi.registerDidOnLedger(i.genesisPath, i.submitterDid, i.targetDid, i.verkey, role);
  }));


  ipcMain.handle(CH.DID_EXPORT_FILE, safeHandler(async () => {
    // 1) Buscar DIDs own + external
    const ownStr = await ssi.listDids("own");         // retorna string JSON
    const extStr = await ssi.listDids("external");    // retorna string JSON

    const own = JSON.parse(ownStr || "[]");
    const ext = JSON.parse(extStr || "[]");

    // 2) Normalizar payload exportado
    const exported = []
      .concat(own.map(d => ({
        type: "own",
        alias: d.alias || "",
        did: d.did,
        verkey: d.verkey
      })))
      .concat(ext.map(d => ({
        type: "external",
        alias: d.alias || "",
        did: d.did,
        verkey: d.verkey
      })));

    const payload = {
      format: "ssi-dids-export-v1",
      createdAt: Date.now(),
      count: exported.length,
      dids: exported
    };

    // 3) Escolher onde salvar
    const r = await showSaveDialog({
      title: "Exportar DIDs (alias + did + verkey)",
      defaultPath: path.join(process.cwd(), `dids_export_${Date.now()}.json`),
      filters: [{ name: "JSON", extensions: ["json"] }],
      properties: ["createDirectory", "showOverwriteConfirmation"]
    });

    if (r.canceled || !r.filePath) return { canceled: true };

    fs.writeFileSync(r.filePath, JSON.stringify(payload, null, 2), "utf-8");
    return { canceled: false, filePath: r.filePath, count: exported.length };
  }));

  ipcMain.handle(CH.DID_IMPORT_FILE, safeHandler(async () => {
    const walletSession = await ssi.walletGetSession();
    if (!walletSession?.activeWalletPath) {
      const e = new Error("Nenhuma wallet ativa. Abra a carteira de destino antes de importar.");
      e.code = "NO_ACTIVE_WALLET";
      throw e;
    }

    // 1) Escolher arquivo
    const r = await showOpenDialog({
      title: "Importar DIDs (alias + did + verkey)",
      filters: [{ name: "JSON", extensions: ["json"] }],
      properties: ["openFile"]
    });

    if (r.canceled || !r.filePaths || !r.filePaths[0]) return { canceled: true };

    const filePath = r.filePaths[0];
    const txt = fs.readFileSync(filePath, "utf-8");
    let obj;
    try {
      obj = JSON.parse(txt);
    } catch (_) {
      const e = new Error("Arquivo JSON inválido.");
      e.code = "INVALID_JSON";
      throw e;
    }

    // 2) Validar formato
    const extracted = extractDidImportRows(obj);
    const dids = extracted.dids;
    if (!extracted.recognized) {
      const e = new Error("Formato inválido: esperado { dids: [...] }");
      e.code = "INVALID_FORMAT";
      throw e;
    }

    // 3) Catálogo de DIDs existentes (own + external) para deduplicação rápida.
    // Não deve bloquear a importação se a listagem falhar.
    const existingDids = new Set();
    for (const category of ["own", "external"]) {
      try {
        const listedRaw = await ssi.listDids(category);
        const listed = parseJsonMaybeString(listedRaw, []);
        if (!Array.isArray(listed)) continue;
        for (const row of listed) {
          const did = firstNonEmpty(row?.did, row?.id, row?.did_id, row?.didId);
          if (did) existingDids.add(did);
        }
      } catch (_) {
        // segue com checagem por getDid item a item
      }
    }

    // 4) Import com deduplicação por DID
    const imported = [];
    const skipped = [];
    const errors = [];

    for (const item of dids) {
      try {
        const normalized = normalizeDidImportItem(item);
        const did = String(normalized.did || "").trim();
        const verkey = String(normalized.verkey || "").trim();
        const alias = String(normalized.alias || "").trim();
        const externalAlias = "DID externo";

        if (!did || !verkey) {
          errors.push({ did, alias, reason: "did/verkey ausentes" });
          continue;
        }

        if (existingDids.has(did)) {
          skipped.push({ did, alias, reason: "já existe" });
          continue;
        }

        // grava como external (catálogo)
        await storeDidAsExternal(did, verkey, externalAlias);
        existingDids.add(did);
        imported.push({
          did,
          alias: externalAlias,
          sourceAlias: alias || null,
          storedAs: "external",
        });

        // Alias: por enquanto não persiste no SQLite (lib não tem setter).
        // Vamos manter no resultado e você decide depois se quer patch Rust.
      } catch (e) {
        const duplicateByError = shouldTreatAsDidAlreadyExists(e);
        let existsNow = false;
        if (!duplicateByError) {
          try {
            existsNow = await didExistsInWallet(item?.did, existingDids);
          } catch (_) {
            existsNow = false;
          }
        }

        if (duplicateByError || existsNow) {
          const normalized = normalizeDidImportItem(item);
          const did = String(normalized.did || "").trim();
          const alias = String(normalized.alias || "").trim();
          if (did) existingDids.add(did);
          skipped.push({ did, alias, reason: "já existe" });
          continue;
        }
        errors.push({ item, reason: String(e?.message || e) });
      }
    }

    let ownCountAfter = null;
    let externalCountAfter = null;
    try {
      const ownAfterRaw = await ssi.listDids("own");
      const extAfterRaw = await ssi.listDids("external");
      const ownAfter = parseJsonMaybeString(ownAfterRaw, []);
      const extAfter = parseJsonMaybeString(extAfterRaw, []);
      ownCountAfter = Array.isArray(ownAfter) ? ownAfter.length : null;
      externalCountAfter = Array.isArray(extAfter) ? extAfter.length : null;
    } catch (_) {
      // diagnóstico opcional
    }

    return {
      canceled: false,
      filePath,
      total: dids.length,
      importedCount: imported.length,
      skippedCount: skipped.length,
      errorCount: errors.length,
      ownCountAfter,
      externalCountAfter,
      imported,
      skipped,
      errors
    };
  }));



  // -------------------------
  // Schemas
  // -------------------------

  // -------------------------
  // Schemas
  // -------------------------
  ipcMain.handle(CH.SCHEMA_BUILD_PREVIEW, safeHandler(async (i) => {
    validateNonEmptyString(i?.name, "name");
    validateNonEmptyString(i?.version, "version");
    const attrNames = Array.isArray(i?.attrNames) ? i.attrNames.map(String) : [];
    const revocable = !!i?.revocable;
    return ssi.schemaBuildPreview(String(i.name), String(i.version), attrNames, revocable);
  }));

  ipcMain.handle(CH.SCHEMA_SAVE_LOCAL, safeHandler(async (i) => {
    validateNonEmptyString(i?.name, "name");
    validateNonEmptyString(i?.version, "version");
    const attrNames = Array.isArray(i?.attrNames) ? i.attrNames.map(String) : [];
    const revocable = !!i?.revocable;
    const envLabel = i?.envLabel ? String(i.envLabel) : null;
    return ssi.schemaSaveLocal(String(i.name), String(i.version), attrNames, revocable, envLabel);
  }));

  ipcMain.handle(CH.SCHEMA_LIST_LOCAL, safeHandler(async (i) => {
    const onLedger = i?.onLedger === undefined ? null : !!i.onLedger;
    const envFilter = i?.envFilter ? String(i.envFilter) : null;
    const nameEq = i?.nameEq ? String(i.nameEq) : null;
    return ssi.schemaListLocal(onLedger, envFilter, nameEq);
  }));

  ipcMain.handle(CH.SCHEMA_GET_LOCAL, safeHandler(async (i) => {
    validateNonEmptyString(i?.idLocal, "idLocal");
    return ssi.schemaGetLocal(String(i.idLocal));
  }));

  ipcMain.handle(CH.SCHEMA_DELETE_LOCAL, safeHandler(async (i) => {
    validateNonEmptyString(i?.idLocal, "idLocal");
    return ssi.schemaDeleteLocal(String(i.idLocal));
  }));

  ipcMain.handle(CH.SCHEMA_REGISTER_FROM_LOCAL, safeHandler(async (i) => {
    validateNonEmptyString(i?.genesisPath, "genesisPath");
    validateNonEmptyString(i?.idLocal, "idLocal");
    const issuerDidOpt = i?.issuerDidOpt ? String(i.issuerDidOpt) : null;
    return ssi.schemaRegisterFromLocal(String(i.genesisPath), String(i.idLocal), issuerDidOpt);
  }));

  ipcMain.handle(CH.SCHEMA_CREATE_AND_REGISTER, safeHandler(async (i) => {
    validateNonEmptyString(i?.genesisPath, "genesisPath");
    validateNonEmptyString(i?.issuerDid, "issuerDid");
    validateNonEmptyString(i?.name, "name");
    validateNonEmptyString(i?.version, "version");
    const attrNames = Array.isArray(i?.attrNames) ? i.attrNames.map(String) : [];
    return ssi.createAndRegisterSchema(
      String(i.genesisPath),
      String(i.issuerDid),
      String(i.name),
      String(i.version),
      attrNames
    );
  }));

  ipcMain.handle(CH.SCHEMA_FETCH_FROM_LEDGER, safeHandler(async (i) => {
    validateNonEmptyString(i?.genesisPath, "genesisPath");
    validateNonEmptyString(i?.schemaId, "schemaId");
    return ssi.fetchSchemaFromLedger(String(i.genesisPath), String(i.schemaId));
  }));

  // -------------------------
  // CredDefs
  // -------------------------
  ipcMain.handle(CH.CREDDEF_SAVE_LOCAL, safeHandler(async (i) => {
    validateNonEmptyString(i?.issuerDid, "issuerDid");
    validateNonEmptyString(i?.schemaId, "schemaId");
    validateNonEmptyString(i?.tag, "tag");
    const supportRevocation = !!i?.supportRevocation;
    const envLabel = i?.envLabel ? String(i.envLabel) : null;
    return ssi.creddefSaveLocal(
      String(i.issuerDid),
      String(i.schemaId),
      String(i.tag),
      supportRevocation,
      envLabel
    );
  }));

  ipcMain.handle(CH.CREDDEF_LIST_LOCAL, safeHandler(async (i) => {
    const onLedger = i?.onLedger === undefined || i?.onLedger === null ? null : !!i.onLedger;
    const envFilter = i?.envFilter ? String(i.envFilter) : null;
    const issuerDidEq = i?.issuerDidEq ? String(i.issuerDidEq) : null;
    const schemaIdEq = i?.schemaIdEq ? String(i.schemaIdEq) : null;
    const tagEq = i?.tagEq ? String(i.tagEq) : null;
    return ssi.creddefListLocal(onLedger, envFilter, issuerDidEq, schemaIdEq, tagEq);
  }));

  ipcMain.handle(CH.CREDDEF_GET_LOCAL, safeHandler(async (i) => {
    validateNonEmptyString(i?.idLocal, "idLocal");
    return ssi.creddefGetLocal(String(i.idLocal));
  }));

  ipcMain.handle(CH.CREDDEF_DELETE_LOCAL, safeHandler(async (i) => {
    validateNonEmptyString(i?.idLocal, "idLocal");
    return ssi.creddefDeleteLocal(String(i.idLocal));
  }));

  ipcMain.handle(CH.CREDDEF_REGISTER_FROM_LOCAL, safeHandler(async (i) => {
    validateNonEmptyString(i?.genesisPath, "genesisPath");
    validateNonEmptyString(i?.idLocal, "idLocal");
    const issuerDidOpt = i?.issuerDidOpt ? String(i.issuerDidOpt) : null;
    return ssi.creddefRegisterFromLocal(String(i.genesisPath), String(i.idLocal), issuerDidOpt);
  }));

  ipcMain.handle(CH.CREDDEF_CREATE_AND_REGISTER, safeHandler(async (i) => {
    validateNonEmptyString(i?.genesisPath, "genesisPath");
    validateNonEmptyString(i?.issuerDid, "issuerDid");
    validateNonEmptyString(i?.schemaId, "schemaId");
    validateNonEmptyString(i?.tag, "tag");
    return ssi.createAndRegisterCredDef(
      String(i.genesisPath),
      String(i.issuerDid),
      String(i.schemaId),
      String(i.tag)
    );
  }));

  ipcMain.handle(CH.CREDDEF_FETCH_FROM_LEDGER, safeHandler(async (i) => {
    validateNonEmptyString(i?.genesisPath, "genesisPath");
    validateNonEmptyString(i?.credDefId, "credDefId");
    return ssi.fetchCredDefFromLedger(String(i.genesisPath), String(i.credDefId));
  }));

  ipcMain.handle(CH.CREDENTIAL_LIST, safeHandler(async (i) => {
    const schemaIdEq = i?.schemaIdEq ? String(i.schemaIdEq).trim() : "";
    const credDefIdEq = i?.credDefIdEq ? String(i.credDefIdEq).trim() : "";
    if (!schemaIdEq && !credDefIdEq) {
      return ssi.listCredentials();
    }
    return ssi.listCredentialsBy(
      schemaIdEq || null,
      credDefIdEq || null
    );
  }));

  ipcMain.handle(CH.CREDENTIAL_DELETE, safeHandler(async (i) => {
    validateNonEmptyString(i?.credentialIdLocal, "credentialIdLocal");
    const raw = await ssi.deleteCredential(String(i.credentialIdLocal).trim());
    return parseJsonMaybeString(raw, raw);
  }));

  ipcMain.handle(CH.CRED_REVOKE_LIST_ISSUED_REVOCABLE, safeHandler(async (i) => {
    const statusFilter = i?.statusFilter ? String(i.statusFilter).trim() : "";
    return ssi.listIssuedRevocableCredentials(statusFilter || null);
  }));

  ipcMain.handle(CH.CRED_REVOKE_GET_ISSUED_SUMMARY, safeHandler(async (i) => {
    validateNonEmptyString(i?.issuerLocalCredentialId, "issuerLocalCredentialId");
    return ssi.getIssuedRevocableCredentialSummary(String(i.issuerLocalCredentialId).trim());
  }));

  ipcMain.handle(CH.CRED_REVOKE_DELETE_ISSUED, safeHandler(async (i) => {
    validateNonEmptyString(i?.issuerLocalCredentialId, "issuerLocalCredentialId");
    const raw = await ssi.deleteIssuedRevocableCredential(String(i.issuerLocalCredentialId).trim());
    return parseJsonMaybeString(raw, raw);
  }));

  ipcMain.handle(CH.CRED_REVOKE_PREFLIGHT, safeHandler(async (i) => {
    validateNonEmptyString(i?.issuerLocalCredentialId, "issuerLocalCredentialId");
    const revokeFromWindow = i?.revokeFromWindow;
    if (revokeFromWindow !== undefined && revokeFromWindow !== null && !Number.isFinite(Number(revokeFromWindow))) {
      const e = new Error("revokeFromWindow inválido.");
      e.code = "VALIDATION_ERROR";
      throw e;
    }
    return ssi.preflightRevokeIssuedCredential(
      String(i.issuerLocalCredentialId).trim(),
      revokeFromWindow === undefined || revokeFromWindow === null
        ? null
        : Math.trunc(Number(revokeFromWindow))
    );
  }));

  ipcMain.handle(CH.CRED_REVOKE_EXECUTE, safeHandler(async (i) => {
    validateNonEmptyString(i?.issuerLocalCredentialId, "issuerLocalCredentialId");
    validateNonEmptyString(i?.bloomAdminToken, "bloomAdminToken");
    validateNonEmptyString(i?.genesisPath, "genesisPath");
    const revokeFromWindow = Number(i?.revokeFromWindow);
    if (!Number.isFinite(revokeFromWindow) || revokeFromWindow < 0) {
      const e = new Error("revokeFromWindow inválido.");
      e.code = "VALIDATION_ERROR";
      throw e;
    }
    const issuerLocalCredentialId = String(i.issuerLocalCredentialId).trim();
    const genesisPath = String(i.genesisPath).trim();
    const revokeFromWindowInt = Math.trunc(revokeFromWindow);
    const nativeAddon = getNativeAddonInfo();

    let preflightObj = null;
    let summaryObj = null;
    let manifestUrl = "";
    let bloomManifestBefore = null;

    try {
      const preflightRaw = await ssi.preflightRevokeIssuedCredential(
        issuerLocalCredentialId,
        revokeFromWindowInt
      );
      preflightObj = parseJsonMaybeString(preflightRaw, preflightRaw);
      manifestUrl = extractManifestUrlFromIssuedSummary(preflightObj);
    } catch (_) {
      // Mantém a revogação funcional mesmo se a coleta de diagnóstico falhar.
    }

    try {
      const summaryRaw = await ssi.getIssuedRevocableCredentialSummary(issuerLocalCredentialId);
      summaryObj = parseJsonMaybeString(summaryRaw, summaryRaw);
      manifestUrl = manifestUrl || extractManifestUrlFromIssuedSummary(summaryObj);
    } catch (_) {
      // Mantém a revogação funcional mesmo se a coleta de diagnóstico falhar.
    }

    try {
      bloomManifestBefore = await fetchBloomManifestDiagnostics(manifestUrl);
    } catch (e) {
      bloomManifestBefore = {
        ok: false,
        manifestUrl,
        error: String(e?.message || e || "erro desconhecido"),
      };
    }

    const rawResult = await ssi.revokeIssuedCredentialFromWindow(
      issuerLocalCredentialId,
      String(i.bloomAdminToken).trim(),
      revokeFromWindowInt,
      i?.reason ? String(i.reason) : null,
      i?.requestedBy ? String(i.requestedBy) : null
    );

    const parsedResult = parseJsonMaybeString(rawResult, rawResult);
    let bloomManifestAfter = null;
    let manifestWrite = null;
    try {
      bloomManifestAfter = await fetchBloomManifestDiagnostics(manifestUrl);
    } catch (e) {
      bloomManifestAfter = {
        ok: false,
        manifestUrl,
        error: String(e?.message || e || "erro desconhecido"),
      };
    }

    const issuerDid = firstNonEmpty(
      parsedResult?.issuer_record?.manifest?.issuer_did,
      summaryObj?.issuer_record?.manifest?.issuer_did,
      parsedResult?.issuer_record?.cred_def_id?.split?.(":")?.[0],
      summaryObj?.issuer_record?.cred_def_id?.split?.(":")?.[0],
      preflightObj?.summary?.issuer_did
    );
    const manifestVersion = firstNonEmpty(
      parsedResult?.issuer_record?.manifest?.manifest_version,
      summaryObj?.issuer_record?.manifest?.manifest_version,
      preflightObj?.summary?.manifest_version,
      "1"
    );
    if (issuerDid && manifestUrl) {
      try {
        manifestWrite = await writeLatestManifestAnchorToLedger(
          genesisPath,
          issuerDid,
          manifestUrl,
          manifestVersion
        );
      } catch (e) {
        manifestWrite = {
          ok: false,
          issuerDid,
          manifestUrl,
          error: String(e?.message || e || "erro desconhecido"),
        };
      }
    }

    if (issuerDid && manifestUrl && (!manifestWrite || manifestWrite.ok === false)) {
      try {
        manifestWrite = await writeLatestManifestAnchorToLedger(
          genesisPath,
          issuerDid,
          manifestUrl,
          manifestVersion
        );
      } catch (e) {
        manifestWrite = {
          ok: false,
          issuerDid,
          manifestUrl,
          error: String(e?.message || e || "erro desconhecido"),
          retryAttempted: true,
        };
      }
    }

    const expectedKeysToWrite = Number(preflightObj?.preflight?.revocation_keys_to_write || 0);
    const actualKeysWritten = Number(parsedResult?.revocation_keys_written || 0);
    const bloomInserted = Number(parsedResult?.bloom?.inserted || 0);
    const bloomManifestDelta = diffBloomManifestDiagnostics(bloomManifestBefore, bloomManifestAfter);

    const warnings = [];
    if (expectedKeysToWrite > 0 && actualKeysWritten > 0 && expectedKeysToWrite !== actualKeysWritten) {
      warnings.push(
        `Preflight esperava ${expectedKeysToWrite} chaves, mas o addon reportou ${actualKeysWritten}.`
      );
    }
    if (expectedKeysToWrite > 0 && bloomInserted > 0 && expectedKeysToWrite !== bloomInserted) {
      warnings.push(
        `Preflight esperava ${expectedKeysToWrite} escritas no Bloom, mas a resposta do addon reportou ${bloomInserted}.`
      );
    }
    if (
      expectedKeysToWrite > 0
      && bloomManifestDelta
      && Number.isFinite(bloomManifestDelta.totalInsertedDelta)
      && bloomManifestDelta.totalInsertedDelta !== expectedKeysToWrite
    ) {
      warnings.push(
        `O manifesto Bloom variou ${bloomManifestDelta.totalInsertedDelta}, mas o preflight esperava ${expectedKeysToWrite}.`
      );
    }
    if (manifestWrite && manifestWrite.ok === false) {
      warnings.push(
        `A credencial foi revogada, mas houve falha ao atualizar o manifesto no ledger: ${manifestWrite.error || "erro desconhecido"}.`
      );
    }

    if (parsedResult && typeof parsedResult === "object") {
      if (manifestWrite?.manifest && parsedResult?.issuer_record && typeof parsedResult.issuer_record === "object") {
        parsedResult.issuer_record.manifest = manifestWrite.manifest;
      }
      parsedResult.manifestWrite = manifestWrite;
      parsedResult.electronDiagnostics = {
        issuerLocalCredentialId,
        genesisPath,
        revokeFromWindow: revokeFromWindowInt,
        nativeAddon,
        preflight: preflightObj,
        summary: summaryObj,
        manifestUrl: manifestUrl || null,
        manifestWrite,
        bloomManifestBefore,
        bloomManifestAfter,
        bloomManifestDelta,
        expectedKeysToWrite,
        actualKeysWritten,
        bloomInserted,
        warnings,
      };
      if (manifestWrite && manifestWrite.ok === false) {
        const e = new Error(
          `A revogação foi escrita no Bloom, mas falhou ao ancorar o manifesto atualizado no ledger: ${manifestWrite.error || "erro desconhecido"}.`
        );
        e.code = "REVOCATION_LEDGER_ANCHOR_FAILED";
        throw e;
      }
      return parsedResult;
    }

    return {
      rawResult,
      manifestWrite,
      electronDiagnostics: {
        issuerLocalCredentialId,
        genesisPath,
        revokeFromWindow: revokeFromWindowInt,
        nativeAddon,
        preflight: preflightObj,
        summary: summaryObj,
        manifestUrl: manifestUrl || null,
        manifestWrite,
        bloomManifestBefore,
        bloomManifestAfter,
        bloomManifestDelta,
        expectedKeysToWrite,
        actualKeysWritten,
        bloomInserted,
        warnings,
      },
    };
  }));

  ipcMain.handle(CH.REVOCATION_VERIFY_GET_HOLDER_BUNDLE, safeHandler(async (i) => {
    validateNonEmptyString(i?.bundleIdLocal, "bundleIdLocal");
    return ssi.getHolderRevocationBundle(String(i.bundleIdLocal).trim());
  }));

  ipcMain.handle(CH.REVOCATION_VERIFY_BUILD_PROOF_SEQUENCE, safeHandler(async (i) => {
    validateNonEmptyString(i?.bundleIdLocal, "bundleIdLocal");
    const primaryWindowIndex = Number(i?.primaryWindowIndex);
    if (!Number.isFinite(primaryWindowIndex) || primaryWindowIndex < 0) {
      const e = new Error("primaryWindowIndex inválido.");
      e.code = "VALIDATION_ERROR";
      throw e;
    }
    const additionalWindowCount = i?.additionalWindowCount;
    if (
      additionalWindowCount !== undefined
      && additionalWindowCount !== null
      && (!Number.isFinite(Number(additionalWindowCount)) || Number(additionalWindowCount) < 0)
    ) {
      const e = new Error("additionalWindowCount inválido.");
      e.code = "VALIDATION_ERROR";
      throw e;
    }
    return ssi.buildPresentationRevocationProofV2(
      String(i.bundleIdLocal).trim(),
      Math.trunc(primaryWindowIndex),
      additionalWindowCount === undefined || additionalWindowCount === null
        ? null
        : Math.trunc(Number(additionalWindowCount)),
      i?.credentialIdLocal ? String(i.credentialIdLocal).trim() : null
    );
  }));

  ipcMain.handle(CH.REVOCATION_VERIFY_VERIFY_PROOF_SEQUENCE, safeHandler(async (i) => {
    validateNonEmptyString(i?.proofSequenceJson, "proofSequenceJson");
    const originalProofSequence = parseJsonMaybeString(String(i.proofSequenceJson), null);
    const manifestRefresh =
      originalProofSequence && typeof originalProofSequence === "object" && !Array.isArray(originalProofSequence)
        ? await refreshProofSequenceManifestAnchors(
          i?.genesisPath ? String(i.genesisPath).trim() : "",
          originalProofSequence
        )
        : null;
    const normalizedProofSequenceJson = manifestRefresh?.proofSequence
      ? JSON.stringify(manifestRefresh.proofSequence)
      : String(i.proofSequenceJson);

    const verifyRaw = await ssi.verifyPresentationRevocationProofV2(
      normalizedProofSequenceJson,
      i?.expectedRootMerkleL ? String(i.expectedRootMerkleL).trim() : null,
      i?.policyJson ? String(i.policyJson) : null,
      i?.storeEvent === false ? false : null
    );
    const verifyParsed = parseJsonMaybeString(verifyRaw, verifyRaw);
    if (verifyParsed && typeof verifyParsed === "object" && !Array.isArray(verifyParsed)) {
      verifyParsed.manifestRefresh = manifestRefresh;
      return verifyParsed;
    }
    return {
      rawResult: verifyRaw,
      manifestRefresh,
    };
  }));

  ipcMain.handle(CH.REVOCATION_VERIFY_FULL_SCAN, safeHandler(async (i) => {
    validateNonEmptyString(i?.bundleIdLocal, "bundleIdLocal");
    const bundleIdLocal = String(i.bundleIdLocal).trim();
    const genesisPath = i?.genesisPath ? String(i.genesisPath).trim() : "";
    let manifestRefresh = null;
    let manifestAnchorJson = null;

    try {
      const bundleRaw = await ssi.getHolderRevocationBundle(bundleIdLocal);
      const bundleObj = parseJsonMaybeString(bundleRaw, null);
      if (bundleObj && typeof bundleObj === "object" && !Array.isArray(bundleObj)) {
        const fakeSequence = {
          primary_proof: {
            manifest: bundleObj.manifest || null,
            cred_def_id: bundleObj.cred_def_id || null,
          },
        };
        manifestRefresh = await refreshProofSequenceManifestAnchors(genesisPath, fakeSequence);
        const effectiveManifest = manifestRefresh?.liveManifest
          || manifestRefresh?.ledgerManifest
          || bundleObj.manifest
          || null;
        if (effectiveManifest && typeof effectiveManifest === "object") {
          manifestAnchorJson = JSON.stringify(effectiveManifest);
        }
      }
    } catch (_) {
      manifestRefresh = null;
      manifestAnchorJson = null;
    }

    const rawResult = await ssi.verifyHolderRevocationStatusFullScan(
      bundleIdLocal,
      i?.credentialIdLocal ? String(i.credentialIdLocal).trim() : null,
      i?.expectedRootMerkleL ? String(i.expectedRootMerkleL).trim() : null,
      i?.policyJson ? String(i.policyJson) : null,
      manifestAnchorJson
    );
    const parsed = parseJsonMaybeString(rawResult, rawResult);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      parsed.manifestRefresh = manifestRefresh;
      return parsed;
    }
    return {
      rawResult,
      manifestRefresh,
    };
  }));

  ipcMain.handle(CH.PRESENTATION_CREATE_EXPORT_ENVELOPE, safeHandler(async (i) => {
    validateNonEmptyString(i?.genesisPath, "genesisPath");
    validateNonEmptyString(i?.holderDid, "holderDid");

    const genesisPath = String(i.genesisPath).trim();
    const holderDid = String(i.holderDid).trim();
    const holderDidRecord = await ssi.getDid(holderDid);
    const holderDidResolved = extractDidFromUnknownRecord(holderDidRecord) || holderDid;
    const recipientResolved = await resolveRecipientForPresentation(i?.recipientDid, i?.recipientVerkey);
    const recipientVerkey = recipientResolved.recipientVerkey;

    const allCredentialsRaw = await ssi.listCredentials();
    const allCredentials = parseCredentialsRecords(allCredentialsRaw);
    const credById = new Map(allCredentials.map((rec) => [rec.id_local, rec]));

    const selectionInput = Array.isArray(i?.selection) ? i.selection : [];
    const selectionWithContext = selectionInput.map((raw) => {
      const item = raw && typeof raw === "object" ? raw : {};
      const credentialId = firstNonEmpty(
        item?.credentialId,
        item?.credId,
        item?.id_local,
        item?.id
      );
      const walletRec = credById.get(credentialId);
      return {
        ...item,
        credentialId,
        schemaId: firstNonEmpty(item?.schemaId, item?.schema_id, walletRec?.schema_id),
        credDefId: firstNonEmpty(item?.credDefId, item?.cred_def_id, walletRec?.cred_def_id),
        valuesRaw: walletRec?.values_raw || null,
      };
    });

    const proofName = String(i?.proofName || "").trim() || `presentation-${Date.now()}`;
    const proofVersion = String(i?.proofVersion || "").trim() || "1.0";
    const proofNonce = String(i?.proofNonce || "").trim()
      || `${Date.now()}${Math.floor(Math.random() * 1_000_000)}`;

    const artifacts = buildPresentationArtifacts(
      selectionWithContext,
      proofName,
      proofVersion,
      proofNonce
    );

    const schemasMap = {};
    for (const schemaId of artifacts.usedSchemaIds) {
      const schemaRaw = await ssi.fetchSchemaFromLedger(genesisPath, schemaId);
      const schemaObj = unwrapLedgerPayload(schemaRaw);
      if (!schemaObj || typeof schemaObj !== "object") {
        const e = new Error(`Schema inválido no ledger: ${schemaId}`);
        e.code = "INVALID_SCHEMA_LEDGER_JSON";
        e.details = { schemaId };
        throw e;
      }
      schemasMap[schemaId] = schemaObj;
    }

    const credDefsMap = {};
    for (const credDefId of artifacts.usedCredDefIds) {
      const resolvedCredDef = await fetchLedgerCredDefOrThrow(genesisPath, credDefId);
      credDefsMap[credDefId] = resolvedCredDef.credDefObj;
    }

    const presentationRequestJson = JSON.stringify(artifacts.presentationRequest);
    const requestedCredentialsJson = JSON.stringify(artifacts.requestedCredentials);
    const schemasJson = JSON.stringify(schemasMap);
    const credDefsJson = JSON.stringify(credDefsMap);

    const revocationSequencesInput = Array.isArray(i?.revocationSequences)
      ? i.revocationSequences
      : [];
    const revocationSequences = revocationSequencesInput.map((raw, index) => {
      const item = raw && typeof raw === "object" ? raw : {};
      const credentialIdLocal = firstNonEmpty(
        item?.credential_id_local,
        item?.credentialIdLocal,
        item?.credentialId,
        item?.credId,
        item?.id_local
      );
      const primaryWindowIndex = Number(item?.primary_window_index ?? item?.primaryWindowIndex);
      const additionalWindowCountRaw = item?.additional_window_count ?? item?.additionalWindowCount ?? 0;
      const additionalWindowCount = Number(additionalWindowCountRaw);
      if (!credentialIdLocal) {
        const e = new Error(`Sequência de revogação ${index + 1} sem credential_id_local.`);
        e.code = "INVALID_REVOCATION_SEQUENCE";
        throw e;
      }
      if (!Number.isInteger(primaryWindowIndex) || primaryWindowIndex < 0) {
        const e = new Error(`Sequência de revogação inválida para ${credentialIdLocal}: primary_window_index deve ser inteiro >= 0.`);
        e.code = "INVALID_REVOCATION_SEQUENCE";
        e.details = { credentialIdLocal, primaryWindowIndex };
        throw e;
      }
      if (!Number.isInteger(additionalWindowCount) || additionalWindowCount < 0) {
        const e = new Error(`Sequência de revogação inválida para ${credentialIdLocal}: additional_window_count deve ser inteiro >= 0.`);
        e.code = "INVALID_REVOCATION_SEQUENCE";
        e.details = { credentialIdLocal, additionalWindowCount };
        throw e;
      }
      return {
        credential_id_local: String(credentialIdLocal).trim(),
        primary_window_index: primaryWindowIndex,
        additional_window_count: additionalWindowCount,
      };
    });
    const useRevocationPackage = revocationSequences.length > 0;

    let presentationObj = null;
    let revocationProofSequences = [];
    let usedCredentials = [];
    let revocableCredentialsCount = 0;
    let payloadFormat = "presentation_package_v1";
    if (useRevocationPackage) {
      payloadFormat = "presentation_package_v2_revocation";
      const packageRaw = await ssi.createPresentationPackageWithRevocationV2(
        presentationRequestJson,
        requestedCredentialsJson,
        schemasJson,
        credDefsJson,
        JSON.stringify(revocationSequences)
      );
      const packageObj = parseJsonMaybeString(packageRaw, null);
      if (!packageObj || typeof packageObj !== "object") {
        const e = new Error("Pacote de apresentação revogável inválido: JSON não parseável.");
        e.code = "INVALID_PRESENTATION_PACKAGE_JSON";
        throw e;
      }
      presentationObj = parseJsonMaybeString(packageObj.presentation_json, packageObj.presentation_json);
      revocationProofSequences = Array.isArray(packageObj.revocation_proof_sequences)
        ? packageObj.revocation_proof_sequences
        : [];
      usedCredentials = Array.isArray(packageObj.used_credentials)
        ? packageObj.used_credentials
        : [];
      revocableCredentialsCount = Number(packageObj.revocable_credentials_count || revocationProofSequences.length || 0);
    } else {
      const presentationJson = await ssi.createPresentation(
        presentationRequestJson,
        requestedCredentialsJson,
        schemasJson,
        credDefsJson
      );
      presentationObj = parseJsonMaybeString(presentationJson, null);
    }
    if (!presentationObj || typeof presentationObj !== "object") {
      const e = new Error("Apresentação inválida: JSON não parseável.");
      e.code = "INVALID_PRESENTATION_JSON";
      throw e;
    }

    const kind = String(i?.kind || "").trim() || "ssi/proof/presentation";
    const threadId = String(i?.threadId || "").trim()
      || `th_${Date.now()}_${Math.floor(Math.random() * 1_000_000_000)}`;
    const expiresAtMsOpt = parsePositiveEpochMs(i?.expiresAtMs, "expiresAtMs");

    const inputMeta = i?.metaObj && typeof i.metaObj === "object" && !Array.isArray(i.metaObj)
      ? i.metaObj
      : null;
    const autoMeta = {
      proof_name: proofName,
      proof_version: proofVersion,
      requested_attributes: artifacts.counts.requestedAttributes,
      requested_predicates: artifacts.counts.requestedPredicates,
      payload_format: payloadFormat,
      revocation_sequences: revocationSequences.length,
      revocation_proof_sequences: revocationProofSequences.length,
    };
    const metaObj = { ...(inputMeta || {}), ...autoMeta };
    const metaJson = JSON.stringify(metaObj);

    const presentationPayload = useRevocationPackage
      ? {
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
        }
      : {
          type: "ssi/presentation-envelope-payload",
          version: 1,
          presentation: presentationObj,
          presentation_request: artifacts.presentationRequest,
          requested_credentials: artifacts.requestedCredentials,
          schema_ids: artifacts.usedSchemaIds,
          cred_def_ids: artifacts.usedCredDefIds,
          created_at_ms: Date.now(),
        };
    const presentationPayloadJson = JSON.stringify(presentationPayload);

    const envelopeJson = await ssi.envelopePackAuthcrypt(
      holderDidResolved,
      recipientVerkey,
      kind,
      threadId,
      presentationPayloadJson,
      expiresAtMsOpt,
      metaJson
    );
    const envelopeSummary = normalizeEnvelopeSummary(ssi.envelopeParse(envelopeJson));

    const saveResp = await showSaveDialog({
      title: "Exportar apresentação (Envelope JSON)",
      defaultPath: path.join(process.cwd(), `presentation_${Date.now()}.env.json`),
      filters: [{ name: "Envelope JSON", extensions: ["json"] }],
      properties: ["createDirectory", "showOverwriteConfirmation"]
    });
    if (saveResp.canceled || !saveResp.filePath) {
      return {
        canceled: true,
        holderDid: holderDidResolved,
        recipientDid: recipientResolved.recipientDid,
        recipientVerkey,
      };
    }

    fs.writeFileSync(saveResp.filePath, envelopeJson, "utf-8");

    return {
      canceled: false,
      filePath: saveResp.filePath,
      holderDid: holderDidResolved,
      recipientDid: recipientResolved.recipientDid,
      recipientVerkey,
      recipientVerkeySource: recipientResolved.recipientVerkeySource,
      kind,
      threadId,
      expiresAtMs: expiresAtMsOpt,
      proofName,
      proofVersion,
      proofNonce,
      counts: artifacts.counts,
      schemaIds: artifacts.usedSchemaIds,
      credDefIds: artifacts.usedCredDefIds,
      payloadFormat,
      revocationSequences: revocationSequences.length,
      revocationProofSequences: revocationProofSequences.length,
      revocableCredentialsCount,
      usedCredentials,
      envelopeSummary,
      presentationRequest: artifacts.presentationRequest,
      envelopeBytes: Buffer.byteLength(envelopeJson, "utf-8"),
    };
  }));

  ipcMain.handle(CH.PRESENTATION_VERIFY_IMPORT_ENVELOPE, safeHandler(async (i) => {
    validateNonEmptyString(i?.genesisPath, "genesisPath");

    let presentationFilePath = i?.presentationFilePath ? String(i.presentationFilePath).trim() : "";
    if (!presentationFilePath) {
      const openResp = await showOpenDialog({
        title: "Importar apresentação (Envelope JSON)",
        filters: [{ name: "Envelope JSON", extensions: ["json"] }],
        properties: ["openFile"]
      });
      if (openResp.canceled || !openResp.filePaths || !openResp.filePaths[0]) {
        return { canceled: true };
      }
      presentationFilePath = openResp.filePaths[0];
    }

    const envelopeJson = fs.readFileSync(presentationFilePath, "utf-8");
    const envelopeSummary = normalizeEnvelopeSummary(ssi.envelopeParse(envelopeJson));
    const resolved = await resolveReceiverDidForEnvelope(i?.verifierDid, envelopeSummary);
    const verifierDid = resolved.receiverDid;
    const plaintext = await ssi.envelopeUnpackAuto(verifierDid, envelopeJson);

    const parsedPlain = parseJsonMaybeString(plaintext, null);
    let payloadFormat = "unknown";
    let presentationObj = null;
    let presentationRequestObj = null;
    let requestSource = "";
    let requestCandidatesChecked = [];
    let revocationProofSequences = [];
    let revocationManifestRefreshes = [];

    if (parsedPlain && typeof parsedPlain === "object" && !Array.isArray(parsedPlain)) {
      const embeddedV2PresentationCandidate = parsedPlain.presentation_json;
      const embeddedV2Presentation = parseJsonMaybeString(
        embeddedV2PresentationCandidate,
        embeddedV2PresentationCandidate
      );
      const embeddedV2RequestCandidate = parsedPlain.presentation_request
        ?? parsedPlain.presentationRequest
        ?? parsedPlain.proof_request
        ?? parsedPlain.proofRequest
        ?? parsedPlain.request
        ?? null;
      const embeddedV2Request = parseJsonMaybeString(
        embeddedV2RequestCandidate,
        embeddedV2RequestCandidate
      );

      if (looksLikePresentationPackageWithRevocationV2(parsedPlain)) {
        presentationObj = embeddedV2Presentation;
        payloadFormat = "presentation_package_v2_revocation";
        revocationProofSequences = Array.isArray(parsedPlain.revocation_proof_sequences)
          ? parsedPlain.revocation_proof_sequences
          : [];
        if (looksLikePresentationRequestObject(embeddedV2Request)) {
          presentationRequestObj = embeddedV2Request;
          requestSource = "envelope_payload";
        }
      }

      const embeddedPresentationCandidate = parsedPlain.presentation;
      const embeddedPresentation = parseJsonMaybeString(
        embeddedPresentationCandidate,
        embeddedPresentationCandidate
      );
      const embeddedRequestCandidate = parsedPlain.presentation_request
        ?? parsedPlain.presentationRequest
        ?? parsedPlain.proof_request
        ?? parsedPlain.proofRequest
        ?? parsedPlain.request
        ?? null;
      const embeddedRequest = parseJsonMaybeString(
        embeddedRequestCandidate,
        embeddedRequestCandidate
      );

      if (
        !presentationObj
        && (
        embeddedPresentation
        && looksLikePresentationObject(embeddedPresentation)
        && looksLikePresentationRequestObject(embeddedRequest)
        )
      ) {
        presentationObj = embeddedPresentation;
        presentationRequestObj = embeddedRequest;
        payloadFormat = "presentation_package_v1";
        requestSource = "envelope_payload";
      } else if (!presentationObj && looksLikePresentationObject(parsedPlain)) {
        presentationObj = parsedPlain;
        payloadFormat = "presentation_only";
      }
    }

    if (!presentationObj || typeof presentationObj !== "object") {
      const e = new Error("Payload inválido: não foi possível extrair a apresentação do envelope.");
      e.code = "INVALID_PRESENTATION_PAYLOAD";
      throw e;
    }

    if (!presentationRequestObj || typeof presentationRequestObj !== "object") {
      const requestJsonInput = String(i?.presentationRequestJson || "").trim();
      if (requestJsonInput) {
        const parsedReqInput = parseJsonMaybeString(requestJsonInput, null);
        if (looksLikePresentationRequestObject(parsedReqInput)) {
          presentationRequestObj = parsedReqInput;
          requestSource = "input_json";
        }
      }
    }

    if (!presentationRequestObj || typeof presentationRequestObj !== "object") {
      const inferred = await inferPresentationRequestFromCompanionFile(
        verifierDid,
        presentationFilePath,
        i?.presentationRequestFilePath
      );
      requestCandidatesChecked = Array.isArray(inferred?.candidatesChecked)
        ? inferred.candidatesChecked
        : [];
      if (looksLikePresentationRequestObject(inferred?.requestObj)) {
        presentationRequestObj = inferred.requestObj;
        requestSource = firstNonEmpty(inferred?.source, "companion_request_file");
      }
    }

    if (!presentationRequestObj || typeof presentationRequestObj !== "object") {
      const e = new Error(
        "Presentation Request ausente no envelope e não foi possível inferir arquivo companion. Informe presentationRequestJson ou arquivo de request."
      );
      e.code = "MISSING_PRESENTATION_REQUEST";
      e.details = {
        payloadFormat,
        presentationFilePath,
        requestCandidatesChecked,
      };
      throw e;
    }

    const ids = collectPresentationIdentifiers(presentationObj);
    if (!ids.schemaIds.length || !ids.credDefIds.length) {
      const e = new Error("Apresentação inválida: identifiers sem schema_id/cred_def_id.");
      e.code = "MISSING_PRESENTATION_IDENTIFIERS";
      throw e;
    }

    const schemasMap = {};
    for (const schemaId of ids.schemaIds) {
      const schemaRaw = await ssi.fetchSchemaFromLedger(String(i.genesisPath), schemaId);
      const schemaObj = unwrapLedgerPayload(schemaRaw);
      if (!schemaObj || typeof schemaObj !== "object") {
        const e = new Error(`Schema inválido no ledger: ${schemaId}`);
        e.code = "INVALID_SCHEMA_LEDGER_JSON";
        e.details = { schemaId };
        throw e;
      }
      schemasMap[schemaId] = schemaObj;
    }

    const credDefsMap = {};
    for (const credDefId of ids.credDefIds) {
      const resolvedCredDef = await fetchLedgerCredDefOrThrow(String(i.genesisPath), credDefId);
      credDefsMap[credDefId] = resolvedCredDef.credDefObj;
    }

    let verified = false;
    let cryptographicValid = false;
    let proofsVerified = null;
    let revoked = false;
    let requiresMoreWindows = false;
    let policy = null;
    let perCredentialStatus = [];

    if (payloadFormat === "presentation_package_v2_revocation") {
      const refreshedProofSequences = [];
      revocationManifestRefreshes = [];
      for (const item of revocationProofSequences) {
        if (!item || typeof item !== "object" || Array.isArray(item)) {
          refreshedProofSequences.push(item);
          continue;
        }
        const proofSequence = item.proof_sequence || item.proofSequence || null;
        if (!proofSequence || typeof proofSequence !== "object" || Array.isArray(proofSequence)) {
          refreshedProofSequences.push(item);
          continue;
        }

        const refresh = await refreshProofSequenceManifestAnchors(String(i.genesisPath), proofSequence);
        const refreshedProofSequence = refresh?.proofSequence || proofSequence;
        refreshedProofSequences.push({
          ...item,
          proof_sequence: refreshedProofSequence,
        });
        revocationManifestRefreshes.push({
          credentialIdLocal: firstNonEmpty(
            item?.credential_id_local,
            item?.credentialIdLocal,
            refreshedProofSequence?.credential_id_local
          ) || null,
          credDefId: firstNonEmpty(item?.cred_def_id, item?.credDefId) || null,
          issuerDid: refresh?.issuerDid || null,
          manifestUrl: refresh?.manifestUrl || null,
          refreshed: !!refresh?.refreshed,
          source: refresh?.source || null,
          fromCache: !!refresh?.fromCache,
          previousManifestHash: refresh?.previousManifestHash || null,
          effectiveManifestHash: refresh?.effectiveManifestHash || null,
          ledgerManifestHash: refresh?.ledgerManifest?.manifest_hash || null,
          liveManifestHash: refresh?.liveManifest?.manifest_hash || null,
        });
      }
      revocationProofSequences = refreshedProofSequences;

      const verifyMixedRaw = await ssi.verifyMixedPresentationPackageV2(
        JSON.stringify(presentationRequestObj),
        JSON.stringify(presentationObj),
        JSON.stringify(schemasMap),
        JSON.stringify(credDefsMap),
        JSON.stringify(revocationProofSequences),
        null,
        null
      );
      const verifyMixed = parseJsonMaybeString(verifyMixedRaw, null);
      if (!verifyMixed || typeof verifyMixed !== "object") {
        const e = new Error("Resposta inválida ao verificar pacote de apresentação com revogação.");
        e.code = "INVALID_VERIFY_MIXED_PRESENTATION_RESPONSE";
        throw e;
      }
      cryptographicValid = !!verifyMixed.cryptographic_valid;
      proofsVerified = !!verifyMixed.proofs_verified;
      revoked = !!verifyMixed.revoked;
      requiresMoreWindows = !!verifyMixed.requires_more_windows;
      verified = !!verifyMixed.accepted;
      policy = verifyMixed.policy ?? null;
      perCredentialStatus = Array.isArray(verifyMixed.per_credential_status)
        ? verifyMixed.per_credential_status
        : [];
    } else {
      const verifyRaw = await ssi.verifyPresentation(
        JSON.stringify(presentationRequestObj),
        JSON.stringify(presentationObj),
        JSON.stringify(schemasMap),
        JSON.stringify(credDefsMap)
      );
      const verifyText = String(verifyRaw).trim().toLowerCase();
      verified = verifyRaw === true || verifyText === "true";
      cryptographicValid = verified;
    }

    const revealedAttributes = buildRevealedAttributesSummary(presentationObj, presentationRequestObj);
    const predicateProofs = buildPredicateProofsSummary(presentationObj, presentationRequestObj, verified);

    return {
      canceled: false,
      presentationFilePath,
      verifierDid,
      verifierDidSource: resolved.source,
      requestSource: requestSource || null,
      payloadFormat,
      kind: firstNonEmpty(envelopeSummary?.kind) || null,
      threadId: firstNonEmpty(envelopeSummary?.thread_id, envelopeSummary?.threadId) || null,
      verified,
      cryptographicValid,
      proofsVerified,
      revoked,
      requiresMoreWindows,
      policy,
      counts: {
        revealedAttributes: revealedAttributes.length,
        predicateProofs: predicateProofs.length,
        revocationProofSequences: revocationProofSequences.length,
        revocationStatuses: perCredentialStatus.length,
        revocationManifestRefreshes: revocationManifestRefreshes.length,
      },
      revealedAttributes,
      predicateProofs,
      revocationProofSequences,
      revocationManifestRefreshes,
      perCredentialStatus,
      schemaIds: ids.schemaIds,
      credDefIds: ids.credDefIds,
      envelopeSummary,
      presentationRequest: presentationRequestObj,
      presentation: presentationObj,
    };
  }));

  ipcMain.handle(CH.PRESENTATION_STORE_LOCAL, safeHandler(async (i) => {
    const parsedPresentation = parseJsonMaybeString(i?.presentationObj ?? i?.presentationJson, null);
    if (!parsedPresentation || typeof parsedPresentation !== "object") {
      const e = new Error("Informe a apresentação em JSON objeto.");
      e.code = "INVALID_PRESENTATION_JSON";
      throw e;
    }

    const parsedRequest = parseJsonMaybeString(
      i?.presentationRequestObj ?? i?.presentationRequestJson,
      null
    );
    const parsedMeta = parseJsonMaybeString(i?.metaObj ?? i?.metaJson, null);

    const threadHint = firstNonEmpty(
      i?.threadId,
      parsedMeta?.thread_id,
      parsedMeta?.threadId
    ).replace(/[^a-zA-Z0-9._-]/g, "_");
    const inputId = String(i?.presentationIdLocal || "").trim();
    const autoBase = threadHint
      ? `pres-received-${threadHint}`
      : `pres-received-${Date.now()}`;

    let presentationIdLocal = inputId || autoBase;
    const presentationJson = JSON.stringify(parsedPresentation);
    const presentationRequestJson = parsedRequest && typeof parsedRequest === "object"
      ? JSON.stringify(parsedRequest)
      : null;
    const metaJson = parsedMeta && typeof parsedMeta === "object"
      ? JSON.stringify(parsedMeta)
      : null;

    try {
      await ssi.storePresentation(
        presentationIdLocal,
        presentationJson,
        presentationRequestJson,
        metaJson
      );
    } catch (storeErr) {
      const msg = String(storeErr?.message || storeErr);
      const isDuplicate = msg.includes("Duplicate")
        || msg.includes("duplicate")
        || msg.includes("já existe")
        || msg.includes("already exists");
      if (!inputId && isDuplicate) {
        presentationIdLocal = `pres-received-${Date.now()}`;
        await ssi.storePresentation(
          presentationIdLocal,
          presentationJson,
          presentationRequestJson,
          metaJson
        );
      } else {
        throw storeErr;
      }
    }

    const loadedRaw = await ssi.getStoredPresentation(presentationIdLocal);
    const parsedLoaded = parseStoredPresentationRecord(loadedRaw);

    return {
      presentationIdLocal,
      presentationRequestPresent: !!parsedRequest,
      metaPresent: !!parsedMeta,
      storedRecord: parsedLoaded?.record || null,
    };
  }));

  ipcMain.handle(CH.PRESENTATION_LIST_LOCAL, safeHandler(async () => {
    return ssi.listPresentations();
  }));

  ipcMain.handle(CH.PRESENTATION_GET_LOCAL, safeHandler(async (i) => {
    validateNonEmptyString(i?.presentationIdLocal, "presentationIdLocal");
    const presentationIdLocal = String(i.presentationIdLocal).trim();
    const genesisPath = firstNonEmpty(i?.genesisPath);
    const skipLiveRevocationCheck = i?.skipLiveRevocationCheck === true;
    const compact = i?.compact === true;

    const recordRaw = await ssi.getStoredPresentation(presentationIdLocal);
    const parsed = parseStoredPresentationRecord(recordRaw);
    if (!parsed) {
      const e = new Error("Record de apresentação armazenada inválido.");
      e.code = "INVALID_STORED_PRESENTATION_RECORD";
      throw e;
    }

    const verifiedHint = !!parsed?.meta?.verified;
    const revealedAttributes = parsed.presentationRequest
      ? buildRevealedAttributesSummary(parsed.presentation, parsed.presentationRequest)
      : [];
    const predicateProofs = parsed.presentationRequest
      ? buildPredicateProofsSummary(parsed.presentation, parsed.presentationRequest, verifiedHint)
      : [];
    let liveRevocationCheck = null;
    if (!skipLiveRevocationCheck) {
      try {
        liveRevocationCheck = await verifyStoredPresentationLiveRevocation(
          genesisPath,
          parsed,
          presentationIdLocal
        );
      } catch (e) {
        liveRevocationCheck = {
          attempted: true,
          ok: false,
          message: String(e?.message || e || "erro desconhecido"),
        };
      }
    }

    return {
      presentationIdLocal,
      record: compact ? buildStoredPresentationCompactRecord(parsed) : parsed.record,
      presentation: compact ? null : parsed.presentation,
      presentationRequest: compact ? null : parsed.presentationRequest,
      meta: compact ? buildStoredPresentationCompactMeta(parsed.meta) : parsed.meta,
      revealedAttributes,
      predicateProofs,
      liveRevocationCheck: compact && liveRevocationCheck
        ? compactStoredPresentationLiveRevocationCheck(liveRevocationCheck)
        : liveRevocationCheck,
      counts: {
        revealedAttributes: revealedAttributes.length,
        predicateProofs: predicateProofs.length,
      },
    };
  }));

  ipcMain.handle(CH.PRESENTATION_VERIFY_STORED_REVOCATION, safeHandler(async (i) => {
    validateNonEmptyString(i?.presentationIdLocal, "presentationIdLocal");
    const presentationIdLocal = String(i.presentationIdLocal).trim();
    const genesisPath = firstNonEmpty(i?.genesisPath);

    const recordRaw = await ssi.getStoredPresentation(presentationIdLocal);
    const parsed = parseStoredPresentationRecord(recordRaw);
    if (!parsed) {
      const e = new Error("Record de apresentação armazenada inválido.");
      e.code = "INVALID_STORED_PRESENTATION_RECORD";
      throw e;
    }

    let liveRevocationCheck = null;
    try {
      liveRevocationCheck = await verifyStoredPresentationLiveRevocation(
        genesisPath,
        parsed,
        presentationIdLocal
      );
    } catch (e) {
      liveRevocationCheck = {
        attempted: true,
        ok: false,
        message: String(e?.message || e || "erro desconhecido"),
      };
    }

    const revocationSummary = Array.isArray(parsed?.meta?.revocation_summary)
      ? parsed.meta.revocation_summary
      : [];
    const compactLiveCheck = compactStoredPresentationLiveRevocationCheck(liveRevocationCheck);
    let revocationProofSequencesForCoverage = [];
    if (Array.isArray(liveRevocationCheck?.revocationProofSequences) && liveRevocationCheck.revocationProofSequences.length > 0) {
      revocationProofSequencesForCoverage = liveRevocationCheck.revocationProofSequences;
    } else {
      try {
        revocationProofSequencesForCoverage = await loadStoredPresentationRevocationProofSequences(
          presentationIdLocal,
          parsed.meta
        );
      } catch (_) {
        revocationProofSequencesForCoverage = [];
      }
    }
    const revocationWindowCoverage = buildStoredPresentationRevocationWindowCoverage(
      revocationProofSequencesForCoverage,
      compactLiveCheck.perCredentialStatus.length ? compactLiveCheck.perCredentialStatus : revocationSummary
    );

    return {
      presentationIdLocal,
      liveRevocationCheck: compactLiveCheck,
      revocationSummary,
      revocationWindowCoverage,
      counts: {
        revocationSummary: revocationSummary.length,
        perCredentialStatus: compactLiveCheck.counts.perCredentialStatus,
        revocationManifestRefreshes: compactLiveCheck.counts.revocationManifestRefreshes,
        revocationProofSequences: compactLiveCheck.counts.revocationProofSequences,
        revocationWindowCoverage: revocationWindowCoverage.length,
      },
    };
  }));

  ipcMain.handle(CH.PRESENTATION_DELETE_LOCAL, safeHandler(async (i) => {
    validateNonEmptyString(i?.presentationIdLocal, "presentationIdLocal");
    const presentationIdLocal = String(i.presentationIdLocal).trim();
    const raw = await ssi.deleteStoredPresentation(presentationIdLocal);
    return {
      presentationIdLocal,
      deleted: raw === true || raw === "true",
    };
  }));

  ipcMain.handle(CH.PRESENTATION_EXPORT_STORED_ENVELOPE, safeHandler(async (i) => {
    validateNonEmptyString(i?.presentationIdLocal, "presentationIdLocal");
    validateNonEmptyString(i?.senderDid, "senderDid");

    const presentationIdLocal = String(i.presentationIdLocal).trim();
    const senderDid = String(i.senderDid).trim();
    const senderDidRecord = await ssi.getDid(senderDid);
    const senderDidResolved = extractDidFromUnknownRecord(senderDidRecord) || senderDid;
    const recipientResolved = await resolveRecipientForPresentation(i?.recipientDid, i?.recipientVerkey);

    const recordRaw = await ssi.getStoredPresentation(presentationIdLocal);
    const parsed = parseStoredPresentationRecord(recordRaw);
    if (!parsed) {
      const e = new Error("Record de apresentação armazenada inválido.");
      e.code = "INVALID_STORED_PRESENTATION_RECORD";
      throw e;
    }

    const genesisPath = firstNonEmpty(i?.genesisPath);
    const liveRevocationCheck = await verifyStoredPresentationLiveRevocation(
      genesisPath,
      parsed,
      presentationIdLocal
    );
    const revocationProofSequencesForExport = Array.isArray(liveRevocationCheck?.revocationProofSequences)
      ? liveRevocationCheck.revocationProofSequences
      : await loadStoredPresentationRevocationProofSequences(presentationIdLocal, parsed?.meta);
    if (liveRevocationCheck?.attempted && liveRevocationCheck?.ok) {
      if (!liveRevocationCheck.cryptographicValid || !liveRevocationCheck.proofsVerified) {
        const e = new Error(
          "A apresentação salva não passou na revalidação viva antes da exportação."
        );
        e.code = "STORED_PRESENTATION_LIVE_REVALIDATION_FAILED";
        e.details = liveRevocationCheck;
        throw e;
      }
      if (liveRevocationCheck.revoked) {
        const e = new Error(
          "A apresentação salva contém credencial revogada na revalidação viva e não pode ser exportada."
        );
        e.code = "STORED_PRESENTATION_REVOKED";
        e.details = liveRevocationCheck;
        throw e;
      }
      if (liveRevocationCheck.requiresMoreWindows) {
        const e = new Error(
          "A apresentação salva exige mais janelas de revogação para nova validação e não pode ser exportada com segurança."
        );
        e.code = "STORED_PRESENTATION_NEEDS_MORE_WINDOWS";
        e.details = liveRevocationCheck;
        throw e;
      }
    } else if (revocationProofSequencesForExport.length > 0) {
      const e = new Error(
        firstNonEmpty(
          liveRevocationCheck?.message,
          "Não foi possível revalidar a revogação da apresentação salva antes da exportação."
        )
      );
      e.code = "STORED_PRESENTATION_LIVE_REVALIDATION_UNAVAILABLE";
      e.details = liveRevocationCheck || null;
      throw e;
    }

    const kind = String(i?.kind || "").trim() || "ssi/proof/presentation";
    const threadId = String(i?.threadId || "").trim()
      || firstNonEmpty(parsed?.meta?.thread_id, parsed?.meta?.threadId)
      || `th_${Date.now()}_${Math.floor(Math.random() * 1_000_000_000)}`;
    const expiresAtMsOpt = parsePositiveEpochMs(i?.expiresAtMs, "expiresAtMs");

    const inputMeta = i?.metaObj && typeof i.metaObj === "object" && !Array.isArray(i.metaObj)
      ? i.metaObj
      : null;
    const ids = collectPresentationIdentifiers(parsed.presentation);
    const hasRevocationPackage = revocationProofSequencesForExport.length > 0;
    const mergedMeta = {
      ...(parsed?.meta && typeof parsed.meta === "object" ? parsed.meta : {}),
      ...(inputMeta || {}),
      source: "stored_presentation",
      presentation_id_local: presentationIdLocal,
      payload_format: hasRevocationPackage
        ? "presentation_package_v2_revocation"
        : firstNonEmpty(parsed?.meta?.payload_format) || "presentation_package_v1",
      revocation_proof_sequences: hasRevocationPackage
        ? revocationProofSequencesForExport.length
        : 0,
      last_live_revocation_check: liveRevocationCheck?.attempted && liveRevocationCheck?.ok
        ? {
          checked_at_ms: Date.now(),
          revoked: !!liveRevocationCheck.revoked,
          requires_more_windows: !!liveRevocationCheck.requiresMoreWindows,
          accepted: !!liveRevocationCheck.accepted,
        }
        : undefined,
    };

    const payload = hasRevocationPackage
      ? {
          type: "ssi/presentation-envelope-payload",
          version: 2,
          presentation_json: parsed.presentation,
          presentation_request: parsed.presentationRequest || null,
          schema_ids: ids.schemaIds,
          cred_def_ids: ids.credDefIds,
          revocation_proof_sequences: revocationProofSequencesForExport,
          source: {
            storage: "wallet",
            presentation_id_local: presentationIdLocal,
          },
          created_at_ms: Date.now(),
        }
      : {
          type: "ssi/presentation-envelope-payload",
          version: 1,
          presentation: parsed.presentation,
          presentation_request: parsed.presentationRequest || null,
          meta: parsed.meta || null,
          source: {
            storage: "wallet",
            presentation_id_local: presentationIdLocal,
          },
          created_at_ms: Date.now(),
        };

    const envelopeJson = await ssi.envelopePackAuthcrypt(
      senderDidResolved,
      recipientResolved.recipientVerkey,
      kind,
      threadId,
      JSON.stringify(payload),
      expiresAtMsOpt,
      JSON.stringify(mergedMeta)
    );
    const envelopeSummary = normalizeEnvelopeSummary(ssi.envelopeParse(envelopeJson));

    const saveResp = await showSaveDialog({
      title: "Exportar apresentação armazenada (Envelope JSON)",
      defaultPath: path.join(process.cwd(), `presentation_${presentationIdLocal}_${Date.now()}.env.json`),
      filters: [{ name: "Envelope JSON", extensions: ["json"] }],
      properties: ["createDirectory", "showOverwriteConfirmation"]
    });
    if (saveResp.canceled || !saveResp.filePath) {
      return {
        canceled: true,
        presentationIdLocal,
      };
    }

    fs.writeFileSync(saveResp.filePath, envelopeJson, "utf-8");

    return {
      canceled: false,
      filePath: saveResp.filePath,
      presentationIdLocal,
      senderDid: senderDidResolved,
      recipientDid: recipientResolved.recipientDid,
      recipientVerkey: recipientResolved.recipientVerkey,
      recipientVerkeySource: recipientResolved.recipientVerkeySource,
      kind,
      threadId,
      expiresAtMs: expiresAtMsOpt,
      payloadFormat: hasRevocationPackage
        ? "presentation_package_v2_revocation"
        : "presentation_package_v1",
      revocationProofSequences: revocationProofSequencesForExport.length,
      schemaIds: ids.schemaIds,
      credDefIds: ids.credDefIds,
      envelopeSummary,
      envelopeBytes: Buffer.byteLength(envelopeJson, "utf-8"),
    };
  }));

  ipcMain.handle(CH.CRED_OFFER_EXPORT_ENVELOPE, safeHandler(async (i) => {
    validateNonEmptyString(i?.issuerDid, "issuerDid");
    validateNonEmptyString(i?.recipientVerkey, "recipientVerkey");
    validateNonEmptyString(i?.credDefId, "credDefId");

    const issuerDidInput = String(i.issuerDid).trim();
    const issuerDidFromCredDef = extractIssuerDidFromCredDefId(String(i.credDefId));
    if (issuerDidFromCredDef && issuerDidInput && issuerDidInput !== issuerDidFromCredDef) {
      const e = new Error(
        `DID emissor (${issuerDidInput}) difere do DID da credDef (${issuerDidFromCredDef}).`
      );
      e.code = "ISSUER_DID_CREDDEF_MISMATCH";
      e.details = {
        issuerDidInput,
        issuerDidFromCredDef,
        credDefId: String(i.credDefId),
      };
      throw e;
    }

    const offerIdRaw = i?.offerId === undefined || i?.offerId === null ? "" : String(i.offerId).trim();

    const kindRaw = i?.kind === undefined || i?.kind === null ? "" : String(i.kind).trim();
    const kind = kindRaw || "anoncreds/credential_offer";

    const threadIdRaw = i?.threadId === undefined || i?.threadId === null ? "" : String(i.threadId).trim();
    const threadIdOpt = threadIdRaw || null;

    let expiresAtMsOpt = null;
    if (i?.expiresAtMs !== undefined && i?.expiresAtMs !== null && String(i.expiresAtMs).trim() !== "") {
      const parsed = Number(i.expiresAtMs);
      if (!Number.isFinite(parsed) || parsed <= 0) {
        const e = new Error("Campo inválido: expiresAtMs");
        e.code = "VALIDATION_ERROR";
        e.details = { field: "expiresAtMs" };
        throw e;
      }
      expiresAtMsOpt = Math.trunc(parsed);
    }

    let metaJson = null;
    if (i?.metaObj !== undefined && i?.metaObj !== null) {
      metaJson = JSON.stringify(i.metaObj);
    }

    const { offerJson, offerId } = await createCredentialOfferWithRetry(String(i.credDefId), offerIdRaw);
    const offerPlaintext = typeof offerJson === "string" ? offerJson : JSON.stringify(offerJson);
    const envelopeJson = await ssi.envelopePackAuthcrypt(
      String(i.issuerDid),
      String(i.recipientVerkey),
      kind,
      threadIdOpt,
      offerPlaintext,
      expiresAtMsOpt,
      metaJson
    );
    const offerObj = parseJsonMaybeString(offerPlaintext, null);
    const envelopeSummary = normalizeEnvelopeSummary(ssi.envelopeParse(envelopeJson));
    cacheOfferRecord({
      source: "offer_export",
      offerJson: offerPlaintext,
      offerObj,
      credDefId: String(i.credDefId),
      offerId,
      threadId: firstNonEmpty(threadIdOpt, envelopeSummary?.thread_id),
      nonce: extractNonceFromOffer(offerObj),
      createdAt: Date.now(),
    });

    let walletOfferId = null;
    let walletOfferStoreError = null;
    try {
      walletOfferId = await ssi.storeReceivedOffer(offerPlaintext);
    } catch (e) {
      walletOfferStoreError = String(e?.message || e);
    }

    const saveResp = await showSaveDialog({
      title: "Exportar oferta de credencial (Envelope JSON)",
      defaultPath: path.join(process.cwd(), `cred_offer_${Date.now()}.env.json`),
      filters: [{ name: "Envelope JSON", extensions: ["json"] }],
      properties: ["createDirectory", "showOverwriteConfirmation"]
    });

    if (saveResp.canceled || !saveResp.filePath) {
      return { canceled: true, offerId, kind };
    }

    fs.writeFileSync(saveResp.filePath, envelopeJson, "utf-8");

    const plainOfferPath = /\.env\.json$/i.test(saveResp.filePath)
      ? saveResp.filePath.replace(/\.env\.json$/i, ".json")
      : `${saveResp.filePath}.offer.json`;
    let plainOfferFilePath = null;
    try {
      if (plainOfferPath !== saveResp.filePath) {
        fs.writeFileSync(plainOfferPath, JSON.stringify(offerObj || parseJsonMaybeString(offerPlaintext, null) || {}, null, 2), "utf-8");
        plainOfferFilePath = plainOfferPath;
      }
    } catch (_) {
      plainOfferFilePath = null;
    }

    return {
      canceled: false,
      filePath: saveResp.filePath,
      plainOfferFilePath,
      offerId,
      walletOfferId,
      walletOfferStoreError,
      kind,
      threadId: threadIdOpt,
      credDefId: String(i.credDefId),
      issuerDid: String(i.issuerDid),
      recipientVerkey: String(i.recipientVerkey),
      expiresAtMs: expiresAtMsOpt,
      envelopeBytes: Buffer.byteLength(envelopeJson, "utf-8")
    };
  }));

  ipcMain.handle(CH.CRED_ACCEPT_IMPORT_OFFER_ENVELOPE, safeHandler(async (i) => {
    let offerFilePath = i?.offerFilePath ? String(i.offerFilePath).trim() : "";
    if (!offerFilePath) {
      const openResp = await showOpenDialog({
        title: "Importar oferta de credencial (Envelope JSON)",
        filters: [{ name: "Envelope JSON", extensions: ["json"] }],
        properties: ["openFile"]
      });
      if (openResp.canceled || !openResp.filePaths || !openResp.filePaths[0]) {
        return { canceled: true };
      }
      offerFilePath = openResp.filePaths[0];
    }

    const envelopeJson = fs.readFileSync(offerFilePath, "utf-8");
    const envelopeSummary = normalizeEnvelopeSummary(ssi.envelopeParse(envelopeJson));

    const resolved = await resolveReceiverDidForEnvelope(i?.holderDid, envelopeSummary);
    const offerPlain = await ssi.envelopeUnpackAuto(resolved.receiverDid, envelopeJson);
    const offerObj = parseJsonMaybeString(offerPlain, null);
    if (!offerObj) {
      const e = new Error("Offer inválida: plaintext não é JSON.");
      e.code = "INVALID_OFFER_JSON";
      throw e;
    }

    const credDefId = extractCredDefIdFromOffer(offerObj);
    if (!credDefId) {
      const e = new Error("Offer inválida: campo cred_def_id ausente.");
      e.code = "INVALID_OFFER";
      throw e;
    }
    const issuerHint = await resolveIssuerVerkeyHintForOffer(
      envelopeSummary,
      credDefId,
      resolved.receiverDid
    );

    return {
      canceled: false,
      offerFilePath,
      envelopeSummary,
      issuerVerkeyHint: issuerHint.issuerVerkey || null,
      issuerVerkeyHintSource: issuerHint.source,
      issuerDidHint: issuerHint.issuerDidHint || null,
      holderDidResolved: resolved.receiverDid,
      holderDidSource: resolved.source,
      threadId: firstNonEmpty(envelopeSummary?.thread_id, envelopeSummary?.threadId) || null,
      kind: firstNonEmpty(envelopeSummary?.kind) || null,
      credDefId,
      nonce: extractNonceFromOffer(offerObj),
      offer: offerObj
    };
  }));

  ipcMain.handle(CH.CRED_ACCEPT_EXPORT_REQUEST_ENVELOPE, safeHandler(async (i) => {
    validateNonEmptyString(i?.genesisPath, "genesisPath");

    const linkSecretId = i?.linkSecretId ? String(i.linkSecretId).trim() : "default";
    const ensureLinkSecret = i?.ensureLinkSecret === undefined ? true : !!i.ensureLinkSecret;

    let offerFilePath = i?.offerFilePath ? String(i.offerFilePath).trim() : "";
    if (!offerFilePath) {
      const openResp = await showOpenDialog({
        title: "Selecionar oferta de credencial (Envelope JSON)",
        filters: [{ name: "Envelope JSON", extensions: ["json"] }],
        properties: ["openFile"]
      });
      if (openResp.canceled || !openResp.filePaths || !openResp.filePaths[0]) {
        return { canceled: true };
      }
      offerFilePath = openResp.filePaths[0];
    }

    const envelopeJson = fs.readFileSync(offerFilePath, "utf-8");
    const envelopeSummary = normalizeEnvelopeSummary(ssi.envelopeParse(envelopeJson));
    const resolved = await resolveReceiverDidForEnvelope(i?.holderDid, envelopeSummary);
    const holderDid = resolved.receiverDid;
    const offerPlain = await ssi.envelopeUnpackAuto(holderDid, envelopeJson);
    const offerObj = parseJsonMaybeString(offerPlain, null);
    if (!offerObj) {
      const e = new Error("Offer inválida: plaintext não é JSON.");
      e.code = "INVALID_OFFER_JSON";
      throw e;
    }

    const credDefId = extractCredDefIdFromOffer(offerObj);
    if (!credDefId) {
      const e = new Error("Offer inválida: campo cred_def_id ausente.");
      e.code = "INVALID_OFFER";
      throw e;
    }

    const issuerVerkeyInput = String(i?.issuerVerkey || "").trim();
    const issuerHint = await resolveIssuerVerkeyHintForOffer(
      envelopeSummary,
      credDefId,
      holderDid
    );
    const issuerVerkeyHint = issuerHint.issuerVerkey;
    const issuerVerkey = issuerVerkeyInput || issuerVerkeyHint;
    if (!issuerVerkey) {
      const e = new Error(
        "Não foi possível identificar a verkey do emissor automaticamente. Informe issuerVerkey ou garanta que o DID emissor da credDef esteja registrado na wallet."
      );
      e.code = "MISSING_ISSUER_VERKEY";
      e.details = {
        credDefId,
        issuerDidHint: issuerHint.issuerDidHint || null,
        issuerVerkeyHintSource: issuerHint.source,
      };
      throw e;
    }

    if (ensureLinkSecret) {
      try {
        await ssi.createLinkSecret(linkSecretId);
      } catch (_) {
        // idempotente: já existente também é válido
      }
    }

    const baseName = path.basename(offerFilePath).replace(/\.env\.json$/i, "").replace(/\.json$/i, "");
    const saveResp = await showSaveDialog({
      title: "Exportar aceite de oferta (Credential Request Envelope)",
      defaultPath: path.join(path.dirname(offerFilePath), `${baseName}_request.env.json`),
      filters: [{ name: "Envelope JSON", extensions: ["json"] }],
      properties: ["createDirectory", "showOverwriteConfirmation"]
    });
    if (saveResp.canceled || !saveResp.filePath) {
      return {
        canceled: true,
        offerFilePath,
        credDefId,
      };
    }

    const resolvedCredDef = await fetchLedgerCredDefOrThrow(String(i.genesisPath), credDefId);
    const credDefJsonLedger = resolvedCredDef.credDefJsonLedger;
    const offerNonce = extractNonceFromOffer(offerObj);
    let reqJson;
    try {
      reqJson = await ssi.createCredentialRequest(
        linkSecretId,
        holderDid,
        credDefJsonLedger,
        offerPlain
      );
    } catch (reqErr) {
      if (isDuplicateEntryError(reqErr)) {
        const e = new Error(
          "Já existe um Credential Request para esta oferta (metadata duplicada). Reuse o request já exportado para esta oferta ou gere uma nova oferta."
        );
        e.code = "DUPLICATE_REQUEST_METADATA";
        e.details = {
          offerNonce: offerNonce || null,
          credDefId,
          credDefIdResolved: resolvedCredDef.credDefIdResolved,
          holderDid,
          linkSecretId,
          offerFilePath,
        };
        throw e;
      }
      throw reqErr;
    }

    const kindRaw = String(i?.kind || "").trim();
    const kind = kindRaw || "anoncreds/credential_request";

    const threadIdInput = String(i?.threadId || "").trim();
    const threadId = threadIdInput || String(envelopeSummary?.thread_id || "").trim() || null;

    const expiresAtMsOpt = parsePositiveEpochMs(i?.expiresAtMs, "expiresAtMs");
    const userMetaObj = i?.metaObj && typeof i.metaObj === "object" ? i.metaObj : null;
    const autoMetaObj = {
      requestMetadataId: offerNonce || null,
      offerNonce: offerNonce || null,
      credDefId,
      credDefIdResolved: resolvedCredDef.credDefIdResolved,
    };
    const mergedMetaObj = { ...(userMetaObj || {}), ...autoMetaObj };
    const hasMergedMeta = Object.values(mergedMetaObj).some((v) => v !== null && v !== undefined && String(v).trim() !== "");
    const metaJson = hasMergedMeta ? JSON.stringify(mergedMetaObj) : null;

    const requestEnvelopeJson = await ssi.envelopePackAuthcrypt(
      holderDid,
      issuerVerkey,
      kind,
      threadId,
      reqJson,
      expiresAtMsOpt,
      metaJson
    );

    fs.writeFileSync(saveResp.filePath, requestEnvelopeJson, "utf-8");

    return {
      canceled: false,
      offerFilePath,
      requestFilePath: saveResp.filePath,
      holderDid,
      holderDidSource: resolved.source,
      issuerVerkey,
      issuerVerkeySource: issuerVerkeyInput ? "input" : issuerHint.source,
      issuerDidHint: issuerHint.issuerDidHint || null,
      credDefId,
      credDefIdResolved: resolvedCredDef.credDefIdResolved,
      nonce: offerNonce,
      requestMetadataId: offerNonce || null,
      linkSecretId,
      kind,
      threadId,
      envelopeBytes: Buffer.byteLength(requestEnvelopeJson, "utf-8"),
      envelopeSummary,
    };
  }));

  ipcMain.handle(CH.CRED_CREATE_IMPORT_REQUEST_ENVELOPE, safeHandler(async (i) => {
    let requestFilePath = i?.requestFilePath ? String(i.requestFilePath).trim() : "";
    if (!requestFilePath) {
      const openResp = await showOpenDialog({
        title: "Importar aceite de oferta (Credential Request Envelope)",
        filters: [{ name: "Envelope JSON", extensions: ["json"] }],
        properties: ["openFile"]
      });
      if (openResp.canceled || !openResp.filePaths || !openResp.filePaths[0]) {
        return { canceled: true };
      }
      requestFilePath = openResp.filePaths[0];
    }

    const envelopeJson = fs.readFileSync(requestFilePath, "utf-8");
    const envelopeSummary = normalizeEnvelopeSummary(ssi.envelopeParse(envelopeJson));
    const resolved = await resolveReceiverDidForEnvelope(i?.issuerDid, envelopeSummary);
    const requestPlain = await ssi.envelopeUnpackAuto(resolved.receiverDid, envelopeJson);
    const requestObj = parseJsonMaybeString(requestPlain, null);
    if (!requestObj) {
      const e = new Error("Request inválido: plaintext não é JSON.");
      e.code = "INVALID_REQUEST_JSON";
      throw e;
    }

    const credDefId = extractCredDefIdFromRequest(requestObj);
    const threadId = firstNonEmpty(envelopeSummary?.thread_id, envelopeSummary?.threadId);
    const requestNonce = extractNonceFromRequest(requestObj);
    const requestMetadataFromEnvelope = extractRequestMetadataIdFromEnvelopeSummary(envelopeSummary);
    const requestMetadataHint = firstNonEmpty(requestMetadataFromEnvelope, requestNonce);
    let matchingOffer = null;
    let offerCandidates = [];
    let matchedOfferFilePath = null;
    if (credDefId) {
      try {
        matchingOffer = await resolveOfferForIssue(credDefId, threadId, requestMetadataHint);
      } catch (_) {
        matchingOffer = null;
      }
      if (!matchingOffer) {
        const companion = await resolveOfferByCompanionFiles(
          resolved.receiverDid,
          requestFilePath,
          null,
          credDefId,
          threadId,
          requestMetadataHint
        );
        matchingOffer = companion.rec;
        offerCandidates = companion.candidatesTried || [];
        matchedOfferFilePath = companion.matchedFilePath || null;
      }
    }

    const requestMetadataIdResolved = firstNonEmpty(
      requestMetadataFromEnvelope,
      matchingOffer?.nonce,
      requestNonce
    );

    return {
      canceled: false,
      requestFilePath,
      issuerDidResolved: resolved.receiverDid,
      issuerDidSource: resolved.source,
      envelopeSummary,
      kind: firstNonEmpty(envelopeSummary?.kind) || null,
      threadId: threadId || null,
      holderVerkeyHint: pickIssuerVerkeyHint(envelopeSummary),
      holderDidHint: extractHolderDidFromRequest(requestObj) || null,
      credDefId: credDefId || null,
      requestNonce: requestNonce || null,
      requestMetadataId: requestMetadataIdResolved || null,
      request: requestObj,
      offerMatched: !!matchingOffer,
      offerMatchSource: matchingOffer?.source || null,
      offerFilePathMatched: matchedOfferFilePath || matchingOffer?.matchedFilePath || null,
      offerId: matchingOffer?.offerId || null,
      offerNonce: matchingOffer?.nonce || null,
      offerCandidatesChecked: offerCandidates,
    };
  }));

  ipcMain.handle(CH.CRED_CREATE_LOAD_SCHEMA_TEMPLATE, safeHandler(async (i) => {
    validateNonEmptyString(i?.genesisPath, "genesisPath");
    validateNonEmptyString(i?.credDefId, "credDefId");

    const resolvedCredDef = await fetchLedgerCredDefOrThrow(String(i.genesisPath), String(i.credDefId));
    const schemaId = await resolveSchemaIdForCredDef(
      String(i.genesisPath),
      resolvedCredDef.credDefIdResolved,
      resolvedCredDef.credDefObj
    );

    let schemaObj = null;
    let attrNames = [];
    let attrSource = "schema";

    if (schemaId) {
      try {
        const schemaRaw = await ssi.fetchSchemaFromLedger(String(i.genesisPath), schemaId);
        schemaObj = unwrapLedgerPayload(schemaRaw);
        if (!schemaObj || typeof schemaObj !== "object") {
          const e = new Error("Schema inválido no ledger: JSON não parseável.");
          e.code = "INVALID_SCHEMA_LEDGER_JSON";
          e.details = { schemaId: String(schemaId), rawType: typeof schemaRaw };
          throw e;
        }
        attrNames = extractSchemaAttrNames(schemaObj);
      } catch (schemaErr) {
        attrNames = extractCredDefAttrNames(resolvedCredDef.credDefObj);
        attrSource = "creddef_primary_r";
        if (!attrNames.length) throw schemaErr;
      }
    } else {
      attrNames = extractCredDefAttrNames(resolvedCredDef.credDefObj);
      attrSource = "creddef_primary_r";
      if (!attrNames.length) {
        const e = new Error("Não foi possível obter schema_id a partir da CredDef.");
        e.code = "MISSING_SCHEMA_ID";
        e.details = {
          credDefId: String(i.credDefId),
          credDefIdResolved: resolvedCredDef.credDefIdResolved,
        };
        throw e;
      }
    }

    if (!attrNames.length) {
      const fallbackAttrs = extractCredDefAttrNames(resolvedCredDef.credDefObj);
      if (fallbackAttrs.length) {
        attrNames = fallbackAttrs;
        attrSource = "creddef_primary_r";
      }
    }
    const valuesTemplate = {};
    attrNames.forEach((a) => { valuesTemplate[a] = ""; });

    return {
      credDefId: String(i.credDefId),
      credDefIdResolved: resolvedCredDef.credDefIdResolved,
      credDefAliasUsed: resolvedCredDef.aliasUsed,
      schemaId: schemaId || null,
      attrSource,
      attrNames,
      valuesTemplate,
      credDef: resolvedCredDef.credDefObj,
      schema: schemaObj || null,
    };
  }));

  ipcMain.handle(CH.CRED_CREATE_EXPORT_CREDENTIAL_ENVELOPE, safeHandler(async (i) => {
    let requestFilePath = i?.requestFilePath ? String(i.requestFilePath).trim() : "";
    if (!requestFilePath) {
      const openResp = await showOpenDialog({
        title: "Selecionar aceite de oferta (Credential Request Envelope)",
        filters: [{ name: "Envelope JSON", extensions: ["json"] }],
        properties: ["openFile"]
      });
      if (openResp.canceled || !openResp.filePaths || !openResp.filePaths[0]) {
        return { canceled: true };
      }
      requestFilePath = openResp.filePaths[0];
    }

    const envelopeJson = fs.readFileSync(requestFilePath, "utf-8");
    const envelopeSummary = normalizeEnvelopeSummary(ssi.envelopeParse(envelopeJson));
    const resolved = await resolveReceiverDidForEnvelope(i?.issuerDid, envelopeSummary);
    const issuerDid = resolved.receiverDid;

    const requestPlain = await ssi.envelopeUnpackAuto(issuerDid, envelopeJson);
    const requestObj = parseJsonMaybeString(requestPlain, null);
    if (!requestObj) {
      const e = new Error("Request inválido: plaintext não é JSON.");
      e.code = "INVALID_REQUEST_JSON";
      throw e;
    }

    const credDefId = firstNonEmpty(i?.credDefId, extractCredDefIdFromRequest(requestObj));
    if (!credDefId) {
      const e = new Error("Request inválido: campo cred_def_id ausente.");
      e.code = "MISSING_CREDDEF_ID";
      throw e;
    }

    const requestNonce = extractNonceFromRequest(requestObj);
    const requestMetadataFromEnvelope = extractRequestMetadataIdFromEnvelopeSummary(envelopeSummary);
    const requestMetadataHint = firstNonEmpty(requestMetadataFromEnvelope, requestNonce);
    const threadIdFromRequest = firstNonEmpty(envelopeSummary?.thread_id, envelopeSummary?.threadId);

    let offerRec = null;
    let offerCandidatesTried = [];
    const offerJsonInput = i?.offerJson;
    if (typeof offerJsonInput === "string" && offerJsonInput.trim()) {
      offerRec = normalizeOfferCacheRecord({ source: "input", offerJson: offerJsonInput, credDefId, threadId: threadIdFromRequest });
    } else if (offerJsonInput && typeof offerJsonInput === "object") {
      offerRec = normalizeOfferCacheRecord({ source: "input", offerObj: offerJsonInput, credDefId, threadId: threadIdFromRequest });
    }
    let offerResolveErr = null;
    const explicitOfferFilePath = String(i?.offerFilePath || "").trim();
    if (!offerRec && explicitOfferFilePath) {
      const companion = await resolveOfferByCompanionFiles(
        issuerDid,
        requestFilePath,
        explicitOfferFilePath,
        credDefId,
        threadIdFromRequest,
        requestMetadataHint
      );
      offerRec = companion.rec;
      offerCandidatesTried = companion.candidatesTried || [];
    }
    if (!offerRec) {
      try {
        offerRec = await resolveOfferForIssue(credDefId, threadIdFromRequest, requestMetadataHint);
      } catch (e) {
        offerResolveErr = e;
      }
    }
    if (!offerRec) {
      const companion = await resolveOfferByCompanionFiles(
        issuerDid,
        requestFilePath,
        explicitOfferFilePath,
        credDefId,
        threadIdFromRequest,
        requestMetadataHint
      );
      offerRec = companion.rec;
      offerCandidatesTried = companion.candidatesTried || [];
    }
    if (!offerRec) {
      if (offerResolveErr) {
        if (!offerResolveErr.details || typeof offerResolveErr.details !== "object") {
          offerResolveErr.details = {};
        }
        offerResolveErr.details.offerCandidatesChecked = offerCandidatesTried;
        throw offerResolveErr;
      }
      const e = new Error(
        "Não foi possível localizar a oferta correspondente para o request (wallet/cache/arquivo)."
      );
      e.code = "OFFER_NOT_FOUND_FOR_REQUEST";
      e.details = {
        credDefId,
        threadId: threadIdFromRequest || null,
        offerNonce: requestNonce || null,
        offerCandidatesChecked: offerCandidatesTried,
      };
      throw e;
    }

    let valuesObj = null;
    if (i?.valuesObj && typeof i.valuesObj === "object") {
      valuesObj = i.valuesObj;
    } else if (typeof i?.valuesJson === "string" && i.valuesJson.trim()) {
      valuesObj = parseJsonMaybeString(i.valuesJson, null);
    }
    if (!valuesObj || typeof valuesObj !== "object" || Array.isArray(valuesObj)) {
      const e = new Error("Informe os valores da credencial em JSON objeto.");
      e.code = "INVALID_CREDENTIAL_VALUES";
      throw e;
    }
    const valuesJson = JSON.stringify(valuesObj);

    const credentialJson = await ssi.createCredential(
      credDefId,
      offerRec.offerJson,
      requestPlain,
      valuesJson
    );

    const holderVerkey = firstNonEmpty(
      i?.holderVerkey,
      pickIssuerVerkeyHint(envelopeSummary)
    );
    if (!holderVerkey) {
      const e = new Error("Não foi possível identificar a verkey do holder. Informe holderVerkey.");
      e.code = "MISSING_HOLDER_VERKEY";
      throw e;
    }

    const kind = firstNonEmpty(i?.kind, "anoncreds/credential");
    const threadId = firstNonEmpty(i?.threadId, threadIdFromRequest, offerRec?.threadId) || null;
    const expiresAtMsOpt = parsePositiveEpochMs(i?.expiresAtMs, "expiresAtMs");
    const requestMetadataIdResolved = firstNonEmpty(
      i?.requestMetadataId,
      requestMetadataFromEnvelope,
      offerRec?.nonce,
      requestNonce
    );
    const userMetaObj = i?.metaObj && typeof i.metaObj === "object" ? i.metaObj : null;
    const autoMetaObj = {
      requestMetadataId: requestMetadataIdResolved || null,
      offerNonce: offerRec?.nonce || null,
      requestNonce: requestNonce || null,
      credDefId,
    };
    const mergedMetaObj = { ...(userMetaObj || {}), ...autoMetaObj };
    const hasMergedMeta = Object.values(mergedMetaObj).some((v) => v !== null && v !== undefined && String(v).trim() !== "");
    const metaJson = hasMergedMeta ? JSON.stringify(mergedMetaObj) : null;

    const credentialEnvelopeJson = await ssi.envelopePackAuthcrypt(
      issuerDid,
      holderVerkey,
      kind,
      threadId,
      credentialJson,
      expiresAtMsOpt,
      metaJson
    );

    const baseName = path.basename(requestFilePath).replace(/\.env\.json$/i, "").replace(/\.json$/i, "");
    const saveResp = await showSaveDialog({
      title: "Exportar credencial (Envelope para Holder)",
      defaultPath: path.join(path.dirname(requestFilePath), `${baseName}_credential.env.json`),
      filters: [{ name: "Envelope JSON", extensions: ["json"] }],
      properties: ["createDirectory", "showOverwriteConfirmation"]
    });
    if (saveResp.canceled || !saveResp.filePath) {
      return {
        canceled: true,
        requestFilePath,
        credDefId,
      };
    }

    fs.writeFileSync(saveResp.filePath, credentialEnvelopeJson, "utf-8");

    return {
      canceled: false,
      requestFilePath,
      credentialFilePath: saveResp.filePath,
      issuerDid,
      issuerDidSource: resolved.source,
      holderVerkey,
      credDefId,
      requestNonce: requestNonce || null,
      threadId,
      kind,
      offerSource: offerRec?.source || null,
      offerId: offerRec?.offerId || null,
      offerNonce: offerRec?.nonce || null,
      requestMetadataId: requestMetadataIdResolved || null,
      envelopeBytes: Buffer.byteLength(credentialEnvelopeJson, "utf-8"),
      envelopeSummary,
    };
  }));

  ipcMain.handle(CH.CRED_CREATE_REVOCABLE_SETUP_K_VECTOR, safeHandler(async (i) => {
    validateNonEmptyString(i?.issuerDid, "issuerDid");
    if (String(i?.genesisPath || "").trim()) {
      const setup = await readRevocationSetupFromLedger(String(i.genesisPath), String(i.issuerDid));
      if (setup?.activeKAnchor?.k_vector_id) {
        return {
          ok: true,
          reusedFromLedger: true,
          k_vector: setup.activeKVector || {
            k_vector_id: setup.activeKAnchor.k_vector_id,
            vector_hash: firstNonEmpty(setup.activeKAnchor?.vector_hash),
          },
          ledger_anchor: setup.activeKAnchor,
          manifest: setup.manifest || null,
        };
      }
    }
    const raw = await ssi.revocationSetupCreateK(i.issuerDid, null, null);
    const parsed = parseJsonMaybeString(raw, raw);
    return unwrapLedgerPayload(parsed);
  }));

  ipcMain.handle(CH.CRED_CREATE_REVOCABLE_WRITE_K_VECTOR_ON_LEDGER, safeHandler(async (i) => {
    validateNonEmptyString(i?.genesisPath, "genesisPath");
    validateNonEmptyString(i?.issuerDid, "issuerDid");

    const kVectorInput = i?.kVectorObj ?? i?.kVectorJson ?? null;
    const kVectorObj = parseJsonMaybeString(kVectorInput, null);
    if (!kVectorObj || typeof kVectorObj !== "object" || Array.isArray(kVectorObj)) {
      const e = new Error("Gere o vetor K antes de publicar no ledger.");
      e.code = "MISSING_K_VECTOR";
      throw e;
    }

    const existingSetup = await readRevocationSetupFromLedger(String(i.genesisPath), String(i.issuerDid));
    const existingAnchor = existingSetup?.activeKAnchor || null;
    const existingVector = existingSetup?.activeKVector || null;
    const requestedKVectorId = firstNonEmpty(kVectorObj?.k_vector_id, kVectorObj?.kVectorId);
    const requestedVectorHash = firstNonEmpty(kVectorObj?.vector_hash, kVectorObj?.vectorHash);
    const existingKVectorId = firstNonEmpty(existingAnchor?.k_vector_id, existingVector?.k_vector_id);
    const existingVectorHash = firstNonEmpty(existingAnchor?.vector_hash, existingVector?.vector_hash);

    if (existingKVectorId) {
      const sameKById = requestedKVectorId && existingKVectorId === requestedKVectorId;
      const sameKByHash = requestedVectorHash && existingVectorHash && existingVectorHash === requestedVectorHash;
      if (sameKById || sameKByHash) {
        return {
          ok: true,
          reusedExisting: true,
          k_vector: existingVector || kVectorObj,
          ledger_anchor: existingAnchor,
          manifest: existingSetup?.manifest || null,
        };
      }

      const e = new Error(
        `Já existe um vetor K ativo para este emissor nesta rede: ${existingKVectorId}. Reutilize o K atual em vez de registrar outro.`
      );
      e.code = "REVOCATION_K_ALREADY_EXISTS";
      e.details = {
        issuerDid: String(i.issuerDid),
        existingKVectorId,
        requestedKVectorId: requestedKVectorId || null,
      };
      throw e;
    }

    const raw = await ssi.revocationWriteKVectorOnLedger(
      i.genesisPath,
      i.issuerDid,
      JSON.stringify(kVectorObj),
      null
    );
    const parsed = parseJsonMaybeString(raw, raw);
    return unwrapLedgerPayload(parsed);
  }));

  ipcMain.handle(CH.CRED_CREATE_REVOCABLE_ANCHOR_MANIFEST_ON_LEDGER, safeHandler(async (i) => {
    validateNonEmptyString(i?.genesisPath, "genesisPath");
    validateNonEmptyString(i?.issuerDid, "issuerDid");
    validateNonEmptyString(i?.manifestUrl, "manifestUrl");
    return writeLatestManifestAnchorToLedger(
      String(i.genesisPath).trim(),
      String(i.issuerDid).trim(),
      String(i.manifestUrl).trim(),
      firstNonEmpty(i?.manifestVersion, "1")
    );
  }));

  ipcMain.handle(CH.CRED_CREATE_REVOCABLE_CHECK_MANIFEST_ON_LEDGER, safeHandler(async (i) => {
    validateNonEmptyString(i?.genesisPath, "genesisPath");
    validateNonEmptyString(i?.issuerDid, "issuerDid");
    validateNonEmptyString(i?.manifestUrl, "manifestUrl");
    return checkManifestAnchorStatus(
      String(i.genesisPath).trim(),
      String(i.issuerDid).trim(),
      String(i.manifestUrl).trim(),
      firstNonEmpty(i?.manifestVersion, "1")
    );
  }));

  ipcMain.handle(CH.CRED_CREATE_REVOCABLE_READ_LEDGER_SETUP, safeHandler(async (i) => {
    validateNonEmptyString(i?.genesisPath, "genesisPath");
    validateNonEmptyString(i?.issuerDid, "issuerDid");
    return readRevocationSetupFromLedger(String(i.genesisPath), String(i.issuerDid));
  }));

  ipcMain.handle(CH.CRED_CREATE_EXPORT_REVOCABLE_CREDENTIAL_ENVELOPE, safeHandler(async (i) => {
    validateNonEmptyString(i?.genesisPath, "genesisPath");

    let requestFilePath = i?.requestFilePath ? String(i.requestFilePath).trim() : "";
    if (!requestFilePath) {
      const openResp = await showOpenDialog({
        title: "Selecionar aceite de oferta (Credential Request Envelope)",
        filters: [{ name: "Envelope JSON", extensions: ["json"] }],
        properties: ["openFile"]
      });
      if (openResp.canceled || !openResp.filePaths || !openResp.filePaths[0]) {
        return { canceled: true };
      }
      requestFilePath = openResp.filePaths[0];
    }

    const envelopeJson = fs.readFileSync(requestFilePath, "utf-8");
    const envelopeSummary = normalizeEnvelopeSummary(ssi.envelopeParse(envelopeJson));
    const resolved = await resolveReceiverDidForEnvelope(i?.issuerDid, envelopeSummary);
    const issuerDid = resolved.receiverDid;

    const requestPlain = await ssi.envelopeUnpackAuto(issuerDid, envelopeJson);
    const requestObj = parseJsonMaybeString(requestPlain, null);
    if (!requestObj) {
      const e = new Error("Request inválido: plaintext não é JSON.");
      e.code = "INVALID_REQUEST_JSON";
      throw e;
    }

    const credDefId = firstNonEmpty(i?.credDefId, extractCredDefIdFromRequest(requestObj));
    if (!credDefId) {
      const e = new Error("Request inválido: campo cred_def_id ausente.");
      e.code = "MISSING_CREDDEF_ID";
      throw e;
    }

    const requestNonce = extractNonceFromRequest(requestObj);
    const requestMetadataFromEnvelope = extractRequestMetadataIdFromEnvelopeSummary(envelopeSummary);
    const requestMetadataHint = firstNonEmpty(requestMetadataFromEnvelope, requestNonce);
    const threadIdFromRequest = firstNonEmpty(envelopeSummary?.thread_id, envelopeSummary?.threadId);

    let offerRec = null;
    let offerCandidatesTried = [];
    const offerJsonInput = i?.offerJson;
    if (typeof offerJsonInput === "string" && offerJsonInput.trim()) {
      offerRec = normalizeOfferCacheRecord({ source: "input", offerJson: offerJsonInput, credDefId, threadId: threadIdFromRequest });
    } else if (offerJsonInput && typeof offerJsonInput === "object") {
      offerRec = normalizeOfferCacheRecord({ source: "input", offerObj: offerJsonInput, credDefId, threadId: threadIdFromRequest });
    }
    let offerResolveErr = null;
    const explicitOfferFilePath = String(i?.offerFilePath || "").trim();
    if (!offerRec && explicitOfferFilePath) {
      const companion = await resolveOfferByCompanionFiles(
        issuerDid,
        requestFilePath,
        explicitOfferFilePath,
        credDefId,
        threadIdFromRequest,
        requestMetadataHint
      );
      offerRec = companion.rec;
      offerCandidatesTried = companion.candidatesTried || [];
    }
    if (!offerRec) {
      try {
        offerRec = await resolveOfferForIssue(credDefId, threadIdFromRequest, requestMetadataHint);
      } catch (e) {
        offerResolveErr = e;
      }
    }
    if (!offerRec) {
      const companion = await resolveOfferByCompanionFiles(
        issuerDid,
        requestFilePath,
        explicitOfferFilePath,
        credDefId,
        threadIdFromRequest,
        requestMetadataHint
      );
      offerRec = companion.rec;
      offerCandidatesTried = companion.candidatesTried || [];
    }
    if (!offerRec) {
      if (offerResolveErr) {
        if (!offerResolveErr.details || typeof offerResolveErr.details !== "object") {
          offerResolveErr.details = {};
        }
        offerResolveErr.details.offerCandidatesChecked = offerCandidatesTried;
        throw offerResolveErr;
      }
      const e = new Error(
        "Não foi possível localizar a oferta correspondente para o request (wallet/cache/arquivo)."
      );
      e.code = "OFFER_NOT_FOUND_FOR_REQUEST";
      e.details = {
        credDefId,
        threadId: threadIdFromRequest || null,
        offerNonce: requestNonce || null,
        offerCandidatesChecked: offerCandidatesTried,
      };
      throw e;
    }

    let valuesObj = null;
    if (i?.valuesObj && typeof i.valuesObj === "object") {
      valuesObj = i.valuesObj;
    } else if (typeof i?.valuesJson === "string" && i.valuesJson.trim()) {
      valuesObj = parseJsonMaybeString(i.valuesJson, null);
    }
    if (!valuesObj || typeof valuesObj !== "object" || Array.isArray(valuesObj)) {
      const e = new Error("Informe os valores da credencial em JSON objeto.");
      e.code = "INVALID_CREDENTIAL_VALUES";
      throw e;
    }
    const sanitizedValues = sanitizeRevocableCredentialValues(valuesObj);

    const resolvedCredDef = await fetchLedgerCredDefOrThrow(String(i.genesisPath), credDefId);
    const credDefJsonLedger = resolvedCredDef.credDefJsonLedger;
    const schemaId = await resolveSchemaIdForCredDef(
      String(i.genesisPath),
      resolvedCredDef.credDefIdResolved,
      resolvedCredDef.credDefObj
    );
    if (!schemaId) {
      const e = new Error("Não foi possível obter schema_id a partir da CredDef.");
      e.code = "SCHEMA_ID_NOT_RESOLVED";
      e.details = {
        credDefId,
        credDefIdResolved: resolvedCredDef.credDefIdResolved,
      };
      throw e;
    }

    const unitOfTime = String(i?.unitOfTime || "").trim();
    if (!unitOfTime) {
      const e = new Error("Campo obrigatório: unitOfTime");
      e.code = "VALIDATION_ERROR";
      throw e;
    }
    const timeWindow = parsePositiveEpochSeconds(i?.timeWindow, "timeWindow");
    const hasStartTimeEpoch = !(i?.startTime === undefined || i?.startTime === null || String(i?.startTime).trim() === "");
    const hasStartDate = String(i?.startDate || "").trim();
    const hasStartTimeText = String(i?.startTimeText || "").trim();
    const startTime = hasStartTimeEpoch
      ? parsePositiveEpochSeconds(i?.startTime, "startTime")
      : (hasStartDate && hasStartTimeText)
        ? parsePtBrDateTimeToLocalEpochSeconds(i?.startDate, i?.startTimeText, "startDate", "startTimeText")
        : hasStartDate
          ? parsePtBrDateToUtcEpochSeconds(i?.startDate, "startDate")
          : parsePositiveEpochSeconds(i?.startTime, "startTime");
    const validityEnd = (i?.validityEnd === undefined || i?.validityEnd === null || String(i?.validityEnd).trim() === "")
      ? computeSingleWindowValidityEnd(startTime, unitOfTime, timeWindow)
      : parsePositiveEpochSeconds(i?.validityEnd, "validityEnd");
    if (validityEnd <= startTime) {
      const e = new Error("validityEnd deve ser maior que startTime.");
      e.code = "VALIDATION_ERROR";
      throw e;
    }

    const manifestInput = i?.manifestObj ?? i?.manifestJson ?? null;
    let manifestObj = manifestInput === null || manifestInput === undefined || manifestInput === ""
      ? null
      : parseJsonMaybeString(manifestInput, null);
    if (manifestInput && (!manifestObj || typeof manifestObj !== "object" || Array.isArray(manifestObj))) {
      const e = new Error("Manifest JSON inválido.");
      e.code = "INVALID_MANIFEST_JSON";
      throw e;
    }
    let kVectorId = firstNonEmpty(
      i?.kVectorId,
      i?.kLedgerAnchor?.k_vector_id,
      i?.kLedgerAnchorObj?.k_vector_id
    );
    let ledgerSetup = null;
    if (!manifestObj || !kVectorId) {
      ledgerSetup = await readRevocationSetupFromLedger(String(i.genesisPath), issuerDid);
      if (!manifestObj) manifestObj = ledgerSetup?.manifest || null;
      if (!kVectorId) kVectorId = firstNonEmpty(ledgerSetup?.activeKAnchor?.k_vector_id);
    }
    if (!manifestObj || !kVectorId) {
      const e = new Error(
        "Setup de revogação incompleto. Publique o vetor K e ancore o manifesto no ledger antes de emitir."
      );
      e.code = "REVOCATION_SETUP_INCOMPLETE";
      e.details = {
        issuerDid,
        hasManifest: !!manifestObj,
        hasKVectorId: !!kVectorId,
        activeKAttrKey: REVOCATION_ACTIVE_K_ATTR_KEY,
        manifestAttrKey: REVOCATION_MANIFEST_ATTR_KEY,
      };
      throw e;
    }

    const sanitizedThread = firstNonEmpty(threadIdFromRequest, requestNonce, Date.now()).replace(/[^a-zA-Z0-9._-]/g, "_");
    const issuerLocalCredentialId = String(
      firstNonEmpty(i?.issuerLocalCredentialId, i?.credentialIdLocal, `issued-revocable-${sanitizedThread}`)
    ).trim();
    const holderDidHint = firstNonEmpty(i?.holderDidHint, i?.holderDid);
    const normalizedOfferJson = normalizeOfferJsonForRevocableIssue(
      offerRec.offerJson,
      credDefId,
      schemaId
    );
    const normalizedOfferObj = parseJsonMaybeString(normalizedOfferJson, null);
    if (!looksLikeAnoncredsOfferObject(normalizedOfferObj)) {
      const e = new Error(
        "Oferta incompatível para emissão revogável. Reimporte a oferta original do emissor e tente novamente."
      );
      e.code = "INVALID_ISSUE_OFFER_JSON";
      e.details = {
        credDefId,
        offerSource: offerRec?.source || null,
        offerFilePath: explicitOfferFilePath || null,
        hasKeyCorrectnessProof: !!(normalizedOfferObj?.key_correctness_proof || normalizedOfferObj?.keyCorrectnessProof),
        topLevelKeys: normalizedOfferObj && typeof normalizedOfferObj === "object" ? Object.keys(normalizedOfferObj) : [],
      };
      throw e;
    }
    const issuePackageJson = await ssi.issueRevocableCredential(
      String(i.genesisPath),
      issuerLocalCredentialId,
      holderDidHint || null,
      credDefId,
      schemaId,
      normalizedOfferJson,
      requestPlain,
      JSON.stringify(sanitizedValues.sanitized),
      startTime,
      validityEnd,
      unitOfTime,
      timeWindow,
      10,
      manifestObj ? JSON.stringify(manifestObj) : null,
      kVectorId,
      null
    );
    const issuePackage = parseJsonMaybeString(issuePackageJson, null);
    if (!issuePackage || typeof issuePackage !== "object") {
      const e = new Error("Pacote revogável inválido retornado pelo addon nativo.");
      e.code = "INVALID_REVOCABLE_PACKAGE";
      throw e;
    }

    const holderVerkey = firstNonEmpty(
      i?.holderVerkey,
      pickIssuerVerkeyHint(envelopeSummary)
    );
    if (!holderVerkey) {
      const e = new Error("Não foi possível identificar a verkey do holder. Informe holderVerkey.");
      e.code = "MISSING_HOLDER_VERKEY";
      throw e;
    }

    const kind = firstNonEmpty(i?.kind, "anoncreds/revocable-credential-package-v2");
    const threadId = firstNonEmpty(i?.threadId, threadIdFromRequest, offerRec?.threadId) || null;
    const expiresAtMsOpt = parsePositiveEpochMs(i?.expiresAtMs, "expiresAtMs");
    const requestMetadataIdResolved = firstNonEmpty(
      i?.requestMetadataId,
      requestMetadataFromEnvelope,
      offerRec?.nonce,
      requestNonce
    );
    const userMetaObj = i?.metaObj && typeof i.metaObj === "object" ? i.metaObj : null;
    const controlValues = issuePackage?.control_values && typeof issuePackage.control_values === "object"
      ? issuePackage.control_values
      : null;
    const autoMetaObj = {
      requestMetadataId: requestMetadataIdResolved || null,
      offerNonce: offerRec?.nonce || null,
      requestNonce: requestNonce || null,
      credDefId,
      credDefIdResolved: resolvedCredDef.credDefIdResolved,
      schemaId,
      kVectorId,
      revocable: true,
      confirmationWindowCount: controlValues?.confirmation_window_count ?? 10,
      manifestUrl: manifestObj?.manifest_url || null,
    };
    const mergedMetaObj = { ...(userMetaObj || {}), ...autoMetaObj };
    const hasMergedMeta = Object.values(mergedMetaObj).some((v) => v !== null && v !== undefined && String(v).trim() !== "");
    const metaJson = hasMergedMeta ? JSON.stringify(mergedMetaObj) : null;

    const credentialEnvelopeJson = await ssi.envelopePackAuthcrypt(
      issuerDid,
      holderVerkey,
      kind,
      threadId,
      issuePackageJson,
      expiresAtMsOpt,
      metaJson
    );

    const baseName = path.basename(requestFilePath).replace(/\.env\.json$/i, "").replace(/\.json$/i, "");
    const saveResp = await showSaveDialog({
      title: "Exportar credencial revogável (Envelope para Holder)",
      defaultPath: path.join(path.dirname(requestFilePath), `${baseName}_revocable_credential.env.json`),
      filters: [{ name: "Envelope JSON", extensions: ["json"] }],
      properties: ["createDirectory", "showOverwriteConfirmation"]
    });
    if (saveResp.canceled || !saveResp.filePath) {
      return {
        canceled: true,
        requestFilePath,
        credDefId,
        credDefIdResolved: resolvedCredDef.credDefIdResolved,
        kVectorId,
      };
    }

    fs.writeFileSync(saveResp.filePath, credentialEnvelopeJson, "utf-8");

    return {
      canceled: false,
      requestFilePath,
      credentialFilePath: saveResp.filePath,
      issuerDid,
      issuerDidSource: resolved.source,
      holderVerkey,
      holderDidHint: holderDidHint || null,
      credDefId,
      credDefIdResolved: resolvedCredDef.credDefIdResolved,
      schemaId,
      kVectorId,
      issuerLocalCredentialId,
      requestNonce: requestNonce || null,
      threadId,
      kind,
      offerSource: offerRec?.source || null,
      offerId: offerRec?.offerId || null,
      offerNonce: offerRec?.nonce || null,
      normalizedOffer: normalizedOfferObj,
      requestMetadataId: requestMetadataIdResolved || null,
      envelopeBytes: Buffer.byteLength(credentialEnvelopeJson, "utf-8"),
      controlValues,
      issuerRecord: issuePackage?.issuer_record || null,
      issuerRecordSummary: issuePackage?.issuer_record
        ? {
          issuerLocalCredentialId: issuePackage?.issuer_record?.issuer_local_credential_id || issuerLocalCredentialId,
          credDefId: issuePackage?.issuer_record?.cred_def_id || credDefId,
          status: issuePackage?.issuer_record?.status || null,
          createdAt: issuePackage?.issuer_record?.created_at || null,
        }
        : null,
      removedControlAttributes: sanitizedValues.removedKeys,
      holderBundleSummary: issuePackage?.holder_bundle?.vectors_summary || null,
      manifest: manifestObj,
      ledgerSetupReady: ledgerSetup?.ready ?? true,
      envelopeSummary,
    };
  }));

  ipcMain.handle(CH.CRED_RECEIVE_PREVIEW_ENVELOPE, safeHandler(async (i) => {
    let credentialFilePath = i?.credentialFilePath ? String(i.credentialFilePath).trim() : "";
    if (!credentialFilePath) {
      const openResp = await showOpenDialog({
        title: "Selecionar credencial recebida (Credential Envelope)",
        filters: [{ name: "Envelope JSON", extensions: ["json"] }],
        properties: ["openFile"]
      });
      if (openResp.canceled || !openResp.filePaths || !openResp.filePaths[0]) {
        return { canceled: true };
      }
      credentialFilePath = openResp.filePaths[0];
    }

    const envelopeJson = fs.readFileSync(credentialFilePath, "utf-8");
    const envelopeSummary = normalizeEnvelopeSummary(ssi.envelopeParse(envelopeJson));
    const resolved = await resolveReceiverDidForEnvelope(i?.holderDid, envelopeSummary);
    const holderDid = resolved.receiverDid;
    const credentialPlain = await ssi.envelopeUnpackAuto(holderDid, envelopeJson);
    const parsedCredentialPayload = parseJsonMaybeString(credentialPlain, null);
    const revocablePackage = looksLikeRevocableCredentialPackage(parsedCredentialPayload)
      ? parsedCredentialPayload
      : null;
    const credentialObj = revocablePackage
      ? parseJsonMaybeString(revocablePackage.credential_json, null)
      : parsedCredentialPayload;
    if (!credentialObj || typeof credentialObj !== "object") {
      const e = new Error("Credencial inválida: plaintext não é JSON.");
      e.code = "INVALID_CREDENTIAL_JSON";
      throw e;
    }
    const credDefId = extractCredDefIdFromCredential(credentialObj);
    if (!credDefId) {
      const e = new Error("Credencial inválida: campo cred_def_id ausente.");
      e.code = "MISSING_CREDDEF_ID";
      throw e;
    }

    const requestMetadataIdInput = String(i?.requestMetadataId || "").trim();
    const requestMetadataIdFromCredential = firstNonEmpty(
      extractRequestMetadataIdFromCredential(credentialObj, envelopeSummary)
    );
    let requestMetadataId = requestMetadataIdInput || requestMetadataIdFromCredential;
    let requestMetadataSource = requestMetadataIdInput
      ? "input"
      : (requestMetadataIdFromCredential ? "credential_envelope" : "");
    let inferredOfferFilePath = null;
    let offerCandidatesChecked = [];

    const inferredInitial = await inferRequestMetadataFromCompanionOffer(
      holderDid,
      credentialFilePath,
      i?.offerFilePath
    );
    const inferredInitialId = firstNonEmpty(inferredInitial?.requestMetadataId);
    if (inferredInitialId) {
      const inferredInitialSource = firstNonEmpty(inferredInitial?.source, "companion_offer_file");
      inferredOfferFilePath = inferredInitial?.offerFilePath || null;
      offerCandidatesChecked = Array.isArray(inferredInitial?.candidatesChecked)
        ? inferredInitial.candidatesChecked
        : [];

      if (!requestMetadataId) {
        requestMetadataId = inferredInitialId;
        requestMetadataSource = inferredInitialSource;
      } else if (
        requestMetadataId !== inferredInitialId
        && !isWeakRequestMetadataSource(inferredInitialSource)
      ) {
        requestMetadataId = inferredInitialId;
        requestMetadataSource = inferredInitialSource;
      }
    }

    const threadId = firstNonEmpty(envelopeSummary?.thread_id, envelopeSummary?.threadId);
    const threadIdSafe = threadId.replace(/[^a-zA-Z0-9._-]/g, "_");
    const credentialIdInput = String(i?.credentialId || "").trim();
    const suggestedCredentialId = credentialIdInput
      || (threadIdSafe ? `received-credential-${threadIdSafe}` : `received-credential-${Date.now()}`);
    const credentialAttributes = extractCredentialAttributesForPreview(credentialObj);
    const credentialValuesRaw = {};
    credentialAttributes.forEach((attr) => {
      credentialValuesRaw[attr.name] = attr.value;
    });

    return {
      canceled: false,
      credentialFilePath,
      holderDid,
      holderDidSource: resolved.source,
      kind: firstNonEmpty(envelopeSummary?.kind) || null,
      threadId: threadId || null,
      credDefId,
      requestMetadataId,
      requestMetadataSource: requestMetadataSource || null,
      inferredOfferFilePath,
      offerCandidatesChecked,
      credentialId: suggestedCredentialId,
      revocable: !!revocablePackage,
      controlValues: revocablePackage?.control_values && typeof revocablePackage.control_values === "object"
        ? revocablePackage.control_values
        : null,
      credentialAttributes,
      credentialValuesRaw,
      envelopeSummary,
    };
  }));

  ipcMain.handle(CH.CRED_RECEIVE_IMPORT_AND_STORE_ENVELOPE, safeHandler(async (i) => {
    validateNonEmptyString(i?.genesisPath, "genesisPath");

    let credentialFilePath = i?.credentialFilePath ? String(i.credentialFilePath).trim() : "";
    if (!credentialFilePath) {
      const openResp = await showOpenDialog({
        title: "Selecionar credencial recebida (Credential Envelope)",
        filters: [{ name: "Envelope JSON", extensions: ["json"] }],
        properties: ["openFile"]
      });
      if (openResp.canceled || !openResp.filePaths || !openResp.filePaths[0]) {
        return { canceled: true };
      }
      credentialFilePath = openResp.filePaths[0];
    }

    const envelopeJson = fs.readFileSync(credentialFilePath, "utf-8");
    const envelopeSummary = normalizeEnvelopeSummary(ssi.envelopeParse(envelopeJson));
    const resolved = await resolveReceiverDidForEnvelope(i?.holderDid, envelopeSummary);
    const holderDid = resolved.receiverDid;
    const credentialPlain = await ssi.envelopeUnpackAuto(holderDid, envelopeJson);
    const parsedCredentialPayload = parseJsonMaybeString(credentialPlain, null);
    const revocablePackage = looksLikeRevocableCredentialPackage(parsedCredentialPayload)
      ? parsedCredentialPayload
      : null;
    const credentialObj = revocablePackage
      ? parseJsonMaybeString(revocablePackage.credential_json, null)
      : parsedCredentialPayload;
    if (!credentialObj || typeof credentialObj !== "object") {
      const e = new Error("Credencial inválida: plaintext não é JSON.");
      e.code = "INVALID_CREDENTIAL_JSON";
      throw e;
    }
    const credentialJsonForStore = revocablePackage
      ? (typeof revocablePackage.credential_json === "string"
        ? revocablePackage.credential_json
        : JSON.stringify(revocablePackage.credential_json))
      : credentialPlain;

    const credDefId = extractCredDefIdFromCredential(credentialObj);
    if (!credDefId) {
      const e = new Error("Credencial inválida: campo cred_def_id ausente.");
      e.code = "MISSING_CREDDEF_ID";
      throw e;
    }

    const credentialIdInput = String(i?.credentialId || "").trim();
    const threadIdHint = firstNonEmpty(envelopeSummary?.thread_id, envelopeSummary?.threadId);
    const threadIdSafe = threadIdHint.replace(/[^a-zA-Z0-9._-]/g, "_");
    const baseCredentialId = credentialIdInput
      || (threadIdSafe ? `received-credential-${threadIdSafe}` : `received-credential-${Date.now()}`);

    const existingCredentialId = credentialIdInput
      ? ""
      : await findMatchingStoredCredentialId(
        credentialObj,
        credDefId,
        baseCredentialId
      );

    const requestMetadataIdInput = String(i?.requestMetadataId || "").trim();
    const requestMetadataIdFromCredential = firstNonEmpty(
      extractRequestMetadataIdFromCredential(credentialObj, envelopeSummary)
    );
    let requestMetadataId = requestMetadataIdInput || requestMetadataIdFromCredential;
    let requestMetadataSource = requestMetadataIdInput
      ? "input"
      : (requestMetadataIdFromCredential ? "credential_envelope" : "");
    let inferredOfferFilePath = null;
    let offerCandidatesChecked = [];
    const requestMetadataCandidates = [];
    const requestMetadataCandidateSeen = new Set();
    const pushRequestMetadataCandidate = (id, source) => {
      const reqId = String(id || "").trim();
      if (!reqId || requestMetadataCandidateSeen.has(reqId)) return;
      requestMetadataCandidateSeen.add(reqId);
      requestMetadataCandidates.push({
        requestMetadataId: reqId,
        source: firstNonEmpty(source, "unknown"),
      });
    };

    pushRequestMetadataCandidate(requestMetadataIdInput, "input");
    pushRequestMetadataCandidate(requestMetadataIdFromCredential, "credential_envelope");

    const inferredInitial = await inferRequestMetadataFromCompanionOffer(
      holderDid,
      credentialFilePath,
      i?.offerFilePath
    );
    const inferredInitialId = firstNonEmpty(inferredInitial?.requestMetadataId);
    if (inferredInitialId) {
      const inferredInitialSource = firstNonEmpty(inferredInitial?.source, "companion_offer_file");
      pushRequestMetadataCandidate(inferredInitialId, inferredInitialSource);
      inferredOfferFilePath = inferredInitial?.offerFilePath || null;
      offerCandidatesChecked = Array.isArray(inferredInitial?.candidatesChecked)
        ? inferredInitial.candidatesChecked
        : [];

      if (!requestMetadataId) {
        requestMetadataId = inferredInitialId;
        requestMetadataSource = inferredInitialSource;
      } else if (
        requestMetadataId !== inferredInitialId
        && !isWeakRequestMetadataSource(inferredInitialSource)
      ) {
        requestMetadataId = inferredInitialId;
        requestMetadataSource = inferredInitialSource;
      }
    }
    if (!requestMetadataId) {
      if (existingCredentialId) {
        requestMetadataSource = requestMetadataSource || "credential_envelope";
      } else {
      const e = new Error(
        "Request Metadata ID ausente. Informe o nonce do request gerado no aceite da oferta."
      );
      e.code = "MISSING_REQUEST_METADATA_ID";
      e.details = {
        credentialFilePath,
        credDefId,
        threadId: firstNonEmpty(envelopeSummary?.thread_id, envelopeSummary?.threadId) || null,
        offerCandidatesChecked,
      };
      throw e;
      }
    }

    const resolvedCredDef = await fetchLedgerCredDefOrThrow(String(i.genesisPath), credDefId);
    const credDefJsonLedger = resolvedCredDef.credDefJsonLedger;

    let credentialIdStored = baseCredentialId;
    let alreadyStored = !!existingCredentialId;
    if (existingCredentialId) {
      credentialIdStored = existingCredentialId;
    } else {
      try {
        credentialIdStored = await ssi.storeCredential(
          baseCredentialId,
          credentialJsonForStore,
          requestMetadataId,
          credDefJsonLedger,
          null
        );
      } catch (storeErr) {
      const msg = String(storeErr?.message || storeErr);
      const isMissingRequestMetadata = msg.includes("Request Metadata não encontrado");
      const isDuplicate = isLikelyDuplicateError(storeErr);
      const isInvalidSignature = isInvalidSignatureProofError(storeErr);
      let recoveredWithAlternateRequestMetadata = false;

      if (isMissingRequestMetadata || isInvalidSignature) {
        const inferredRetry = await inferRequestMetadataFromCompanionOffer(
          holderDid,
          credentialFilePath,
          i?.offerFilePath
        );
        const retryRequestMetadataId = firstNonEmpty(inferredRetry?.requestMetadataId);
        if (retryRequestMetadataId) {
          const retrySource = firstNonEmpty(inferredRetry?.source, "companion_offer_file:retry");
          if (!requestMetadataCandidates.some((c) => c.requestMetadataId === retryRequestMetadataId)) {
            requestMetadataCandidates.push({
              requestMetadataId: retryRequestMetadataId,
              source: retrySource,
            });
          }
          inferredOfferFilePath = inferredRetry?.offerFilePath || inferredOfferFilePath;
          offerCandidatesChecked = Array.isArray(inferredRetry?.candidatesChecked)
            ? inferredRetry.candidatesChecked
            : offerCandidatesChecked;
        }
      }

      if (isMissingRequestMetadata || isInvalidSignature) {
        for (const candidate of requestMetadataCandidates) {
          const candidateId = firstNonEmpty(candidate?.requestMetadataId);
          if (!candidateId || candidateId === requestMetadataId) continue;
          try {
            credentialIdStored = await ssi.storeCredential(
              baseCredentialId,
              credentialJsonForStore,
              candidateId,
              credDefJsonLedger,
              null
            );
            requestMetadataId = candidateId;
            requestMetadataSource = firstNonEmpty(candidate?.source, "metadata_retry");
            recoveredWithAlternateRequestMetadata = true;
            break;
          } catch (retryErr) {
            const retryMsg = String(retryErr?.message || retryErr);
            const retryIsMissingRequestMetadata = retryMsg.includes("Request Metadata não encontrado");
            const retryIsInvalidSignature = isInvalidSignatureProofError(retryErr);
            const retryIsDuplicate = isLikelyDuplicateError(retryErr);

            if (retryIsDuplicate) {
              const retryId = credentialIdInput
                ? `${credentialIdInput}-${formatCredentialIdTimestamp()}`
                : `received-credential-${Date.now()}`;
              try {
                credentialIdStored = await ssi.storeCredential(
                  retryId,
                  credentialJsonForStore,
                  candidateId,
                  credDefJsonLedger,
                  null
                );
                requestMetadataId = candidateId;
                requestMetadataSource = firstNonEmpty(candidate?.source, "metadata_retry");
                recoveredWithAlternateRequestMetadata = true;
                break;
              } catch (retryDupErr) {
                if (isLikelyDuplicateError(retryDupErr)) continue;
                throw retryDupErr;
              }
            }

            if (retryIsMissingRequestMetadata || retryIsInvalidSignature) {
              continue;
            }
            throw retryErr;
          }
        }
      }

      if (!recoveredWithAlternateRequestMetadata && isDuplicate) {
        const retryIds = [];
        if (credentialIdInput) retryIds.push(`${credentialIdInput}-${formatCredentialIdTimestamp()}`);
        retryIds.push(`received-credential-${Date.now()}`);
        let storedAfterDuplicateRetry = false;

        for (const retryId of retryIds) {
          try {
            credentialIdStored = await ssi.storeCredential(
              retryId,
              credentialJsonForStore,
              requestMetadataId,
              credDefJsonLedger,
              null
            );
            storedAfterDuplicateRetry = true;
            break;
          } catch (retryStoreErr) {
            if (isLikelyDuplicateError(retryStoreErr)) {
              continue;
            }
            throw retryStoreErr;
          }
        }

        if (!storedAfterDuplicateRetry) {
          const existingId = await findMatchingStoredCredentialId(
            credentialObj,
            credDefId,
            credentialIdInput || baseCredentialId
          );
          if (existingId) {
            credentialIdStored = existingId;
            alreadyStored = true;
          } else {
            throw storeErr;
          }
        }
      } else if (!recoveredWithAlternateRequestMetadata) {
        throw storeErr;
      }
      }
    }

    let revocable = false;
    let bundleIdLocal = null;
    let holderBundleStored = false;
    let controlValues = null;
    let revocationBundleRecord = null;

    if (revocablePackage) {
      revocable = true;
      bundleIdLocal = `revocation-bundle-${credentialIdStored}`;
      const revStoreRaw = await ssi.storeReceivedRevocableCredential(
        bundleIdLocal,
        JSON.stringify(revocablePackage.holder_bundle),
        credentialIdStored
      );
      const revStoreObj = parseJsonMaybeString(revStoreRaw, null);
      if (revStoreObj && typeof revStoreObj === "object") {
        holderBundleStored = !!revStoreObj.ok;
        bundleIdLocal = firstNonEmpty(revStoreObj.bundle_id_local, bundleIdLocal) || bundleIdLocal;
        revocationBundleRecord = revStoreObj;
      } else {
        holderBundleStored = true;
      }
      controlValues = revocablePackage?.control_values && typeof revocablePackage.control_values === "object"
        ? revocablePackage.control_values
        : null;
    }

    return {
      canceled: false,
      credentialFilePath,
      holderDid,
      holderDidSource: resolved.source,
      kind: firstNonEmpty(envelopeSummary?.kind) || null,
      threadId: firstNonEmpty(envelopeSummary?.thread_id, envelopeSummary?.threadId) || null,
      credDefId,
      credDefIdResolved: resolvedCredDef.credDefIdResolved,
      requestMetadataId,
      requestMetadataSource: requestMetadataSource || "credential_envelope",
      inferredOfferFilePath,
      credentialId: credentialIdStored,
      alreadyStored,
      revocable,
      bundleIdLocal,
      holderBundleStored,
      controlValues,
      revocationBundleRecord,
      envelopeSummary,
    };
  }));

}


module.exports = { registerIpcHandlers };
