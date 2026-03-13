const { ipcMain, dialog, BrowserWindow } = require("electron");
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

function toJsonString(obj) {
  return obj ? JSON.stringify(obj) : "{}";
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
    const localRaw = await ssi.creddefListLocal(null, null, null, null, null);
    if (Array.isArray(localRaw)) {
      for (const it of localRaw) {
        const rec = parseCredDefLocalRecord(it);
        if (!rec || typeof rec !== "object") continue;
        const recId = firstNonEmpty(rec?.id_local, rec?.id, rec?.cred_def_id, rec?.credDefId);
        if (!recId || recId !== String(credDefId)) continue;
        const schemaId = firstNonEmpty(rec?.schema_id, rec?.schemaId);
        if (schemaId) return schemaId;
      }
    }
  } catch (_) {
    // ignora fallback local
  }

  // fallback extra: tenta catálogo local de schemas por ref/seqNo e issuer do credDefId
  const refTarget = String(byRef || "").trim();
  const issuerDid = parseIssuerDidFromCredDefId(credDefId);
  if (refTarget) {
    try {
      const schemasRaw = await ssi.schemaListLocal(null, null, null);
      if (Array.isArray(schemasRaw)) {
        for (const item of schemasRaw) {
          const rec = parseSchemaLocalRecord(item);
          if (!rec || typeof rec !== "object") continue;
          const seqNo = firstNonEmpty(rec?.seq_no, rec?.seqNo, rec?.ref, rec?.schema_ref, rec?.schemaRef);
          if (!seqNo || seqNo !== refTarget) continue;
          const recIssuer = firstNonEmpty(rec?.issuer_did, rec?.issuerDid);
          if (issuerDid && recIssuer && recIssuer !== issuerDid) continue;
          const schemaIdLocal = firstNonEmpty(rec?.id_local, rec?.id, rec?.schema_id, rec?.schemaId);
          if (schemaIdLocal) return schemaIdLocal;
        }
      }
    } catch (_) {
      // ignora fallback local de schemas
    }
  }

  return "";
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

  const offerObj = parseJsonMaybeString(recRaw.offerObj, null)
    || parseJsonMaybeString(recInput.offerObj, null)
    || parseJsonMaybeString(recInput.offerJson, null)
    || parseJsonMaybeString(recInput.offer_json, null)
    || parseJsonMaybeString(recInput.offerJsonStr, null)
    || parseJsonMaybeString(recInput.offer_json_str, null)
    || parseJsonMaybeString(recInput.offer, null)
    || parseJsonMaybeString(recInput.json, null)
    || parseJsonMaybeString(recInput.record_json, null)
    || parseJsonMaybeString(recInput.value, null);
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

  pushCandidate(offerFilePathOpt);

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
    pushCandidate(path.join(reqDir, `${b}.env.json`));
    pushCandidate(path.join(reqDir, `${b}.json`));
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
    const withSource = { ...rec, source: `${sourceLabel}:${path.basename(p)}` };
    cacheOfferRecord(withSource);
    return withSource;
  };

  try {
    const envelopeJson = fs.readFileSync(p, "utf-8");
    const envelopeSummary = normalizeEnvelopeSummary(ssi.envelopeParse(envelopeJson));
    const envelopeKind = firstNonEmpty(envelopeSummary?.kind).toLowerCase();
    if (envelopeKind && !envelopeKind.includes("offer")) return null;
    const offerPlain = await ssi.envelopeUnpackAuto(String(issuerDid), envelopeJson);
    const offerObj = parseJsonMaybeString(offerPlain, null);
    if (!offerObj) return null;

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

    const withSource = { ...rec, source: `offer_file:${path.basename(p)}` };
    cacheOfferRecord(withSource);
    return withSource;
  } catch (_) {
    // fallback: arquivo sidecar com oferta em JSON puro (sem envelope)
    try {
      const raw = fs.readFileSync(p, "utf-8");
      const plainObj = parseJsonMaybeString(raw, null);
      return buildRecFromPlainOffer(plainObj, "offer_plain_file");
    } catch (_) {
      return null;
    }
  }
}

async function resolveOfferByCompanionFiles(issuerDid, requestFilePath, offerFilePathOpt, credDefId, threadId, offerNonce) {
  const candidates = buildOfferEnvelopeCandidates(requestFilePath, offerFilePathOpt);
  for (const p of candidates) {
    const rec = await resolveOfferFromEnvelopeFile(issuerDid, p, credDefId, threadId, offerNonce);
    if (rec) {
      return { rec, candidatesTried: candidates };
    }
  }
  return { rec: null, candidatesTried: candidates };
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
    if (foundById) return preferred;
  }

  const byCredDef = targetCredDefId
    ? records.filter((r) => firstNonEmpty(r?.cred_def_id, r?.credDefId) === targetCredDefId)
    : records;

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

    if (!credentialId || !schemaId || !credDefId || !attributes.length) continue;

    for (const attrRaw of attributes) {
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
      const credDefRaw = await ssi.fetchCredDefFromLedger(genesisPath, credDefId);
      const credDefObj = unwrapLedgerPayload(credDefRaw);
      if (!credDefObj || typeof credDefObj !== "object") {
        const e = new Error(`CredDef inválida no ledger: ${credDefId}`);
        e.code = "INVALID_CREDDEF_LEDGER_JSON";
        e.details = { credDefId };
        throw e;
      }
      credDefsMap[credDefId] = credDefObj;
    }

    const presentationRequestJson = JSON.stringify(artifacts.presentationRequest);
    const requestedCredentialsJson = JSON.stringify(artifacts.requestedCredentials);
    const schemasJson = JSON.stringify(schemasMap);
    const credDefsJson = JSON.stringify(credDefsMap);

    const presentationJson = await ssi.createPresentation(
      presentationRequestJson,
      requestedCredentialsJson,
      schemasJson,
      credDefsJson
    );
    const presentationObj = parseJsonMaybeString(presentationJson, null);
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
      payload_format: "presentation_package_v1",
    };
    const metaObj = { ...(inputMeta || {}), ...autoMeta };
    const metaJson = JSON.stringify(metaObj);

    const presentationPayload = {
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
      payloadFormat: "presentation_package_v1",
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

    if (parsedPlain && typeof parsedPlain === "object" && !Array.isArray(parsedPlain)) {
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
        embeddedPresentation
        && looksLikePresentationObject(embeddedPresentation)
        && looksLikePresentationRequestObject(embeddedRequest)
      ) {
        presentationObj = embeddedPresentation;
        presentationRequestObj = embeddedRequest;
        payloadFormat = "presentation_package_v1";
        requestSource = "envelope_payload";
      } else if (looksLikePresentationObject(parsedPlain)) {
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
      const credDefRaw = await ssi.fetchCredDefFromLedger(String(i.genesisPath), credDefId);
      const credDefObj = unwrapLedgerPayload(credDefRaw);
      if (!credDefObj || typeof credDefObj !== "object") {
        const e = new Error(`CredDef inválida no ledger: ${credDefId}`);
        e.code = "INVALID_CREDDEF_LEDGER_JSON";
        e.details = { credDefId };
        throw e;
      }
      credDefsMap[credDefId] = credDefObj;
    }

    const verifyRaw = await ssi.verifyPresentation(
      JSON.stringify(presentationRequestObj),
      JSON.stringify(presentationObj),
      JSON.stringify(schemasMap),
      JSON.stringify(credDefsMap)
    );
    const verifyText = String(verifyRaw).trim().toLowerCase();
    const verified = verifyRaw === true || verifyText === "true";

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
      counts: {
        revealedAttributes: revealedAttributes.length,
        predicateProofs: predicateProofs.length,
      },
      revealedAttributes,
      predicateProofs,
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

    return {
      presentationIdLocal,
      record: parsed.record,
      presentation: parsed.presentation,
      presentationRequest: parsed.presentationRequest,
      meta: parsed.meta,
      revealedAttributes,
      predicateProofs,
      counts: {
        revealedAttributes: revealedAttributes.length,
        predicateProofs: predicateProofs.length,
      },
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

    const kind = String(i?.kind || "").trim() || "ssi/proof/presentation";
    const threadId = String(i?.threadId || "").trim()
      || firstNonEmpty(parsed?.meta?.thread_id, parsed?.meta?.threadId)
      || `th_${Date.now()}_${Math.floor(Math.random() * 1_000_000_000)}`;
    const expiresAtMsOpt = parsePositiveEpochMs(i?.expiresAtMs, "expiresAtMs");

    const inputMeta = i?.metaObj && typeof i.metaObj === "object" && !Array.isArray(i.metaObj)
      ? i.metaObj
      : null;
    const mergedMeta = {
      ...(parsed?.meta && typeof parsed.meta === "object" ? parsed.meta : {}),
      ...(inputMeta || {}),
      source: "stored_presentation",
      presentation_id_local: presentationIdLocal,
    };

    const payload = {
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

    const credDefJsonLedger = await ssi.fetchCredDefFromLedger(String(i.genesisPath), credDefId);
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
      offerId: matchingOffer?.offerId || null,
      offerNonce: matchingOffer?.nonce || null,
      offerCandidatesChecked: offerCandidates,
    };
  }));

  ipcMain.handle(CH.CRED_CREATE_LOAD_SCHEMA_TEMPLATE, safeHandler(async (i) => {
    validateNonEmptyString(i?.genesisPath, "genesisPath");
    validateNonEmptyString(i?.credDefId, "credDefId");

    const credDefRaw = await ssi.fetchCredDefFromLedger(String(i.genesisPath), String(i.credDefId));
    const credDefObj = unwrapLedgerPayload(credDefRaw);
    if (!credDefObj || typeof credDefObj !== "object") {
      const e = new Error("CredDef inválida no ledger: JSON não parseável.");
      e.code = "INVALID_CREDDEF_LEDGER_JSON";
      e.details = { credDefId: String(i.credDefId), rawType: typeof credDefRaw };
      throw e;
    }

    const schemaId = await resolveSchemaIdForCredDef(String(i.genesisPath), String(i.credDefId), credDefObj);

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
        attrNames = extractCredDefAttrNames(credDefObj);
        attrSource = "creddef_primary_r";
        if (!attrNames.length) throw schemaErr;
      }
    } else {
      attrNames = extractCredDefAttrNames(credDefObj);
      attrSource = "creddef_primary_r";
      if (!attrNames.length) {
        const e = new Error("Não foi possível obter schema_id a partir da CredDef.");
        e.code = "MISSING_SCHEMA_ID";
        e.details = { credDefId: String(i.credDefId) };
        throw e;
      }
    }

    if (!attrNames.length) {
      const fallbackAttrs = extractCredDefAttrNames(credDefObj);
      if (fallbackAttrs.length) {
        attrNames = fallbackAttrs;
        attrSource = "creddef_primary_r";
      }
    }
    const valuesTemplate = {};
    attrNames.forEach((a) => { valuesTemplate[a] = ""; });

    return {
      credDefId: String(i.credDefId),
      schemaId: schemaId || null,
      attrSource,
      attrNames,
      valuesTemplate,
      credDef: credDefObj,
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
        i?.offerFilePath,
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
    const credentialObj = parseJsonMaybeString(credentialPlain, null);
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

    const credDefJsonLedger = await ssi.fetchCredDefFromLedger(String(i.genesisPath), credDefId);
    const credentialIdInput = String(i?.credentialId || "").trim();
    const threadIdHint = firstNonEmpty(envelopeSummary?.thread_id, envelopeSummary?.threadId);
    const threadIdSafe = threadIdHint.replace(/[^a-zA-Z0-9._-]/g, "_");
    const baseCredentialId = credentialIdInput
      || (threadIdSafe ? `received-credential-${threadIdSafe}` : `received-credential-${Date.now()}`);

    let credentialIdStored = baseCredentialId;
    let alreadyStored = false;
    try {
      credentialIdStored = await ssi.storeCredential(
        baseCredentialId,
        credentialPlain,
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
              credentialPlain,
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
                ? `${credentialIdInput}-${Date.now()}`
                : `received-credential-${Date.now()}`;
              try {
                credentialIdStored = await ssi.storeCredential(
                  retryId,
                  credentialPlain,
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
        if (credentialIdInput) retryIds.push(`${credentialIdInput}-${Date.now()}`);
        retryIds.push(`received-credential-${Date.now()}`);
        let storedAfterDuplicateRetry = false;

        for (const retryId of retryIds) {
          try {
            credentialIdStored = await ssi.storeCredential(
              retryId,
              credentialPlain,
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

    return {
      canceled: false,
      credentialFilePath,
      holderDid,
      holderDidSource: resolved.source,
      kind: firstNonEmpty(envelopeSummary?.kind) || null,
      threadId: firstNonEmpty(envelopeSummary?.thread_id, envelopeSummary?.threadId) || null,
      credDefId,
      requestMetadataId,
      requestMetadataSource: requestMetadataSource || "credential_envelope",
      inferredOfferFilePath,
      credentialId: credentialIdStored,
      alreadyStored,
      envelopeSummary,
    };
  }));

}


module.exports = { registerIpcHandlers };
