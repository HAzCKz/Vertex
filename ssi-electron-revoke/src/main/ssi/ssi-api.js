// src/main/ssi/ssi-api.js
const { loadNative } = require("./ssi-loader");

const SSI_API_INSTANCE = Math.random().toString(16).slice(2);
console.log(`[ssi-api] loaded instance=${SSI_API_INSTANCE}`);

let addon;
let agent;
let activeWalletPath = null;
const schemaPublishInFlight = new Map();

function getAgent() {
  if (!addon) addon = loadNative();
  if (!agent) agent = new addon.IndyAgent();
  return agent;
}

function toSchemaId(issuerDid, name, version) {
  return `${String(issuerDid)}:2:${String(name)}:${String(version)}`;
}

module.exports = {
  // -------------------------
  // Wallet
  // -------------------------
  walletCreate: (walletPath, pass) => getAgent().walletCreate(walletPath, pass),

  walletOpen: async (walletPath, pass) => {
    const r = await getAgent().walletOpen(walletPath, pass);
    activeWalletPath = walletPath;
    return r;
  },

  // FECHAR "normal" no app: use LOCK
  walletLock: async () => {
    return getAgent().walletLock();
  },

  // CLOSE: não recebe path (use só em shutdown se quiser)
  walletClose: async () => {
    return getAgent().walletClose();
  },

  walletChangePass: (walletPath, oldPass, newPass) =>
    getAgent().walletChangePass(walletPath, oldPass, newPass),

  walletGetSession: () => ({ activeWalletPath }),

  // walletInfo exige String (path)
  walletInfo: (walletPath) => {
    const p = walletPath || activeWalletPath;
    if (!p) {
      const e = new Error("walletInfo: walletPath ausente e nenhuma wallet ativa.");
      e.code = "VALIDATION_ERROR";
      throw e;
    }
    return getAgent().walletInfo(p);
  },

  // -------------------------
  // Ledger / Network
  // -------------------------
  connectNetwork: (genesisPath) => getAgent().connectNetwork(genesisPath),
  networkHealthcheck: () => getAgent().networkHealthcheck(),

  writeAttribOnLedger: (genesisPath, did, key, value) => {
    const agentRef = getAgent();
    const fn = agentRef.writeAttribOnLedger || agentRef.write_attrib_on_ledger;
    if (typeof fn !== "function") {
      const e = new Error("Método writeAttribOnLedger indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(agentRef, String(genesisPath), String(did), String(key), String(value));
  },

  readAttribFromLedger: (genesisPath, did, key) => {
    const agentRef = getAgent();
    const fn = agentRef.readAttribFromLedger || agentRef.read_attrib_from_ledger;
    if (typeof fn !== "function") {
      const e = new Error("Método readAttribFromLedger indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(agentRef, String(genesisPath), String(did), String(key));
  },

  checkAttribExists: (genesisPath, did, key) => {
    const agentRef = getAgent();
    const fn = agentRef.checkAttribExists || agentRef.check_attrib_exists;
    if (typeof fn !== "function") {
      const e = new Error("Método checkAttribExists indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(agentRef, String(genesisPath), String(did), String(key));
  },

  // -------------------------
  // DIDs
  // -------------------------
  createDidV2: (optsJson) => getAgent().createDidV2(optsJson),

  // ✅ Você continua “usando createOwnDid”.
  // Se (e somente se) vier o erro de category_type, fazemos fallback compatível.
  createOwnDid: async () => {
    try {
      return await getAgent().createOwnDid();
    } catch (e) {
      const msg = String(e?.message || e);
      console.log(`[ssi-api ${SSI_API_INSTANCE}] createOwnDid error:`, msg);

      if (msg.includes("category_type inválido")) {
        console.log(`[ssi-api ${SSI_API_INSTANCE}] fallback -> createDidV2({category_type:'own'})`);
        return getAgent().createDidV2(JSON.stringify({ category_type: "own" }));
      }
      throw e;
    }
  },

  storeTheirDid: (did, verkey, alias = "") =>
    getAgent().storeTheirDid(String(did), String(verkey), String(alias)),

  listDids: (category) => getAgent().listDids(String(category)),
  searchDids: (optsJson) => getAgent().searchDids(optsJson),
  getDid: (did) => getAgent().getDid(String(did)),           // usado pra checar duplicação
  getDidByVerkey: (verkey) => getAgent().getDidByVerkey(String(verkey)),

  exportDidsBatch: (optsJson) => getAgent().exportDidsBatch(optsJson),
  importDidsBatch: (optsJson) => getAgent().importDidsBatch(optsJson),

  importDidFromSeed: async (seed) => {
    console.log("[ssi-api] importDidFromSeed called; seed len=", String(seed).length);
    return getAgent().importDidFromSeed(String(seed));
  },

  registerDidOnLedger: (genesisPath, submitterDid, targetDid, verkey, role) =>
    getAgent().registerDidOnLedger(
      String(genesisPath),
      String(submitterDid),
      String(targetDid),
      String(verkey),
      role === "" ? null : role // permite null como no seu teste
    ),

  // -------------------------
  // Credential Offer + Envelope
  // -------------------------
  createCredentialOffer: (credDefId, offerId) =>
    getAgent().createCredentialOffer(String(credDefId), String(offerId)),

  envelopePackAuthcrypt: (
    senderDid,
    recipientVerkey,
    kind,
    threadIdOpt,
    plaintext,
    expiresAtMsOpt,
    metaJsonOpt
  ) =>
    getAgent().envelopePackAuthcrypt(
      String(senderDid),
      String(recipientVerkey),
      String(kind),
      threadIdOpt ? String(threadIdOpt) : null,
      typeof plaintext === "string" ? plaintext : JSON.stringify(plaintext),
      expiresAtMsOpt === undefined || expiresAtMsOpt === null ? null : Number(expiresAtMsOpt),
      metaJsonOpt === undefined || metaJsonOpt === null ? null : String(metaJsonOpt)
    ),

  envelopeParse: (envelopeJson) => getAgent().envelopeParse(String(envelopeJson)),

  envelopeUnpackAuto: (receiverDid, envelopeJson) =>
    getAgent().envelopeUnpackAuto(String(receiverDid), String(envelopeJson)),

  createLinkSecret: (linkSecretId) => getAgent().createLinkSecret(String(linkSecretId)),

  createCredentialRequest: (linkSecretId, holderDid, credDefJsonLedger, offerJson) =>
    getAgent().createCredentialRequest(
      String(linkSecretId),
      String(holderDid),
      typeof credDefJsonLedger === "string" ? credDefJsonLedger : JSON.stringify(credDefJsonLedger),
      typeof offerJson === "string" ? offerJson : JSON.stringify(offerJson)
    ),

  createCredential: (credDefId, offerJson, requestJson, valuesJson) =>
    getAgent().createCredential(
      String(credDefId),
      typeof offerJson === "string" ? offerJson : JSON.stringify(offerJson),
      typeof requestJson === "string" ? requestJson : JSON.stringify(requestJson),
      typeof valuesJson === "string" ? valuesJson : JSON.stringify(valuesJson)
    ),

  issueRevocableCredential: (
    genesisPath,
    issuerLocalCredentialId,
    holderDidHint,
    credDefId,
    schemaId,
    offerJson,
    requestJson,
    valuesJson,
    startTime,
    validityEnd,
    unitOfTime,
    timeWindow,
    extraWindowsForFpOpt,
    manifestJsonOpt,
    kVectorIdOpt,
    chunkSizeBytesOpt
  ) => {
    const agentRef = getAgent();
    const fn = agentRef.issueRevocableCredential || agentRef.issue_revocable_credential;
    if (typeof fn !== "function") {
      const e = new Error("Método issueRevocableCredential indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      String(genesisPath),
      String(issuerLocalCredentialId),
      holderDidHint === undefined || holderDidHint === null || holderDidHint === ""
        ? null
        : String(holderDidHint),
      String(credDefId),
      String(schemaId),
      typeof offerJson === "string" ? offerJson : JSON.stringify(offerJson),
      typeof requestJson === "string" ? requestJson : JSON.stringify(requestJson),
      typeof valuesJson === "string" ? valuesJson : JSON.stringify(valuesJson),
      Number(startTime),
      Number(validityEnd),
      String(unitOfTime),
      Number(timeWindow),
      extraWindowsForFpOpt === undefined || extraWindowsForFpOpt === null
        ? null
        : Number(extraWindowsForFpOpt),
      manifestJsonOpt === undefined || manifestJsonOpt === null || manifestJsonOpt === ""
        ? null
        : (typeof manifestJsonOpt === "string" ? manifestJsonOpt : JSON.stringify(manifestJsonOpt)),
      kVectorIdOpt === undefined || kVectorIdOpt === null || kVectorIdOpt === ""
        ? null
        : String(kVectorIdOpt),
      chunkSizeBytesOpt === undefined || chunkSizeBytesOpt === null
        ? null
        : Number(chunkSizeBytesOpt)
    );
  },

  revocationSetupCreateK: (issuerDid, kVectorIdOpt, chunkSizeBytesOpt) => {
    const agentRef = getAgent();
    const fn = agentRef.revocationSetupCreateK || agentRef.revocation_setup_create_k;
    if (typeof fn !== "function") {
      const e = new Error("Método revocationSetupCreateK indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      String(issuerDid),
      kVectorIdOpt === undefined || kVectorIdOpt === null || kVectorIdOpt === ""
        ? null
        : String(kVectorIdOpt),
      chunkSizeBytesOpt === undefined || chunkSizeBytesOpt === null
        ? null
        : Number(chunkSizeBytesOpt)
    );
  },

  revocationWriteKVectorOnLedger: (genesisPath, issuerDid, kVectorJson, chunkSizeBytesOpt) => {
    const agentRef = getAgent();
    const fn =
      agentRef.revocationWriteKVectorOnLedger || agentRef.revocation_write_k_vector_on_ledger;
    if (typeof fn !== "function") {
      const e = new Error("Método revocationWriteKVectorOnLedger indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      String(genesisPath),
      String(issuerDid),
      typeof kVectorJson === "string" ? kVectorJson : JSON.stringify(kVectorJson),
      chunkSizeBytesOpt === undefined || chunkSizeBytesOpt === null
        ? null
        : Number(chunkSizeBytesOpt)
    );
  },

  revocationReadKVectorFromLedger: (genesisPath, issuerDid, kVectorId) => {
    const agentRef = getAgent();
    const fn =
      agentRef.revocationReadKVectorFromLedger || agentRef.revocation_read_k_vector_from_ledger;
    if (typeof fn !== "function") {
      const e = new Error("Método revocationReadKVectorFromLedger indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(agentRef, String(genesisPath), String(issuerDid), String(kVectorId));
  },

  revocationBuildManifestAnchor: (issuerDid, manifestUrl, manifestHash, manifestVersionOpt) => {
    const agentRef = getAgent();
    const fn =
      agentRef.revocationBuildManifestAnchor || agentRef.revocation_build_manifest_anchor;
    if (typeof fn !== "function") {
      const e = new Error("Método revocationBuildManifestAnchor indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      String(issuerDid),
      String(manifestUrl),
      String(manifestHash),
      manifestVersionOpt === undefined || manifestVersionOpt === null || manifestVersionOpt === ""
        ? null
        : String(manifestVersionOpt)
    );
  },

  revocationWriteManifestAnchorOnLedger: (genesisPath, issuerDid, manifestJson) => {
    const agentRef = getAgent();
    const fn =
      agentRef.revocationWriteManifestAnchorOnLedger
      || agentRef.revocation_write_manifest_anchor_on_ledger;
    if (typeof fn !== "function") {
      const e = new Error("Método revocationWriteManifestAnchorOnLedger indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      String(genesisPath),
      String(issuerDid),
      typeof manifestJson === "string" ? manifestJson : JSON.stringify(manifestJson)
    );
  },

  revocationReadManifestAnchorFromLedger: (genesisPath, issuerDid) => {
    const agentRef = getAgent();
    const fn =
      agentRef.revocationReadManifestAnchorFromLedger
      || agentRef.revocation_read_manifest_anchor_from_ledger;
    if (typeof fn !== "function") {
      const e = new Error("Método revocationReadManifestAnchorFromLedger indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(agentRef, String(genesisPath), String(issuerDid));
  },

  storeCredential: (credentialId, credentialJson, requestMetadataId, credDefJson, revRegDefJsonOpt) =>
    getAgent().storeCredential(
      String(credentialId),
      typeof credentialJson === "string" ? credentialJson : JSON.stringify(credentialJson),
      String(requestMetadataId),
      typeof credDefJson === "string" ? credDefJson : JSON.stringify(credDefJson),
      revRegDefJsonOpt === undefined || revRegDefJsonOpt === null
        ? null
        : (typeof revRegDefJsonOpt === "string" ? revRegDefJsonOpt : JSON.stringify(revRegDefJsonOpt))
    ),

  storeReceivedRevocableCredential: (bundleIdLocal, holderBundleJson, credentialIdLocalOpt) => {
    const agentRef = getAgent();
    const fn = agentRef.storeReceivedRevocableCredential || agentRef.store_received_revocable_credential;
    if (typeof fn !== "function") {
      const e = new Error("Método storeReceivedRevocableCredential indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      String(bundleIdLocal),
      typeof holderBundleJson === "string" ? holderBundleJson : JSON.stringify(holderBundleJson),
      credentialIdLocalOpt === undefined || credentialIdLocalOpt === null || credentialIdLocalOpt === ""
        ? null
        : String(credentialIdLocalOpt)
    );
  },

  listIssuedRevocableCredentials: (statusFilterOpt) => {
    const agentRef = getAgent();
    const fn =
      agentRef.listIssuedRevocableCredentials || agentRef.list_issued_revocable_credentials;
    if (typeof fn !== "function") {
      const e = new Error("Método listIssuedRevocableCredentials indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      statusFilterOpt === undefined || statusFilterOpt === null || statusFilterOpt === ""
        ? null
        : String(statusFilterOpt)
    );
  },

  getIssuedRevocableCredentialSummary: (idLocal) => {
    const agentRef = getAgent();
    const fn =
      agentRef.getIssuedRevocableCredentialSummary || agentRef.get_issued_revocable_credential_summary;
    if (typeof fn !== "function") {
      const e = new Error("Método getIssuedRevocableCredentialSummary indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(agentRef, String(idLocal));
  },

  preflightRevokeIssuedCredential: (idLocal, revokeFromWindowOpt) => {
    const agentRef = getAgent();
    const fn =
      agentRef.preflightRevokeIssuedCredential || agentRef.preflight_revoke_issued_credential;
    if (typeof fn !== "function") {
      const e = new Error("Método preflightRevokeIssuedCredential indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      String(idLocal),
      revokeFromWindowOpt === undefined || revokeFromWindowOpt === null
        ? null
        : Number(revokeFromWindowOpt)
    );
  },

  revokeIssuedCredentialFromWindow: (
    idLocal,
    bloomAdminToken,
    revokeFromWindow,
    reasonOpt,
    requestedByOpt
  ) => {
    const agentRef = getAgent();
    const fn =
      agentRef.revokeIssuedCredentialFromWindow || agentRef.revoke_issued_credential_from_window;
    if (typeof fn !== "function") {
      const e = new Error("Método revokeIssuedCredentialFromWindow indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      String(idLocal),
      String(bloomAdminToken),
      Number(revokeFromWindow),
      reasonOpt === undefined || reasonOpt === null || reasonOpt === ""
        ? null
        : String(reasonOpt),
      requestedByOpt === undefined || requestedByOpt === null || requestedByOpt === ""
        ? null
        : String(requestedByOpt)
    );
  },

  getHolderRevocationBundle: (bundleIdLocal) => {
    const agentRef = getAgent();
    const fn = agentRef.getHolderRevocationBundle || agentRef.get_holder_revocation_bundle;
    if (typeof fn !== "function") {
      const e = new Error("Método getHolderRevocationBundle indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(agentRef, String(bundleIdLocal));
  },

  buildPresentationRevocationProofV2: (
    bundleIdLocal,
    primaryWindowIndex,
    additionalWindowCountOpt,
    credentialIdLocalOpt
  ) => {
    const agentRef = getAgent();
    const fn =
      agentRef.buildPresentationRevocationProofV2 || agentRef.build_presentation_revocation_proof_v2;
    if (typeof fn !== "function") {
      const e = new Error("Método buildPresentationRevocationProofV2 indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      String(bundleIdLocal),
      Number(primaryWindowIndex),
      additionalWindowCountOpt === undefined || additionalWindowCountOpt === null
        ? null
        : Number(additionalWindowCountOpt),
      credentialIdLocalOpt === undefined || credentialIdLocalOpt === null || credentialIdLocalOpt === ""
        ? null
        : String(credentialIdLocalOpt)
    );
  },

  verifyPresentationRevocationProofV2: (
    proofSequenceJson,
    expectedRootMerkleLOpt,
    policyJsonOpt,
    storeEventOpt
  ) => {
    const agentRef = getAgent();
    const fn =
      agentRef.verifyPresentationRevocationProofV2 || agentRef.verify_presentation_revocation_proof_v2;
    if (typeof fn !== "function") {
      const e = new Error("Método verifyPresentationRevocationProofV2 indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      typeof proofSequenceJson === "string" ? proofSequenceJson : JSON.stringify(proofSequenceJson),
      expectedRootMerkleLOpt === undefined || expectedRootMerkleLOpt === null || expectedRootMerkleLOpt === ""
        ? null
        : String(expectedRootMerkleLOpt),
      policyJsonOpt === undefined || policyJsonOpt === null || policyJsonOpt === ""
        ? null
        : (typeof policyJsonOpt === "string" ? policyJsonOpt : JSON.stringify(policyJsonOpt)),
      storeEventOpt === undefined || storeEventOpt === null ? null : !!storeEventOpt
    );
  },

  verifyHolderRevocationStatusFullScan: (
    bundleIdLocal,
    credentialIdLocalOpt,
    expectedRootMerkleLOpt,
    policyJsonOpt,
    manifestAnchorJsonOpt
  ) => {
    const agentRef = getAgent();
    const fn =
      agentRef.verifyHolderRevocationStatusFullScan || agentRef.verify_holder_revocation_status_full_scan;
    if (typeof fn !== "function") {
      const e = new Error("Método verifyHolderRevocationStatusFullScan indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      String(bundleIdLocal),
      credentialIdLocalOpt === undefined || credentialIdLocalOpt === null || credentialIdLocalOpt === ""
        ? null
        : String(credentialIdLocalOpt),
      expectedRootMerkleLOpt === undefined || expectedRootMerkleLOpt === null || expectedRootMerkleLOpt === ""
        ? null
        : String(expectedRootMerkleLOpt),
      policyJsonOpt === undefined || policyJsonOpt === null || policyJsonOpt === ""
        ? null
        : (typeof policyJsonOpt === "string" ? policyJsonOpt : JSON.stringify(policyJsonOpt)),
      manifestAnchorJsonOpt === undefined || manifestAnchorJsonOpt === null || manifestAnchorJsonOpt === ""
        ? null
        : (typeof manifestAnchorJsonOpt === "string" ? manifestAnchorJsonOpt : JSON.stringify(manifestAnchorJsonOpt))
    );
  },

  listCredentials: () => getAgent().listCredentials(),

  deleteCredential: (credentialIdLocal) => {
    const agentRef = getAgent();
    const fn = agentRef.deleteCredential || agentRef.delete_credential;
    if (typeof fn !== "function") {
      const e = new Error("Método deleteCredential indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(agentRef, String(credentialIdLocal));
  },

  deleteIssuedRevocableCredential: (issuerLocalCredentialId) => {
    const agentRef = getAgent();
    const fn =
      agentRef.deleteIssuedRevocableCredential || agentRef.delete_issued_revocable_credential;
    if (typeof fn !== "function") {
      const e = new Error("Método deleteIssuedRevocableCredential indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(agentRef, String(issuerLocalCredentialId));
  },

  listCredentialsBy: (schemaIdOpt, credDefIdOpt) =>
    getAgent().listCredentialsBy(
      schemaIdOpt ? String(schemaIdOpt) : null,
      credDefIdOpt ? String(credDefIdOpt) : null
    ),

  listCredentialOffers: () => getAgent().listCredentialOffers(),
  storeReceivedOffer: (offerJson) => getAgent().storeReceivedOffer(String(offerJson)),

  buildRequestedCredentialsV1: (selectionJson) => {
    const agentRef = getAgent();
    const fn = agentRef.buildRequestedCredentialsV1 || agentRef.build_requested_credentials_v1;
    if (typeof fn !== "function") {
      const e = new Error("Método buildRequestedCredentialsV1 indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(agentRef, String(selectionJson));
  },

  createPresentation: (presentationRequestJson, requestedCredentialsJson, schemasJson, credDefsJson) => {
    const agentRef = getAgent();
    const fn = agentRef.createPresentation || agentRef.create_presentation;
    if (typeof fn !== "function") {
      const e = new Error("Método createPresentation indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      String(presentationRequestJson),
      String(requestedCredentialsJson),
      String(schemasJson),
      String(credDefsJson)
    );
  },

  createPresentationV2: (presentationRequestJson, selectionJson, schemasJson, credDefsJson) => {
    const agentRef = getAgent();
    const fn = agentRef.createPresentationV2 || agentRef.create_presentation_v2;
    if (typeof fn !== "function") {
      const e = new Error("Método createPresentationV2 indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      String(presentationRequestJson),
      String(selectionJson),
      String(schemasJson),
      String(credDefsJson)
    );
  },

  createPresentationPackageWithRevocationV2: (
    presentationRequestJson,
    selectionJson,
    schemasJson,
    credDefsJson,
    revocationSequencesJsonOpt
  ) => {
    const agentRef = getAgent();
    const fn = agentRef.createPresentationPackageWithRevocationV2
      || agentRef.create_presentation_package_with_revocation_v2;
    if (typeof fn !== "function") {
      const e = new Error("Método createPresentationPackageWithRevocationV2 indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      String(presentationRequestJson),
      String(selectionJson),
      String(schemasJson),
      String(credDefsJson),
      revocationSequencesJsonOpt === undefined || revocationSequencesJsonOpt === null
        ? null
        : String(revocationSequencesJsonOpt)
    );
  },

  verifyPresentation: (presentationRequestJson, presentationJson, schemasJson, credDefsJson) => {
    const agentRef = getAgent();
    const fn = agentRef.verifyPresentation || agentRef.verify_presentation;
    if (typeof fn !== "function") {
      const e = new Error("Método verifyPresentation indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      String(presentationRequestJson),
      String(presentationJson),
      String(schemasJson),
      String(credDefsJson)
    );
  },

  verifyMixedPresentationPackageV2: (
    presentationRequestJson,
    presentationJson,
    schemasJson,
    credDefsJson,
    revocationProofSequencesJson,
    expectedRootsJsonOpt,
    policyJsonOpt
  ) => {
    const agentRef = getAgent();
    const fn = agentRef.verifyMixedPresentationPackageV2 || agentRef.verify_mixed_presentation_package_v2;
    if (typeof fn !== "function") {
      const e = new Error("Método verifyMixedPresentationPackageV2 indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      String(presentationRequestJson),
      String(presentationJson),
      String(schemasJson),
      String(credDefsJson),
      String(revocationProofSequencesJson),
      expectedRootsJsonOpt === undefined || expectedRootsJsonOpt === null
        ? null
        : String(expectedRootsJsonOpt),
      policyJsonOpt === undefined || policyJsonOpt === null
        ? null
        : String(policyJsonOpt)
    );
  },

  storePresentation: (presentationIdLocal, presentationJson, presentationRequestJsonOpt, metaJsonOpt) => {
    const agentRef = getAgent();
    const fn = agentRef.storePresentation || agentRef.store_presentation;
    if (typeof fn !== "function") {
      const e = new Error("Método storePresentation indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(
      agentRef,
      String(presentationIdLocal),
      String(presentationJson),
      presentationRequestJsonOpt === undefined || presentationRequestJsonOpt === null
        ? null
        : String(presentationRequestJsonOpt),
      metaJsonOpt === undefined || metaJsonOpt === null
        ? null
        : String(metaJsonOpt)
    );
  },

  listPresentations: () => {
    const agentRef = getAgent();
    const fn = agentRef.listPresentations || agentRef.list_presentations;
    if (typeof fn !== "function") {
      const e = new Error("Método listPresentations indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(agentRef);
  },

  getStoredPresentation: (presentationIdLocal) => {
    const agentRef = getAgent();
    const fn = agentRef.getStoredPresentation || agentRef.get_stored_presentation;
    if (typeof fn !== "function") {
      const e = new Error("Método getStoredPresentation indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(agentRef, String(presentationIdLocal));
  },

  getStoredPresentationRevocationSequences: (presentationIdLocal) => {
    const agentRef = getAgent();
    const fn =
      agentRef.getStoredPresentationRevocationSequences
      || agentRef.get_stored_presentation_revocation_sequences;
    if (typeof fn !== "function") {
      const e = new Error("Método getStoredPresentationRevocationSequences indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(agentRef, String(presentationIdLocal));
  },

  deleteStoredPresentation: (presentationIdLocal) => {
    const agentRef = getAgent();
    const fn = agentRef.deleteStoredPresentation || agentRef.delete_stored_presentation;
    if (typeof fn !== "function") {
      const e = new Error("Método deleteStoredPresentation indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(agentRef, String(presentationIdLocal));
  },

  exportStoredPresentation: (presentationIdLocal) => {
    const agentRef = getAgent();
    const fn = agentRef.exportStoredPresentation || agentRef.export_stored_presentation;
    if (typeof fn !== "function") {
      const e = new Error("Método exportStoredPresentation indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(agentRef, String(presentationIdLocal));
  },

  // -------------------------
  // Schemas (assinaturas reais do schemas.rs)
  // -------------------------
  schemaBuildPreview: (name, version, attrNames, revocable) =>
    getAgent().schemaBuildPreview(String(name), String(version), attrNames || [], !!revocable),

  schemaSaveLocal: (name, version, attrNames, revocable, envLabel) =>
    getAgent().schemaSaveLocal(
      String(name),
      String(version),
      attrNames || [],
      !!revocable,
      envLabel === undefined || envLabel === null || envLabel === "" ? null : String(envLabel)
    ),

  schemaListLocal: (onLedger, envFilter, nameEq) =>
    getAgent().schemaListLocal(
      onLedger === undefined || onLedger === null ? null : !!onLedger,
      envFilter ? String(envFilter) : null,
      nameEq ? String(nameEq) : null
    ),

  schemaGetLocal: (idLocal) => getAgent().schemaGetLocal(String(idLocal)),
  schemaDeleteLocal: (idLocal) => getAgent().schemaDeleteLocal(String(idLocal)),

  schemaRegisterFromLocal: (genesisPath, idLocal, issuerDidOpt) =>
    getAgent().schemaRegisterFromLocal(
      String(genesisPath),
      String(idLocal),
      issuerDidOpt ? String(issuerDidOpt) : null
    ),

  createAndRegisterSchema: async (genesisPath, issuerDid, name, version, attrNames) => {
    const schemaId = toSchemaId(issuerDid, name, version);
    if (schemaPublishInFlight.has(schemaId)) {
      return schemaPublishInFlight.get(schemaId);
    }

    const op = (async () => {
      try {
        // O ledger pode ser resetado sem limpar a wallet local.
        // Se já existir registro local com a mesma chave schemaId, removemos para evitar
        // "Duplicate entry" no insert final da lib nativa.
        try {
          await getAgent().schemaDeleteLocal(String(schemaId));
        } catch (_) {
          // ignora: não existir é o caso esperado na maioria das vezes
        }

        return await getAgent().createAndRegisterSchema(
          String(genesisPath),
          String(issuerDid),
          String(name),
          String(version),
          Array.isArray(attrNames) ? attrNames.map(String) : []
        );
      } catch (e) {
        const msg = String(e?.message || e);
        if (msg.includes("Duplicate entry")) {
          return {
            schemaId,
            alreadyPublished: true,
            source: "ssi-api-duplicate-entry",
          };
        }
        throw e;
      }
    })();

    schemaPublishInFlight.set(schemaId, op);
    try {
      return await op;
    } finally {
      if (schemaPublishInFlight.get(schemaId) === op) {
        schemaPublishInFlight.delete(schemaId);
      }
    }
  },

  fetchSchemaFromLedger: (genesisPath, schemaId) =>
    getAgent().fetchSchemaFromLedger(String(genesisPath), String(schemaId)),

  // -------------------------
  // CredDefs
  // -------------------------
  creddefSaveLocal: (issuerDid, schemaId, tag, supportRevocation, envLabel) =>
    getAgent().creddefSaveLocal(
      String(issuerDid),
      String(schemaId),
      String(tag),
      !!supportRevocation,
      envLabel === undefined || envLabel === null || envLabel === "" ? null : String(envLabel)
    ),

  creddefListLocal: (onLedger, envFilter, issuerDidEq, schemaIdEq, tagEq) =>
    getAgent().creddefListLocal(
      onLedger === undefined || onLedger === null ? null : !!onLedger,
      envFilter ? String(envFilter) : null,
      issuerDidEq ? String(issuerDidEq) : null,
      schemaIdEq ? String(schemaIdEq) : null,
      tagEq ? String(tagEq) : null
    ),

  creddefGetLocal: (idLocal) => getAgent().creddefGetLocal(String(idLocal)),
  creddefGetLocalByCredDefId: (credDefId) => {
    const agentRef = getAgent();
    const fn = agentRef.creddefGetLocalByCredDefId || agentRef.creddef_get_local_by_cred_def_id;
    if (typeof fn !== "function") {
      const e = new Error("Método creddefGetLocalByCredDefId indisponível no addon nativo.");
      e.code = "NATIVE_METHOD_NOT_FOUND";
      throw e;
    }
    return fn.call(agentRef, String(credDefId));
  },
  creddefDeleteLocal: (idLocal) => getAgent().creddefDeleteLocal(String(idLocal)),

  creddefRegisterFromLocal: (genesisPath, idLocal, issuerDidOpt) =>
    getAgent().creddefRegisterFromLocal(
      String(genesisPath),
      String(idLocal),
      issuerDidOpt ? String(issuerDidOpt) : null
    ),

  createAndRegisterCredDef: (genesisPath, issuerDid, schemaId, tag) =>
    getAgent().createAndRegisterCredDef(
      String(genesisPath),
      String(issuerDid),
      String(schemaId),
      String(tag)
    ),

  fetchCredDefFromLedger: (genesisPath, credDefId) =>
    getAgent().fetchCredDefFromLedger(String(genesisPath), String(credDefId)),
};
