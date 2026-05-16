const { contextBridge, ipcRenderer } = require("electron");
const CH = require("../main/ipc/channels");

contextBridge.exposeInMainWorld("ssi", {
  ping: () => ipcRenderer.invoke(CH.APP_PING),

  wallet: {
    create: (walletPath, pass) => ipcRenderer.invoke(CH.WALLET_CREATE, { walletPath, pass }),
    open: (walletPath, pass) => ipcRenderer.invoke(CH.WALLET_OPEN, { walletPath, pass }),
    close: () => ipcRenderer.invoke(CH.WALLET_CLOSE, {}),
    changePass: (walletPath, oldPass, newPass) =>
      ipcRenderer.invoke(CH.WALLET_CHANGE_PASS, { walletPath, oldPass, newPass }),
    pickPath: (mode) => ipcRenderer.invoke(CH.WALLET_PICK_PATH, { mode }),
    verifyPass: (walletPath, pass) => ipcRenderer.invoke(CH.WALLET_VERIFY_PASS, { walletPath, pass }),
    lock: () => ipcRenderer.invoke(CH.WALLET_LOCK, {}),
    info: (walletPath) => ipcRenderer.invoke(CH.WALLET_INFO, { walletPath }),
    getSession: () => ipcRenderer.invoke(CH.WALLET_GET_SESSION, {})
  },

  ledger: {
    connect: (genesisPath) => ipcRenderer.invoke(CH.LEDGER_CONNECT, { genesisPath }),
    health: () => ipcRenderer.invoke(CH.LEDGER_HEALTH)
  },

  attrib: {
    writeOnLedger: (genesisPath, did, key, value) =>
      ipcRenderer.invoke(CH.ATTRIB_WRITE_ON_LEDGER, { genesisPath, did, key, value }),
    readFromLedger: (genesisPath, did, key) =>
      ipcRenderer.invoke(CH.ATTRIB_READ_FROM_LEDGER, { genesisPath, did, key }),
    checkExists: (genesisPath, did, key) =>
      ipcRenderer.invoke(CH.ATTRIB_CHECK_EXISTS, { genesisPath, did, key }),
  },

  did: {
    createOwn: () => ipcRenderer.invoke(CH.DID_CREATE_OWN, {}),
    storeTheir: (did, verkey, alias) => ipcRenderer.invoke(CH.DID_STORE_THEIR, { did, verkey, alias }),
    list: (category) => ipcRenderer.invoke(CH.DID_LIST, { category }),
    exportBatch: (opts) => ipcRenderer.invoke(CH.DID_EXPORT_BATCH, { opts }),
    importBatch: (opts) => ipcRenderer.invoke(CH.DID_IMPORT_BATCH, { opts }),
    importTrustee: (seed) => ipcRenderer.invoke(CH.DID_IMPORT_TRUSTEE, { seed }),

    registerOnLedger: (genesisPath, submitterDid, targetDid, verkey, role) =>
      ipcRenderer.invoke(CH.DID_REGISTER_ON_LEDGER, { genesisPath, submitterDid, targetDid, verkey, role }),
    exportFile: () => ipcRenderer.invoke(CH.DID_EXPORT_FILE, {}),
    importFile: () => ipcRenderer.invoke(CH.DID_IMPORT_FILE, {}),

  },

  schema: {
    // Local (catálogo)
    saveLocal: (name, version, attrNames, revocable, envLabel) =>
      ipcRenderer.invoke(CH.SCHEMA_SAVE_LOCAL, { name, version, attrNames, revocable, envLabel }),
    listLocal: (onLedger, envFilter, nameEq) => ipcRenderer.invoke(CH.SCHEMA_LIST_LOCAL, { onLedger, envFilter, nameEq }),
    getLocal: (idLocal) => ipcRenderer.invoke(CH.SCHEMA_GET_LOCAL, { idLocal }),
    deleteLocal: (idLocal) => ipcRenderer.invoke(CH.SCHEMA_DELETE_LOCAL, { idLocal }),

    // Preview
    buildPreview: (name, version, attrNames, revocable) =>
      ipcRenderer.invoke(CH.SCHEMA_BUILD_PREVIEW, { name, version, attrNames, revocable }),

    // Ledger
    registerFromLocal: (genesisPath, idLocal, issuerDidOpt) =>
      ipcRenderer.invoke(CH.SCHEMA_REGISTER_FROM_LOCAL, { genesisPath, idLocal, issuerDidOpt }),
    createAndRegister: (genesisPath, issuerDid, name, version, attrNames) =>
      ipcRenderer.invoke(CH.SCHEMA_CREATE_AND_REGISTER, { genesisPath, issuerDid, name, version, attrNames }),
    fetchFromLedger: (genesisPath, schemaId) => ipcRenderer.invoke(CH.SCHEMA_FETCH_FROM_LEDGER, { genesisPath, schemaId }),
  },

  creddef: {
    saveLocal: (issuerDid, schemaId, tag, supportRevocation, envLabel) =>
      ipcRenderer.invoke(CH.CREDDEF_SAVE_LOCAL, { issuerDid, schemaId, tag, supportRevocation, envLabel }),
    listLocal: (onLedger, envFilter, issuerDidEq, schemaIdEq, tagEq) =>
      ipcRenderer.invoke(CH.CREDDEF_LIST_LOCAL, { onLedger, envFilter, issuerDidEq, schemaIdEq, tagEq }),
    getLocal: (idLocal) => ipcRenderer.invoke(CH.CREDDEF_GET_LOCAL, { idLocal }),
    deleteLocal: (idLocal) => ipcRenderer.invoke(CH.CREDDEF_DELETE_LOCAL, { idLocal }),
    registerFromLocal: (genesisPath, idLocal, issuerDidOpt) =>
      ipcRenderer.invoke(CH.CREDDEF_REGISTER_FROM_LOCAL, { genesisPath, idLocal, issuerDidOpt }),
    createAndRegister: (genesisPath, issuerDid, schemaId, tag) =>
      ipcRenderer.invoke(CH.CREDDEF_CREATE_AND_REGISTER, { genesisPath, issuerDid, schemaId, tag }),
    fetchFromLedger: (genesisPath, credDefId) =>
      ipcRenderer.invoke(CH.CREDDEF_FETCH_FROM_LEDGER, { genesisPath, credDefId }),
  },

  credOffer: {
    exportEnvelope: (input) => ipcRenderer.invoke(CH.CRED_OFFER_EXPORT_ENVELOPE, input || {}),
  },

  credAccept: {
    importOfferEnvelope: (input) => ipcRenderer.invoke(CH.CRED_ACCEPT_IMPORT_OFFER_ENVELOPE, input || {}),
    exportRequestEnvelope: (input) => ipcRenderer.invoke(CH.CRED_ACCEPT_EXPORT_REQUEST_ENVELOPE, input || {}),
  },

  credCreate: {
    importRequestEnvelope: (input) => ipcRenderer.invoke(CH.CRED_CREATE_IMPORT_REQUEST_ENVELOPE, input || {}),
    loadSchemaTemplate: (input) => ipcRenderer.invoke(CH.CRED_CREATE_LOAD_SCHEMA_TEMPLATE, input || {}),
    exportCredentialEnvelope: (input) => ipcRenderer.invoke(CH.CRED_CREATE_EXPORT_CREDENTIAL_ENVELOPE, input || {}),
  },

  credCreateRevocable: {
    setupKVector: (input) =>
      ipcRenderer.invoke(CH.CRED_CREATE_REVOCABLE_SETUP_K_VECTOR, input || {}),
    writeKVectorOnLedger: (input) =>
      ipcRenderer.invoke(CH.CRED_CREATE_REVOCABLE_WRITE_K_VECTOR_ON_LEDGER, input || {}),
    checkManifestOnLedger: (input) =>
      ipcRenderer.invoke(CH.CRED_CREATE_REVOCABLE_CHECK_MANIFEST_ON_LEDGER, input || {}),
    anchorManifestOnLedger: (input) =>
      ipcRenderer.invoke(CH.CRED_CREATE_REVOCABLE_ANCHOR_MANIFEST_ON_LEDGER, input || {}),
    readLedgerSetup: (input) =>
      ipcRenderer.invoke(CH.CRED_CREATE_REVOCABLE_READ_LEDGER_SETUP, input || {}),
    exportCredentialEnvelope: (input) =>
      ipcRenderer.invoke(CH.CRED_CREATE_EXPORT_REVOCABLE_CREDENTIAL_ENVELOPE, input || {}),
  },

  credReceive: {
    previewEnvelope: (input) => ipcRenderer.invoke(CH.CRED_RECEIVE_PREVIEW_ENVELOPE, input || {}),
    importAndStoreEnvelope: (input) => ipcRenderer.invoke(CH.CRED_RECEIVE_IMPORT_AND_STORE_ENVELOPE, input || {}),
  },

  credential: {
    list: (schemaIdEq, credDefIdEq) => ipcRenderer.invoke(CH.CREDENTIAL_LIST, { schemaIdEq, credDefIdEq }),
    delete: (credentialIdLocal) => ipcRenderer.invoke(CH.CREDENTIAL_DELETE, { credentialIdLocal }),
  },

  credRevoke: {
    listIssuedRevocable: (input) =>
      ipcRenderer.invoke(CH.CRED_REVOKE_LIST_ISSUED_REVOCABLE, input || {}),
    getIssuedSummary: (input) =>
      ipcRenderer.invoke(CH.CRED_REVOKE_GET_ISSUED_SUMMARY, input || {}),
    deleteIssued: (input) =>
      ipcRenderer.invoke(CH.CRED_REVOKE_DELETE_ISSUED, input || {}),
    preflight: (input) =>
      ipcRenderer.invoke(CH.CRED_REVOKE_PREFLIGHT, input || {}),
    execute: (input) =>
      ipcRenderer.invoke(CH.CRED_REVOKE_EXECUTE, input || {}),
  },

  revocationVerify: {
    getHolderBundle: (input) =>
      ipcRenderer.invoke(CH.REVOCATION_VERIFY_GET_HOLDER_BUNDLE, input || {}),
    buildProofSequence: (input) =>
      ipcRenderer.invoke(CH.REVOCATION_VERIFY_BUILD_PROOF_SEQUENCE, input || {}),
    verifyProofSequence: (input) =>
      ipcRenderer.invoke(CH.REVOCATION_VERIFY_VERIFY_PROOF_SEQUENCE, input || {}),
    fullScan: (input) =>
      ipcRenderer.invoke(CH.REVOCATION_VERIFY_FULL_SCAN, input || {}),
  },

  presentation: {
    createExportEnvelope: (input) => ipcRenderer.invoke(CH.PRESENTATION_CREATE_EXPORT_ENVELOPE, input || {}),
    verifyImportEnvelope: (input) => ipcRenderer.invoke(CH.PRESENTATION_VERIFY_IMPORT_ENVELOPE, input || {}),
    storeLocal: (input) => ipcRenderer.invoke(CH.PRESENTATION_STORE_LOCAL, input || {}),
    listLocal: () => ipcRenderer.invoke(CH.PRESENTATION_LIST_LOCAL, {}),
    getLocal: (input) =>
      ipcRenderer.invoke(
        CH.PRESENTATION_GET_LOCAL,
        input && typeof input === "object" && !Array.isArray(input)
          ? input
          : { presentationIdLocal: input }
      ),
    verifyStoredRevocation: (input) =>
      ipcRenderer.invoke(CH.PRESENTATION_VERIFY_STORED_REVOCATION, input || {}),
    deleteLocal: (presentationIdLocal) =>
      ipcRenderer.invoke(CH.PRESENTATION_DELETE_LOCAL, { presentationIdLocal }),
    exportStoredEnvelope: (input) =>
      ipcRenderer.invoke(CH.PRESENTATION_EXPORT_STORED_ENVELOPE, input || {}),
  },

});
