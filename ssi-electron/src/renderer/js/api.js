const LOGS_STORAGE_KEY = "ssi-electron.logs";
const MAX_LOG_ENTRIES = 5000;
const LOGS_PERSIST_DEBOUNCE_MS = 400;
const LOGS_NOTIFY_DEBOUNCE_MS = 80;

function normalizeLogMessage(msg) {
  if (msg === undefined || msg === null) return "";
  if (typeof msg === "string") return msg;
  try {
    return JSON.stringify(msg);
  } catch (_) {
    return String(msg);
  }
}

function parseStoredLogs() {
  try {
    const raw = window.localStorage?.getItem(LOGS_STORAGE_KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    return arr
      .filter((it) => it && typeof it === "object")
      .map((it) => ({
        id: String(it.id || ""),
        tsMs: Number(it.tsMs || 0),
        message: normalizeLogMessage(it.message),
      }))
      .filter((it) => it.id && Number.isFinite(it.tsMs));
  } catch (_) {
    return [];
  }
}

const logsStore = parseStoredLogs()
  .sort((a, b) => (Number(b.tsMs || 0) - Number(a.tsMs || 0)));
let logsSeq = 0;
const logSubscribers = new Set();
let persistTimer = null;
let notifyTimer = null;

function persistLogsNow() {
  try {
    window.localStorage?.setItem(LOGS_STORAGE_KEY, JSON.stringify(logsStore));
  } catch (_) {
    // Não interrompe o fluxo se storage estiver indisponível.
  }
}

function schedulePersistLogs() {
  if (persistTimer !== null) return;
  persistTimer = window.setTimeout(() => {
    persistTimer = null;
    persistLogsNow();
  }, LOGS_PERSIST_DEBOUNCE_MS);
}

function flushPersistLogs() {
  if (persistTimer !== null) {
    window.clearTimeout(persistTimer);
    persistTimer = null;
  }
  persistLogsNow();
}

function getLogsSnapshot() {
  return logsStore.slice();
}

function notifyLogsChangedNow() {
  const snapshot = getLogsSnapshot();
  logSubscribers.forEach((fn) => {
    try {
      fn(snapshot);
    } catch (_) {
      // Ignora erro de subscriber para não travar os demais.
    }
  });
}

function scheduleLogsChanged() {
  if (notifyTimer !== null) return;
  notifyTimer = window.setTimeout(() => {
    notifyTimer = null;
    notifyLogsChangedNow();
  }, LOGS_NOTIFY_DEBOUNCE_MS);
}

function flushNotifyLogsChanged() {
  if (notifyTimer !== null) {
    window.clearTimeout(notifyTimer);
    notifyTimer = null;
  }
  notifyLogsChangedNow();
}

function appendLog(msg) {
  const message = normalizeLogMessage(msg).trim();
  const tsMs = Date.now();
  logsSeq += 1;
  logsStore.unshift({
    id: `${tsMs}-${logsSeq}`,
    tsMs,
    message,
  });
  if (logsStore.length > MAX_LOG_ENTRIES) {
    logsStore.length = MAX_LOG_ENTRIES;
  }
  schedulePersistLogs();
  scheduleLogsChanged();
}

window.addEventListener("beforeunload", () => {
  flushPersistLogs();
  flushNotifyLogsChanged();
});

const Api = {
  setStatus(msg) {
    const text = normalizeLogMessage(msg);
    const el = document.getElementById("status");
    if (el) el.textContent = text;
    appendLog(text);
  },

  async ping() {
    return window.ssi.ping();
  },

  wallet: {
    create: (walletPath, pass) => window.ssi.wallet.create(walletPath, pass),
    open: (walletPath, pass) => window.ssi.wallet.open(walletPath, pass),
    close: () => window.ssi.wallet.close(),
    changePass: (walletPath, oldPass, newPass) => window.ssi.wallet.changePass(walletPath, oldPass, newPass),
    pickPath: (mode) => window.ssi.wallet.pickPath(mode),
    lock: () => window.ssi.wallet.lock(),
    info: (walletPath) => window.ssi.wallet.info(walletPath),
    getSession: () => window.ssi.wallet.getSession()
  },

  ledger: {
    connect: (genesisPath) => window.ssi.ledger.connect(genesisPath),
    health: () => window.ssi.ledger.health()
  },

  attrib: {
    writeOnLedger: (genesisPath, did, key, value) =>
      window.ssi.attrib.writeOnLedger(genesisPath, did, key, value),
    readFromLedger: (genesisPath, did, key) =>
      window.ssi.attrib.readFromLedger(genesisPath, did, key),
    checkExists: (genesisPath, did, key) =>
      window.ssi.attrib.checkExists(genesisPath, did, key),
  },

  did: {
    createOwn: () => window.ssi.did.createOwn(),
    storeTheir: (did, verkey, alias) => window.ssi.did.storeTheir(did, verkey, alias),
    list: (category) => window.ssi.did.list(category),
    exportBatch: (opts) => window.ssi.did.exportBatch(opts),
    importBatch: (opts) => window.ssi.did.importBatch(opts),
    importTrustee: (seed) => window.ssi.did.importTrustee(seed),
    registerOnLedger: (genesisPath, submitterDid, targetDid, verkey, role) =>
      window.ssi.did.registerOnLedger(genesisPath, submitterDid, targetDid, verkey, role),
    exportFile: () => window.ssi.did.exportFile(),
    importFile: () => window.ssi.did.importFile(),
  },

  schema: {
    buildPreview: (name, version, attrNames, revocable) =>
      window.ssi.schema.buildPreview(name, version, attrNames, revocable),
    saveLocal: (name, version, attrNames, revocable, envLabel) =>
      window.ssi.schema.saveLocal(name, version, attrNames, revocable, envLabel),
    listLocal: (onLedger, envFilter, nameEq) =>
      window.ssi.schema.listLocal(onLedger, envFilter, nameEq),
    getLocal: (idLocal) => window.ssi.schema.getLocal(idLocal),
    deleteLocal: (idLocal) => window.ssi.schema.deleteLocal(idLocal),
    registerFromLocal: (genesisPath, idLocal, issuerDidOpt) =>
      window.ssi.schema.registerFromLocal(genesisPath, idLocal, issuerDidOpt),
    createAndRegister: (genesisPath, issuerDid, name, version, attrNames) =>
      window.ssi.schema.createAndRegister(genesisPath, issuerDid, name, version, attrNames),
    fetchFromLedger: (genesisPath, schemaId) =>
      window.ssi.schema.fetchFromLedger(genesisPath, schemaId),
  },

  creddef: {
    saveLocal: (issuerDid, schemaId, tag, supportRevocation, envLabel) =>
      window.ssi.creddef.saveLocal(issuerDid, schemaId, tag, supportRevocation, envLabel),
    listLocal: (onLedger, envFilter, issuerDidEq, schemaIdEq, tagEq) =>
      window.ssi.creddef.listLocal(onLedger, envFilter, issuerDidEq, schemaIdEq, tagEq),
    getLocal: (idLocal) => window.ssi.creddef.getLocal(idLocal),
    deleteLocal: (idLocal) => window.ssi.creddef.deleteLocal(idLocal),
    registerFromLocal: (genesisPath, idLocal, issuerDidOpt) =>
      window.ssi.creddef.registerFromLocal(genesisPath, idLocal, issuerDidOpt),
    createAndRegister: (genesisPath, issuerDid, schemaId, tag) =>
      window.ssi.creddef.createAndRegister(genesisPath, issuerDid, schemaId, tag),
    fetchFromLedger: (genesisPath, credDefId) =>
      window.ssi.creddef.fetchFromLedger(genesisPath, credDefId),
  },

  credOffer: {
    exportEnvelope: (input) => window.ssi.credOffer.exportEnvelope(input),
  },

  credAccept: {
    importOfferEnvelope: (input) => window.ssi.credAccept.importOfferEnvelope(input),
    exportRequestEnvelope: (input) => window.ssi.credAccept.exportRequestEnvelope(input),
  },

  credCreate: {
    importRequestEnvelope: (input) => window.ssi.credCreate.importRequestEnvelope(input),
    loadSchemaTemplate: (input) => window.ssi.credCreate.loadSchemaTemplate(input),
    exportCredentialEnvelope: (input) => window.ssi.credCreate.exportCredentialEnvelope(input),
  },

  credReceive: {
    importAndStoreEnvelope: (input) => window.ssi.credReceive.importAndStoreEnvelope(input),
  },

  credential: {
    list: (schemaIdEq, credDefIdEq) => window.ssi.credential.list(schemaIdEq, credDefIdEq),
  },

  presentation: {
    createExportEnvelope: (input) => window.ssi.presentation.createExportEnvelope(input),
    verifyImportEnvelope: (input) => window.ssi.presentation.verifyImportEnvelope(input),
    storeLocal: (input) => window.ssi.presentation.storeLocal(input),
    listLocal: () => window.ssi.presentation.listLocal(),
    getLocal: (presentationIdLocal) => window.ssi.presentation.getLocal(presentationIdLocal),
    exportStoredEnvelope: (input) => window.ssi.presentation.exportStoredEnvelope(input),
  },

  logs: {
    list: () => getLogsSnapshot(),
    clear: () => {
      logsStore.length = 0;
      schedulePersistLogs();
      scheduleLogsChanged();
      return true;
    },
    remove: (id) => {
      const key = String(id || "");
      const idx = logsStore.findIndex((it) => it.id === key);
      if (idx < 0) return false;
      logsStore.splice(idx, 1);
      schedulePersistLogs();
      scheduleLogsChanged();
      return true;
    },
    subscribe: (handler) => {
      if (typeof handler !== "function") return () => {};
      logSubscribers.add(handler);
      return () => logSubscribers.delete(handler);
    },
  },
};
