module.exports = {
  APP_PING: "app:ping",

  WALLET_CREATE: "wallet:create",
  WALLET_OPEN: "wallet:open",
  WALLET_CLOSE: "wallet:close",
  WALLET_CHANGE_PASS: "wallet:changePass",
  WALLET_INFO: "wallet:info",
  WALLET_PICK_PATH: "wallet:pickPath",
  WALLET_GET_SESSION: "wallet:getSession",
  WALLET_VERIFY_PASS: "wallet:verifyPass",
  WALLET_LOCK: "wallet:lock",

  LEDGER_CONNECT: "ledger:connect",
  LEDGER_HEALTH: "ledger:health",
  ATTRIB_WRITE_ON_LEDGER: "attrib:writeOnLedger",
  ATTRIB_READ_FROM_LEDGER: "attrib:readFromLedger",
  ATTRIB_CHECK_EXISTS: "attrib:checkExists",

  DID_CREATE_OWN: "did:createOwn",
  DID_LIST: "did:list",
  DID_EXPORT_BATCH: "did:exportBatch",
  DID_IMPORT_BATCH: "did:importBatch",
  DID_REGISTER_ON_LEDGER: "did:registerOnLedger",
  DID_STORE_THEIR: "did:storeTheir",

  DID_IMPORT_TRUSTEE: "did:importTrustee",
  DID_REGISTER_ON_LEDGER: "did:registerOnLedger",

  DID_EXPORT_FILE: "did:exportFile",
  DID_IMPORT_FILE: "did:importFile",

  // -------------------------
  // Schemas
  // -------------------------
  SCHEMA_SAVE_LOCAL: "schema:saveLocal",
  SCHEMA_LIST_LOCAL: "schema:listLocal",
  SCHEMA_GET_LOCAL: "schema:getLocal",
  SCHEMA_DELETE_LOCAL: "schema:deleteLocal",
  SCHEMA_BUILD_PREVIEW: "schema:buildPreview",

  SCHEMA_REGISTER_FROM_LOCAL: "schema:registerFromLocal",
  SCHEMA_CREATE_AND_REGISTER: "schema:createAndRegister",
  SCHEMA_FETCH_FROM_LEDGER: "schema:fetchFromLedger",

  // -------------------------
  // CredDefs
  // -------------------------
  CREDDEF_SAVE_LOCAL: "creddef:saveLocal",
  CREDDEF_LIST_LOCAL: "creddef:listLocal",
  CREDDEF_GET_LOCAL: "creddef:getLocal",
  CREDDEF_DELETE_LOCAL: "creddef:deleteLocal",
  CREDDEF_REGISTER_FROM_LOCAL: "creddef:registerFromLocal",
  CREDDEF_CREATE_AND_REGISTER: "creddef:createAndRegister",
  CREDDEF_FETCH_FROM_LEDGER: "creddef:fetchFromLedger",

  CRED_OFFER_EXPORT_ENVELOPE: "credOffer:exportEnvelope",
  CRED_ACCEPT_IMPORT_OFFER_ENVELOPE: "credAccept:importOfferEnvelope",
  CRED_ACCEPT_EXPORT_REQUEST_ENVELOPE: "credAccept:exportRequestEnvelope",

  CRED_CREATE_IMPORT_REQUEST_ENVELOPE: "credCreate:importRequestEnvelope",
  CRED_CREATE_LOAD_SCHEMA_TEMPLATE: "credCreate:loadSchemaTemplate",
  CRED_CREATE_EXPORT_CREDENTIAL_ENVELOPE: "credCreate:exportCredentialEnvelope",

  CRED_RECEIVE_IMPORT_AND_STORE_ENVELOPE: "credReceive:importAndStoreEnvelope",

  CREDENTIAL_LIST: "credential:list",

  PRESENTATION_CREATE_EXPORT_ENVELOPE: "presentation:createExportEnvelope",
  PRESENTATION_VERIFY_IMPORT_ENVELOPE: "presentation:verifyImportEnvelope",
  PRESENTATION_STORE_LOCAL: "presentation:storeLocal",
  PRESENTATION_LIST_LOCAL: "presentation:listLocal",
  PRESENTATION_GET_LOCAL: "presentation:getLocal",
  PRESENTATION_EXPORT_STORED_ENVELOPE: "presentation:exportStoredEnvelope",
};
