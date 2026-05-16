/*
PARA RODAR:
cd /home/yugi/programacao/ssi_napi_lib
RESET_WALLET=1 \
WALLET_PASS="minha_senha_teste" \
GENESIS_FILE=./von_genesis.txn \
BFILTER_BASE_URL="http://127.0.0.1:8080" \
BFILTER_ADMIN_TOKEN="dev-admin-token" \
TRUSTEE_SEED="000000000000000000000000Trustee1" \
TRUSTEE_DID="V4SGRU86Z58d6TV7PBUe6f" \
node teste-node/revocation/test_revocation_44_revocation_boundary_from_window_10_von.js

Para subir o bfilter:
cd /home/yugi/programacao/bfilter
BFILTER_ADMIN_TOKEN="dev-admin-token" cargo run
*/

/*
Teste E2E de fronteira de revogação a partir da janela 10.

Objetivo:
- garantir explicitamente que, ao revogar na janela 10:
  - janelas 1..9 continuam válidas;
  - janela 10 e todas as posteriores tornam-se inválidas.

Estratégia:
- emitir 1 credencial normal e 2 revogáveis com 365 janelas válidas diárias e 10 extras de confirmação;
- montar/verificar pacotes para:
  - todas as janelas 1..9
  - a janela 10
  - algumas posteriores representativas: 11, 30, 90, 364
- revogar a primeira credencial revogável a partir da janela 10;
- revalidar todas essas janelas e confirmar o comportamento esperado.

Depois da revogação, o teste reancora o manifesto atualizado do Bloom
antes de revalidar as janelas.
*/

const crypto = require("crypto");
const path = require("path");
const {
  NETWORK_CONFIG,
  assert,
  downloadGenesisHttp,
  loadIndyAgent,
  fn,
  walletCreateOpenIdempotent,
  parseJsonSafe,
  extractNonce,
  cleanupWalletFamily,
  ensureWalletDir,
} = require("./_helpers");

const CONTROL_ATTRS = [
  "seed",
  "start_time",
  "unit_of_time",
  "time_window",
  "root_merkle_L",
];

const VALID_WINDOWS_BEFORE = [1, 2, 3, 4, 5, 6, 7, 8, 9];
const INVALID_WINDOWS_AFTER = [10, 11, 30, 90, 364];

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function sha256Base64(input) {
  return crypto.createHash("sha256").update(input).digest("base64");
}

async function tryRegisterDid(agent, genesisFile, submitterDid, did, verkey, role) {
  try {
    await agent.registerDidOnLedger(genesisFile, submitterDid, did, verkey, role);
  } catch (e) {
    const msg = e?.message || String(e);
    if (/already exists|exists|DID.*exist|NYM.*exist|Ledger/i.test(msg)) {
      console.log(`ℹ️ DID já estava no ledger, seguindo: ${did}`);
      return;
    }
    throw e;
  }
}

async function fetchManifestEnvelope(baseUrl) {
  const resp = await fetch(`${baseUrl}/manifest`);
  assert(resp.ok, `Falha GET /manifest: ${resp.status}`);
  const manifestBodyText = await resp.text();
  const envelope = JSON.parse(manifestBodyText);
  assert(envelope.ok === true, "manifesto Bloom deveria retornar ok=true");
  envelope.manifest_hash_body = sha256Base64(manifestBodyText);
  return envelope;
}

(async () => {
  const IndyAgent = loadIndyAgent();
  const pass = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET = process.env.RESET_WALLET === "1";
  const BFILTER_BASE_URL = process.env.BFILTER_BASE_URL || "http://127.0.0.1:8080";
  const BFILTER_ADMIN_TOKEN = process.env.BFILTER_ADMIN_TOKEN || "dev-admin-token";
  const TRUSTEE_SEED = process.env.TRUSTEE_SEED || NETWORK_CONFIG.trusteeSeed;
  const TRUSTEE_DID = process.env.TRUSTEE_DID || NETWORK_CONFIG.trusteeDid;

  const walletDir = ensureWalletDir();
  const issuerDb =
    process.env.WALLET_ISSUER || path.join(walletDir, "test_wallet_revocation_boundary10_issuer.db");
  const holderDb =
    process.env.WALLET_HOLDER || path.join(walletDir, "test_wallet_revocation_boundary10_holder.db");
  const verifierDb =
    process.env.WALLET_VERIFIER || path.join(walletDir, "test_wallet_revocation_boundary10_verifier.db");

  const genesisAbs = path.join(process.cwd(), process.env.GENESIS_FILE || NETWORK_CONFIG.genesisFile);
  await downloadGenesisHttp(NETWORK_CONFIG.genesisUrl, genesisAbs);

  if (RESET) {
    cleanupWalletFamily(issuerDb);
    cleanupWalletFamily(holderDb);
    cleanupWalletFamily(verifierDb);
  }

  const issuer = new IndyAgent();
  const holder = new IndyAgent();
  const verifier = new IndyAgent();

  await walletCreateOpenIdempotent(issuer, issuerDb, pass);
  await walletCreateOpenIdempotent(holder, holderDb, pass);
  await walletCreateOpenIdempotent(verifier, verifierDb, pass);

  try {
    await issuer.connectNetwork(genesisAbs);
    await holder.connectNetwork(genesisAbs);
    await verifier.connectNetwork(genesisAbs);

    const importDidFromSeed = fn(issuer, "importDidFromSeed", "import_did_from_seed");
    const createAndRegisterSchema = fn(issuer, "createAndRegisterSchema", "create_and_register_schema");
    const creddefSaveLocal = fn(issuer, "creddefSaveLocal", "creddef_save_local");
    const creddefRegisterFromLocal = fn(issuer, "creddefRegisterFromLocal", "creddef_register_from_local");
    const fetchSchemaFromLedger = fn(issuer, "fetchSchemaFromLedger", "fetch_schema_from_ledger");
    const fetchCredDefFromLedger = fn(issuer, "fetchCredDefFromLedger", "fetch_cred_def_from_ledger");
    const createCredentialOffer = fn(issuer, "createCredentialOffer", "create_credential_offer");
    const createCredential = fn(issuer, "createCredential", "create_credential");
    const createCredentialRequest = fn(holder, "createCredentialRequest", "create_credential_request");
    const createLinkSecret = fn(holder, "createLinkSecret", "create_link_secret");
    const storeCredential = fn(holder, "storeCredential", "store_credential");
    const revocationBuildManifestAnchor = fn(issuer, "revocationBuildManifestAnchor", "revocation_build_manifest_anchor");
    const revocationWriteManifestAnchorOnLedger = fn(issuer, "revocationWriteManifestAnchorOnLedger", "revocation_write_manifest_anchor_on_ledger");
    const issueRevocableCredential = fn(issuer, "issueRevocableCredential", "issue_revocable_credential");
    const storeReceivedRevocableCredential = fn(holder, "storeReceivedRevocableCredential", "store_received_revocable_credential");
    const createPresentationPackageWithRevocation = fn(
      holder,
      "createPresentationPackageWithRevocation",
      "create_presentation_package_with_revocation"
    );
    const verifyMixedPresentationPackage = fn(
      verifier,
      "verifyMixedPresentationPackage",
      "verify_mixed_presentation_package"
    );
    const preflightRevokeIssuedCredential = fn(
      issuer,
      "preflightRevokeIssuedCredential",
      "preflight_revoke_issued_credential"
    );
    const revokeIssuedCredentialFromWindow = fn(
      issuer,
      "revokeIssuedCredentialFromWindow",
      "revoke_issued_credential_from_window"
    );

    console.log("🚀 TESTE REVOGAÇÃO 44: fronteira de revogação a partir da janela 10");

    const [trusteeDid] = await importDidFromSeed(TRUSTEE_SEED);
    assert(trusteeDid === TRUSTEE_DID, `Trustee DID inesperado: ${trusteeDid}`);

    const [issuerDid, issuerVerkey] = await issuer.createOwnDid();
    const [holderDid, holderVerkey] = await holder.createOwnDid();
    const [verifierDid, verifierVerkey] = await verifier.createOwnDid();

    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, issuerDid, issuerVerkey, "ENDORSER");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, holderDid, holderVerkey, "ENDORSER");
    await tryRegisterDid(issuer, genesisAbs, TRUSTEE_DID, verifierDid, verifierVerkey, "ENDORSER");

    const manifestEnvelope = await fetchManifestEnvelope(BFILTER_BASE_URL);
    const manifestHash = manifestEnvelope.manifest_hash_body;
    const manifestJson = await revocationBuildManifestAnchor(
      issuerDid,
      `${BFILTER_BASE_URL}/manifest`,
      manifestHash,
      String(manifestEnvelope.manifest.version || 1)
    );
    const manifest = parseJsonSafe(manifestJson, "manifest_anchor");
    parseJsonSafe(
      await revocationWriteManifestAnchorOnLedger(genesisAbs, issuerDid, JSON.stringify(manifest)),
      "write_manifest"
    );

    const schemaIdNormal = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaNormalBoundary10_${Date.now()}`,
      `1.${nowSec()}`,
      ["nome", "matricula", "curso"]
    );
    const schemaIdRev1 = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRevBoundary10_1_${Date.now()}`,
      `1.${nowSec() + 1}`,
      ["nome", "cpf", "idade", ...CONTROL_ATTRS]
    );
    const schemaIdRev2 = await createAndRegisterSchema(
      genesisAbs,
      issuerDid,
      `SchemaRevBoundary10_2_${Date.now()}`,
      `1.${nowSec() + 2}`,
      ["email", "telefone", ...CONTROL_ATTRS]
    );

    async function registerCredDef(schemaId, tag) {
      const localJson = await creddefSaveLocal(issuerDid, schemaId, tag, false, "prod");
      const local = parseJsonSafe(localJson, `creddef_local_${tag}`);
      const reg = await creddefRegisterFromLocal(genesisAbs, local.id_local, issuerDid);
      return reg.credDefId || reg.cred_def_id;
    }

    const credDefIdNormal = await registerCredDef(schemaIdNormal, `TAG_NORMAL_BOUNDARY10_${Date.now()}`);
    const credDefIdRev1 = await registerCredDef(schemaIdRev1, `TAG_REV1_BOUNDARY10_${Date.now()}`);
    const credDefIdRev2 = await registerCredDef(schemaIdRev2, `TAG_REV2_BOUNDARY10_${Date.now()}`);

    const schemaNormalLedger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdNormal), "schema_normal");
    const schemaRev1Ledger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdRev1), "schema_rev1");
    const schemaRev2Ledger = parseJsonSafe(await fetchSchemaFromLedger(genesisAbs, schemaIdRev2), "schema_rev2");
    const credDefNormalLedger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdNormal), "creddef_normal");
    const credDefRev1Ledger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdRev1), "creddef_rev1");
    const credDefRev2Ledger = parseJsonSafe(await fetchCredDefFromLedger(genesisAbs, credDefIdRev2), "creddef_rev2");

    try {
      await createLinkSecret("default");
    } catch (_) {}

    const offerNormalJson = await createCredentialOffer(credDefIdNormal, `offer-normal-boundary10-${Date.now()}`);
    const requestNormalJson = await createCredentialRequest(
      "default",
      holderDid,
      JSON.stringify(credDefNormalLedger),
      offerNormalJson
    );
    const requestNormalMetadataId = extractNonce(offerNormalJson);
    const normalCredentialJson = await createCredential(
      credDefIdNormal,
      offerNormalJson,
      requestNormalJson,
      JSON.stringify({
        nome: "Alice Normal",
        matricula: "2026001",
        curso: "Computacao",
      })
    );
    const normalCredentialId = `cred-normal-boundary10-${Date.now()}`;
    await storeCredential(
      normalCredentialId,
      normalCredentialJson,
      requestNormalMetadataId,
      JSON.stringify(credDefNormalLedger),
      null
    );

    const startTime = nowSec();
    const validityEnd = startTime + 86400 * 364;

    async function issueAndStoreRevocable({
      issuerLocalCredentialId,
      credentialId,
      bundleId,
      credDefId,
      schemaId,
      credDefLedger,
      values,
    }) {
      const offerJson = await createCredentialOffer(credDefId, `offer-${issuerLocalCredentialId}`);
      const requestJson = await createCredentialRequest(
        "default",
        holderDid,
        JSON.stringify(credDefLedger),
        offerJson
      );
      const requestMetadataId = extractNonce(offerJson);
      const issued = parseJsonSafe(
        await issueRevocableCredential(
          genesisAbs,
          issuerLocalCredentialId,
          holderDid,
          credDefId,
          schemaId,
          offerJson,
          requestJson,
          JSON.stringify(values),
          startTime,
          validityEnd,
          "days",
          1,
          10,
          JSON.stringify(manifest),
          null,
          null
        ),
        `issued_${issuerLocalCredentialId}`
      );

      await storeCredential(
        credentialId,
        issued.credential_json,
        requestMetadataId,
        JSON.stringify(credDefLedger),
        null
      );
      parseJsonSafe(
        await storeReceivedRevocableCredential(bundleId, JSON.stringify(issued.holder_bundle), credentialId),
        `store_bundle_${issuerLocalCredentialId}`
      );
    }

    const rev1CredentialId = `cred-rev1-boundary10-${Date.now()}`;
    const rev2CredentialId = `cred-rev2-boundary10-${Date.now()}`;
    const rev1IssuerLocalId = `issued-rev1-boundary10-${Date.now()}`;
    const rev2IssuerLocalId = `issued-rev2-boundary10-${Date.now()}`;

    await issueAndStoreRevocable({
      issuerLocalCredentialId: rev1IssuerLocalId,
      credentialId: rev1CredentialId,
      bundleId: `bundle-rev1-boundary10-${Date.now()}`,
      credDefId: credDefIdRev1,
      schemaId: schemaIdRev1,
      credDefLedger: credDefRev1Ledger,
      values: { nome: "Alice Revogavel 1", cpf: "12345678900", idade: "29" },
    });

    await issueAndStoreRevocable({
      issuerLocalCredentialId: rev2IssuerLocalId,
      credentialId: rev2CredentialId,
      bundleId: `bundle-rev2-boundary10-${Date.now()}`,
      credDefId: credDefIdRev2,
      schemaId: schemaIdRev2,
      credDefLedger: credDefRev2Ledger,
      values: { email: "alice@example.org", telefone: "+5511999999999" },
    });

    const presReq = {
      nonce: String(Date.now() * 1000 + 55123),
      name: "ProofReqBoundary10",
      version: "0.1",
      requested_attributes: {
        attr_normal_nome: { name: "nome", restrictions: [{ cred_def_id: credDefIdNormal }] },
        attr_rev1_nome: { name: "nome", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_rev1_seed: { name: "seed", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_rev1_start: { name: "start_time", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_rev1_unit: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_rev1_window: { name: "time_window", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_rev1_root: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefIdRev1 }] },
        attr_rev2_email: { name: "email", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_rev2_seed: { name: "seed", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_rev2_start: { name: "start_time", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_rev2_unit: { name: "unit_of_time", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_rev2_window: { name: "time_window", restrictions: [{ cred_def_id: credDefIdRev2 }] },
        attr_rev2_root: { name: "root_merkle_L", restrictions: [{ cred_def_id: credDefIdRev2 }] },
      },
      requested_predicates: {},
    };

    const reqCreds = {
      requested_attributes: {
        attr_normal_nome: { cred_id: normalCredentialId, revealed: true },
        attr_rev1_nome: { cred_id: rev1CredentialId, revealed: true },
        attr_rev1_seed: { cred_id: rev1CredentialId, revealed: true },
        attr_rev1_start: { cred_id: rev1CredentialId, revealed: true },
        attr_rev1_unit: { cred_id: rev1CredentialId, revealed: true },
        attr_rev1_window: { cred_id: rev1CredentialId, revealed: true },
        attr_rev1_root: { cred_id: rev1CredentialId, revealed: true },
        attr_rev2_email: { cred_id: rev2CredentialId, revealed: true },
        attr_rev2_seed: { cred_id: rev2CredentialId, revealed: true },
        attr_rev2_start: { cred_id: rev2CredentialId, revealed: true },
        attr_rev2_unit: { cred_id: rev2CredentialId, revealed: true },
        attr_rev2_window: { cred_id: rev2CredentialId, revealed: true },
        attr_rev2_root: { cred_id: rev2CredentialId, revealed: true },
      },
      requested_predicates: {},
    };

    const schemasMap = {
      [schemaIdNormal]: schemaNormalLedger,
      [schemaIdRev1]: schemaRev1Ledger,
      [schemaIdRev2]: schemaRev2Ledger,
    };
    const credDefsMap = {
      [credDefIdNormal]: credDefNormalLedger,
      [credDefIdRev1]: credDefRev1Ledger,
      [credDefIdRev2]: credDefRev2Ledger,
    };

    async function verifyForWindow(windowIndex, manifestOverride = null) {
      const presentationPackage = parseJsonSafe(
        await createPresentationPackageWithRevocation(
          JSON.stringify(presReq),
          JSON.stringify(reqCreds),
          JSON.stringify(schemasMap),
          JSON.stringify(credDefsMap),
          JSON.stringify([
            { credential_id_local: rev1CredentialId, window_index: windowIndex },
            { credential_id_local: rev2CredentialId, window_index: windowIndex },
          ])
        ),
        `presentation_package_${windowIndex}`
      );
      const revocationProofsForVerification = presentationPackage.revocation_proofs.map((item) => ({
        credential_id_local: item.credential_id_local,
        proof: manifestOverride
          ? {
              ...item.proof,
              manifest: manifestOverride,
            }
          : item.proof,
      }));

      return parseJsonSafe(
        await verifyMixedPresentationPackage(
          JSON.stringify(presReq),
          presentationPackage.presentation_json,
          JSON.stringify(schemasMap),
          JSON.stringify(credDefsMap),
          JSON.stringify(revocationProofsForVerification),
          null
        ),
        `verification_${windowIndex}`
      );
    }

    console.log("1) Confirmando que 1..9 são válidas antes da revogação...");
    for (const windowIndex of VALID_WINDOWS_BEFORE) {
      const result = await verifyForWindow(windowIndex);
      assert(result.cryptographic_valid === true, `janela ${windowIndex} deveria ser criptograficamente válida`);
      assert(result.proofs_verified === true, `janela ${windowIndex} deveria verificar`);
      assert(result.revoked === false, `janela ${windowIndex} não deveria estar revogada antes`);
      assert(result.accepted === true, `janela ${windowIndex} deveria ser aceita antes`);
    }

    console.log("2) Confirmando que 10 e janelas posteriores também são válidas antes da revogação...");
    for (const windowIndex of INVALID_WINDOWS_AFTER) {
      const result = await verifyForWindow(windowIndex);
      assert(result.cryptographic_valid === true, `janela ${windowIndex} deveria ser criptograficamente válida`);
      assert(result.proofs_verified === true, `janela ${windowIndex} deveria verificar`);
      assert(result.revoked === false, `janela ${windowIndex} não deveria estar revogada antes`);
      assert(result.accepted === true, `janela ${windowIndex} deveria ser aceita antes`);
    }

    console.log("3) Revogando a partir da janela 10...");
    const preflight = parseJsonSafe(
      await preflightRevokeIssuedCredential(rev1IssuerLocalId, 10),
      "preflight_boundary10"
    );
    assert(preflight.ok === true, "preflight deveria retornar ok=true");
    assert(preflight.can_revoke === true, "preflight deveria permitir revogação");
    assert(preflight.preflight.revocation_keys_to_write === 365, "deveria haver 365 chaves da janela 10 até a 374");

    const revoke = parseJsonSafe(
      await revokeIssuedCredentialFromWindow(
        rev1IssuerLocalId,
        BFILTER_ADMIN_TOKEN,
        10,
        "revogacao-fronteira-10",
        "teste-node"
      ),
      "revoke_boundary10"
    );
    assert(revoke.ok === true, "revogação deveria retornar ok=true");
    assert(revoke.revocation_keys_written === 365, "a revogação deveria gravar 365 chaves");

    const manifestAfterRevoke = await fetchManifestEnvelope(BFILTER_BASE_URL);
    const manifestAfterJson = await revocationBuildManifestAnchor(
      issuerDid,
      `${BFILTER_BASE_URL}/manifest`,
      manifestAfterRevoke.manifest_hash_body,
      String(manifestAfterRevoke.manifest.version || 1)
    );
    const writeManifestAfter = parseJsonSafe(
      await revocationWriteManifestAnchorOnLedger(genesisAbs, issuerDid, manifestAfterJson),
      "write_manifest_after"
    );
    assert(writeManifestAfter.ok === true, "reanchor do manifesto após revogação falhou");

    console.log("4) Confirmando que 1..9 continuam válidas após a revogação...");
    for (const windowIndex of VALID_WINDOWS_BEFORE) {
      const result = await verifyForWindow(windowIndex, writeManifestAfter.manifest);
      const rev1Status = result.per_credential_status.find((item) => item.credential_id_local === rev1CredentialId);
      assert(result.cryptographic_valid === true, `janela ${windowIndex} deve continuar criptograficamente válida`);
      assert(result.proofs_verified === true, `janela ${windowIndex} deve continuar verificando`);
      assert(result.revoked === false, `janela ${windowIndex} não deveria ser consolidada como revogada`);
      assert(result.accepted === true, `janela ${windowIndex} deve continuar aceita`);
      assert(rev1Status && rev1Status.revoked === false, `rev1 não deveria estar revogada na janela ${windowIndex}`);
    }

    console.log("5) Confirmando que 10 e posteriores tornam-se inválidas...");
    for (const windowIndex of INVALID_WINDOWS_AFTER) {
      const result = await verifyForWindow(windowIndex, writeManifestAfter.manifest);
      const rev1Status = result.per_credential_status.find((item) => item.credential_id_local === rev1CredentialId);
      assert(result.cryptographic_valid === true, `janela ${windowIndex} deve continuar criptograficamente válida`);
      assert(result.proofs_verified === true, `janela ${windowIndex} deve continuar com provas válidas`);
      assert(result.revoked === true, `janela ${windowIndex} deveria estar revogada`);
      assert(result.accepted === false, `janela ${windowIndex} deveria ser rejeitada`);
      assert(rev1Status && rev1Status.revoked === true, `rev1 deveria estar revogada na janela ${windowIndex}`);
    }

    console.log("✅ OK: TESTE REVOGAÇÃO 44 passou.");
  } finally {
    try { await issuer.walletClose(); } catch {}
    try { await holder.walletClose(); } catch {}
    try { await verifier.walletClose(); } catch {}
  }
})().catch((e) => {
  console.error("❌ FALHA TESTE REVOGAÇÃO 44:", e && e.stack ? e.stack : e);
  process.exit(1);
});
