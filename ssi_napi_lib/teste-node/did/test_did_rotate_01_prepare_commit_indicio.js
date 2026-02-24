/*
PARA RODAR ESTE TESTE (INDICIO TESTNET) — ROTATE VERKEY (prepare+commit):
WALLET_PASS="minha_senha_teste" RESET_WALLET=1 \
SUBMITTER_SEED="+0HGyElhOr/GuwUaDsyiTn926bFMrBUh" \
SUBMITTER_DID="7DffLFWsgrwbt7T1Ni9cmu" \
node teste-node/did/test_did_rotate_01_prepare_commit_indicio.js

PRÉ-REQ:
- ./indicio_testnet.txn deve existir (ou o teste baixa via genesisUrl).
- O submitter (Endorser) é usado APENAS para registrar o DID inicialmente.
- A rotação de verkey é assinada pelo PRÓPRIO DID (owner), como exige o Indy.
- resolveDidOnLedger* na sua lib recebe APENAS (did), não recebe genesis_file.
*/

/* eslint-disable no-console */
const fs = require("fs");
const path = require("path");
const https = require("https");

const { IndyAgent } = require(path.join(__dirname, "..", "..", "index.node"));

// -----------------------
// Helpers básicos
// -----------------------
function rmIfExists(walletDbPath) {
  const sidecar = `${walletDbPath}.kdf.json`;
  try { fs.unlinkSync(walletDbPath); } catch (_) {}
  try { fs.unlinkSync(sidecar); } catch (_) {}
  try { fs.unlinkSync(`${sidecar}.tmp`); } catch (_) {}
  try { fs.unlinkSync(`${walletDbPath}-shm`); } catch (_) {}
  try { fs.unlinkSync(`${walletDbPath}-wal`); } catch (_) {}
}

function must(cond, msg) {
  if (!cond) throw new Error(msg);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function retry(label, fn, attempts = 14, baseDelayMs = 900) {
  let lastErr;
  for (let i = 1; i <= attempts; i++) {
    try {
      return await fn();
    } catch (e) {
      lastErr = e;
      const wait = Math.min(baseDelayMs * i, 9000);
      console.log(`⏳ retry(${label}) ${i}/${attempts} falhou; aguardando ${wait}ms...`);
      await sleep(wait);
    }
  }
  throw lastErr;
}

// -----------------------
// Genesis (download if missing)
// -----------------------
function downloadToFile(url, filePath) {
  return new Promise((resolve, reject) => {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const file = fs.createWriteStream(filePath, { encoding: "utf8" });

    https.get(url, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`Falha download genesis: HTTP ${res.statusCode}`));
        return;
      }
      res.setEncoding("utf8");
      res.pipe(file);
      file.on("finish", () => file.close(resolve));
    }).on("error", (err) => {
      try { fs.unlinkSync(filePath); } catch (_) {}
      reject(err);
    });
  });
}

async function ensureGenesis(genesisUrl, genesisFile) {
  console.log("0) Garantindo genesis da Indicio...");
  if (fs.existsSync(genesisFile)) {
    console.log(`📂 Genesis já existe: ${genesisFile}`);
    return;
  }
  console.log(`⬇️ Baixando genesis: ${genesisUrl}`);
  await downloadToFile(genesisUrl, genesisFile);
  console.log(`✅ Genesis salvo em: ${genesisFile}`);
}

// -----------------------
// Ledger: register DID (ignore if exists)
// -----------------------
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

// -----------------------
// Resolve DID (na sua lib recebe APENAS did)
// -----------------------
async function resolveDidJson(agent, did) {
  try {
    return await agent.resolveDidOnLedgerV2(did);
  } catch (_) {
    return await agent.resolveDidOnLedger(did);
  }
}

function extractVerkeyFromResolve(raw) {
  try {
    const obj = JSON.parse(raw);

    // alguns retornos trazem result.data como string JSON
    let data = obj?.result?.data;
    if (typeof data === "string") {
      try { data = JSON.parse(data); } catch (_) {}
    }

    return obj?.verkey || obj?.data?.verkey || data?.verkey || null;
  } catch (_) {
    return null;
  }
}

// -----------------------
// MAIN
// -----------------------
(async () => {
  const WALLET_PASS = process.env.WALLET_PASS || "minha_senha_teste";
  const RESET_WALLET = String(process.env.RESET_WALLET || "0") === "1";

  const genesisUrl =
    "https://raw.githubusercontent.com/Indicio-tech/indicio-network/refs/heads/main/genesis_files/pool_transactions_testnet_genesis";
  const genesisFile = "./indicio_testnet.txn";

  // DADOS DO SUBMITTER (ENDORSER / ISSUER) — usado só para registrar o DID
  const SUBMITTER_SEED = process.env.SUBMITTER_SEED || "+0HGyElhOr/GuwUaDsyiTn926bFMrBUh";
  const SUBMITTER_DID  = process.env.SUBMITTER_DID  || "7DffLFWsgrwbt7T1Ni9cmu";

  await ensureGenesis(genesisUrl, genesisFile);

  const walletsDir = path.join(__dirname, "..", "wallets");
  fs.mkdirSync(walletsDir, { recursive: true });

  const issuerWalletPath = path.join(walletsDir, "did_rotate_indicio_issuer.db");
  const holderWalletPath = path.join(walletsDir, "did_rotate_indicio_holder.db");

  if (RESET_WALLET) {
    console.log("🧹 RESET_WALLET=1: removendo wallet artifacts...");
    rmIfExists(issuerWalletPath);
    rmIfExists(holderWalletPath);
  }

  const issuer = new IndyAgent();
  const holder = new IndyAgent();

  try {
    console.log("1) Criando wallets...");
    await issuer.walletCreate(issuerWalletPath, WALLET_PASS);
    await holder.walletCreate(holderWalletPath, WALLET_PASS);

    console.log("2) Abrindo wallets...");
    await issuer.walletOpen(issuerWalletPath, WALLET_PASS);
    await holder.walletOpen(holderWalletPath, WALLET_PASS);

    console.log("3) Conectando na rede (Indicio)...");
    await issuer.connectNetwork(genesisFile);
    await holder.connectNetwork(genesisFile);

    console.log("4) Importando SUBMITTER DID no issuer (Endorser)...");
    await issuer.importDidFromSeed(SUBMITTER_SEED);

    const submitterDidJson = await issuer.getDid(SUBMITTER_DID);
    const submitterDidObj = JSON.parse(submitterDidJson);
    const issuerDid = SUBMITTER_DID;
    const issuerVerkey = submitterDidObj?.verkey;
    must(issuerVerkey, "Não consegui obter verkey do SUBMITTER via getDid().");

    console.log("5) Criando DID do holder...");
    const [holderDid, holderVerkey] = await holder.createOwnDid();
    must(holderDid && holderVerkey, "createOwnDid não retornou did/verkey.");

    console.log("Holder DID....:", holderDid);
    console.log("Holder Verkey.:", holderVerkey);

    console.log("6) Registrando DID do holder no ledger via SUBMITTER (NYM role=null)...");
    await tryRegisterDid(issuer, genesisFile, issuerDid, holderDid, holderVerkey, null);

    console.log("7) Aguardando consistência do ledger após NYM inicial...");
    await sleep(3500);

    console.log("8) Resolvendo DID no ledger para validar verkey inicial...");
    const raw0 = await retry("resolveVk0", () => resolveDidJson(holder, holderDid), 16, 900);
    const ledgerVk0 = extractVerkeyFromResolve(raw0);
    must(ledgerVk0, `Não consegui extrair verkey do resolve inicial. raw=${raw0}`);
    must(
      ledgerVk0.includes(holderVerkey.slice(0, 10)),
      `Ledger verkey inicial inesperada. ledgerVk0=${ledgerVk0} holderVerkey=${holderVerkey}`
    );

    // ------------------------------------------------------------
    // ROTATE PREPARE (holder)
    // ------------------------------------------------------------
    console.log("9) rotateDidVerkeyPrepare (holder)...");
    const prepOutJson = await holder.rotateDidVerkeyPrepare(
      holderDid,
      JSON.stringify({ reason: "scheduled", keepOldKeys: true })
    );

    const prepOut = JSON.parse(prepOutJson);
    must(prepOut.ok === true, "prepare não retornou ok=true");
    const pendingVerkey = prepOut.pendingVerkey;
    must(pendingVerkey && typeof pendingVerkey === "string", "prepare não retornou pendingVerkey");

    console.log("   currentVerkey:", prepOut.currentVerkey);
    console.log("   pendingVerkey:", pendingVerkey);

    console.log("10) Validando did_vk para pendingVerkey (getDidByVerkey)...");
    const byPendingJson = await holder.getDidByVerkey(pendingVerkey);
    const byPending = JSON.parse(byPendingJson);
    must(byPending.did === holderDid, "getDidByVerkey(pending) não retornou o DID correto");

    // ------------------------------------------------------------
    // ROTATE COMMIT: deve ser assinado pelo owner (holderDid)
    // ------------------------------------------------------------
    console.log("11) rotateDidVerkeyCommit (holder -> ledger), assinando como o PRÓPRIO DID (owner)...");
    const commitOutJson = await holder.rotateDidVerkeyCommit(
      genesisFile,
      holderDid,
      JSON.stringify({
        submitterDid: holderDid, // ✅ owner
        role: null,
        force: true
      })
    );

    const commitOut = JSON.parse(commitOutJson);
    must(commitOut.ok === true, "commit não retornou ok=true");
    const newVerkey = commitOut.newVerkey;
    const oldVerkey = commitOut.oldVerkey;
    must(newVerkey && oldVerkey, "commit não retornou oldVerkey/newVerkey");
    must(newVerkey === pendingVerkey, "newVerkey != pendingVerkey (inconsistência)");

    console.log("   oldVerkey:", oldVerkey);
    console.log("   newVerkey:", newVerkey);

    console.log("12) Aguardando consistência do ledger após rotação...");
    await sleep(6500);

    console.log("13) Resolvendo no ledger (deve refletir newVerkey)...");
    const raw1 = await retry("resolveVk1", () => resolveDidJson(holder, holderDid), 20, 1000);
    const ledgerVk1 = extractVerkeyFromResolve(raw1);
    must(ledgerVk1, `Não consegui extrair verkey do resolve pós-rotação. raw=${raw1}`);
    must(
      ledgerVk1.includes(newVerkey.slice(0, 10)),
      `Ledger ainda não refletiu rotação. ledgerVk1=${ledgerVk1} newVerkey=${newVerkey}`
    );

    console.log("14) Validando que holder getDid retorna verkey nova...");
    const holderDidJson2 = await holder.getDid(holderDid);
    const holderDidObj2 = JSON.parse(holderDidJson2);
    must(holderDidObj2?.verkey === newVerkey, "getDid(holderDid) não atualizou para verkey nova");

    console.log("15) Validando did_vk para verkey antiga (getDidByVerkey)...");
    const byOldJson = await holder.getDidByVerkey(oldVerkey);
    const byOld = JSON.parse(byOldJson);
    must(byOld.did === holderDid, "getDidByVerkey(old) não retornou DID correto");

    console.log("✅ OK: rotação de verkey passou (Indicio) — prepare+commit + ledger + did_vk.");
  } finally {
    try { await issuer.walletClose(); } catch (_) {}
    try { await holder.walletClose(); } catch (_) {}
  }
})().catch((e) => {
  console.error("❌ FALHA NO TESTE:", e?.message || e);
  console.error(e?.stack || "");
  process.exit(1);
});
