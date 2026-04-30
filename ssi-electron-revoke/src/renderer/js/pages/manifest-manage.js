// src/renderer/js/pages/manifest-manage.js
/* eslint-disable no-console */

const ManifestManagePage = (() => {
  const root = document.getElementById("page-manifest-manage");
  if (!root) return {};

  const DEFAULT_MANIFEST_URL = "http://127.0.0.1:8080/manifest";

  let ownDidOptions = [];

  root.innerHTML = `
    <div class="card">
      <h2>Gerenciar Manifesto</h2>
      <p class="small">
        Permite ao Emissor ancorar manualmente no ledger o manifesto atual do Bloom Filter.
        Esse recurso é útil para corrigir inconsistências ou forçar uma atualização manual do ATTRIB
        <code>REVOCATION_MANIFEST</code>. A revogação automática continua devendo atualizar esse manifesto
        sempre que uma credencial for revogada.
      </p>

      <div class="row">
        <button class="secondary" id="btn_manifest_manage_refresh_dids">Atualizar DIDs own</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Genesis path</label>
          <input id="manifest_manage_genesis_path" placeholder="/caminho/para/genesis.txn" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:360px">
          <label>DID emissor (lista own)</label>
          <select id="sel_manifest_manage_did">
            <option value="">-- selecione um DID --</option>
          </select>
        </div>

        <div class="input" style="min-width:420px">
          <label>DID emissor (manual)</label>
          <input id="manifest_manage_did" placeholder="ex.: DID do emissor" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Manifest URL</label>
          <input id="manifest_manage_url" value="${DEFAULT_MANIFEST_URL}" />
        </div>

        <div class="input" style="min-width:180px">
          <label>Manifest version</label>
          <input id="manifest_manage_version" value="1" />
        </div>
      </div>

      <div class="row">
        <button class="secondary" id="btn_manifest_manage_check">Verificar manifesto atual</button>
        <button class="primary" id="btn_manifest_manage_anchor">Ancorar manifesto no ledger</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:760px">
          <label>Resultado</label>
          <textarea id="manifest_manage_result" rows="10" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="manifest_manage_out">{}</pre>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#manifest_manage_out");

  function setOut(obj) {
    out.textContent = JSON.stringify(obj, null, 2);
  }

  function toStringSafe(v) {
    if (v === undefined || v === null) return "";
    return String(v);
  }

  function normalizeText(v) {
    return toStringSafe(v).toLocaleLowerCase("pt-BR");
  }

  function firstNonEmpty(...values) {
    for (const v of values) {
      const txt = toStringSafe(v).trim();
      if (txt) return txt;
    }
    return "";
  }

  function parseDidList(resp) {
    if (!resp?.ok) return [];
    let data = resp.data;
    if (typeof data === "string") {
      try {
        data = JSON.parse(data);
      } catch (_) {
        return [];
      }
    }
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.items)) return data.items;
    return [];
  }

  function didSearchBlob(d) {
    return normalizeText([
      d.did,
      d.alias,
      d.verkey,
      d.verKey,
    ].filter(Boolean).join(" "));
  }

  function renderDidOptions(items) {
    const sel = $("#sel_manifest_manage_did");
    const currentDid = toStringSafe(sel.value).trim();
    sel.innerHTML = `<option value="">-- selecione um DID --</option>`;

    const fragment = document.createDocumentFragment();
    (items || []).forEach((d) => {
      const did = toStringSafe(d.did).trim();
      if (!did) return;
      const opt = document.createElement("option");
      opt.value = did;
      opt.textContent = `${did}${d.alias ? ` (${d.alias})` : ""}`;
      fragment.appendChild(opt);
    });
    sel.appendChild(fragment);

    if (currentDid && (items || []).some((d) => toStringSafe(d.did).trim() === currentDid)) {
      sel.value = currentDid;
    }
  }

  function syncGenesisPathInput() {
    const genesisPath = firstNonEmpty(window.AppState?.genesisPath);
    if (!genesisPath) return "";
    if (toStringSafe($("#manifest_manage_genesis_path").value).trim() !== genesisPath) {
      $("#manifest_manage_genesis_path").value = genesisPath;
    }
    return genesisPath;
  }

  async function refreshDidOptions() {
    Api.setStatus("Carregando DIDs own do emissor...");
    const resp = await Api.did.list("own");
    setOut({ where: "manifestManage.refreshDidOptions", resp });

    if (!resp?.ok) {
      Api.setStatus(`Erro listando DIDs own: ${resp?.error?.message || "erro desconhecido"}`);
      return;
    }

    ownDidOptions = parseDidList(resp);
    renderDidOptions(ownDidOptions);

    if (!toStringSafe($("#manifest_manage_did").value).trim() && ownDidOptions.length > 0) {
      const did = toStringSafe(ownDidOptions[0].did).trim();
      $("#manifest_manage_did").value = did;
      $("#sel_manifest_manage_did").value = did;
    }

    Api.setStatus(`DIDs own carregados: ${ownDidOptions.length}.`);
  }

  async function anchorManifestOnLedger() {
    const genesisPath = firstNonEmpty($("#manifest_manage_genesis_path").value, window.AppState?.genesisPath);
    const issuerDid = firstNonEmpty($("#manifest_manage_did").value, $("#sel_manifest_manage_did").value);
    const manifestUrl = firstNonEmpty($("#manifest_manage_url").value, DEFAULT_MANIFEST_URL);
    const manifestVersion = firstNonEmpty($("#manifest_manage_version").value, "1");

    $("#manifest_manage_genesis_path").value = genesisPath;

    if (!genesisPath) {
      Api.setStatus("Informe o Genesis path.");
      return;
    }
    if (!issuerDid) {
      Api.setStatus("Selecione ou informe o DID do emissor.");
      return;
    }
    if (!manifestUrl) {
      Api.setStatus("Informe a URL do manifesto.");
      return;
    }

    const checkResp = await Api.credCreateRevocable.checkManifestOnLedger({
      genesisPath,
      issuerDid,
      manifestUrl,
      manifestVersion,
    });
    setOut({
      where: "manifestManage.checkBeforeAnchor",
      input: { genesisPath, issuerDid, manifestUrl, manifestVersion },
      resp: checkResp,
    });

    if (!checkResp?.ok) {
      $("#manifest_manage_result").value = JSON.stringify(checkResp, null, 2);
      Api.setStatus(`Erro verificando manifesto atual: ${checkResp?.error?.message || "erro desconhecido"}`);
      return;
    }

    if (checkResp?.data?.upToDate) {
      $("#manifest_manage_result").value = JSON.stringify(checkResp, null, 2);
      Api.setStatus("O manifesto atual já está ancorado no ledger; nenhuma nova escrita foi necessária.");
      return;
    }

    Api.setStatus("Manifesto divergente; ancorando versão atual no ledger...");
    const resp = await Api.credCreateRevocable.anchorManifestOnLedger({
      genesisPath,
      issuerDid,
      manifestUrl,
      manifestVersion,
    });

    setOut({
      where: "manifestManage.anchorManifestOnLedger",
      input: { genesisPath, issuerDid, manifestUrl, manifestVersion },
      resp,
    });
    $("#manifest_manage_result").value = JSON.stringify(resp, null, 2);

    if (!resp?.ok) {
      Api.setStatus(`Erro ancorando manifesto: ${resp?.error?.message || "erro desconhecido"}`);
      return;
    }

    Api.setStatus(`Manifesto ancorado no ledger: ${firstNonEmpty(resp?.data?.manifest?.manifest_url, manifestUrl)}.`);
  }

  async function checkManifestOnLedger() {
    const genesisPath = firstNonEmpty($("#manifest_manage_genesis_path").value, window.AppState?.genesisPath);
    const issuerDid = firstNonEmpty($("#manifest_manage_did").value, $("#sel_manifest_manage_did").value);
    const manifestUrl = firstNonEmpty($("#manifest_manage_url").value, DEFAULT_MANIFEST_URL);
    const manifestVersion = firstNonEmpty($("#manifest_manage_version").value, "1");

    $("#manifest_manage_genesis_path").value = genesisPath;

    if (!genesisPath) {
      Api.setStatus("Informe o Genesis path.");
      return;
    }
    if (!issuerDid) {
      Api.setStatus("Selecione ou informe o DID do emissor.");
      return;
    }
    if (!manifestUrl) {
      Api.setStatus("Informe a URL do manifesto.");
      return;
    }

    Api.setStatus("Comparando manifesto atual do Bloom com o ATTRIB do ledger...");
    const resp = await Api.credCreateRevocable.checkManifestOnLedger({
      genesisPath,
      issuerDid,
      manifestUrl,
      manifestVersion,
    });

    setOut({
      where: "manifestManage.checkManifestOnLedger",
      input: { genesisPath, issuerDid, manifestUrl, manifestVersion },
      resp,
    });
    $("#manifest_manage_result").value = JSON.stringify(resp, null, 2);

    if (!resp?.ok) {
      Api.setStatus(`Erro verificando manifesto atual: ${resp?.error?.message || "erro desconhecido"}`);
      return;
    }

    Api.setStatus(
      resp?.data?.upToDate
        ? "O manifesto atual já está alinhado entre Bloom e ledger."
        : "O manifesto atual difere do ledger e precisa ser ancorado novamente."
    );
  }

  $("#btn_manifest_manage_refresh_dids").addEventListener("click", () => {
    refreshDidOptions().catch(() => {});
  });

  $("#sel_manifest_manage_did").addEventListener("change", () => {
    const did = toStringSafe($("#sel_manifest_manage_did").value).trim();
    if (did) $("#manifest_manage_did").value = did;
  });

  $("#manifest_manage_genesis_path").addEventListener("change", () => {
    if (window.AppState) {
      window.AppState.genesisPath = toStringSafe($("#manifest_manage_genesis_path").value).trim() || null;
    }
  });

  $("#btn_manifest_manage_check").addEventListener("click", () => {
    checkManifestOnLedger().catch(() => {});
  });
  $("#btn_manifest_manage_anchor").addEventListener("click", () => {
    anchorManifestOnLedger().catch(() => {});
  });

  syncGenesisPathInput();
  refreshDidOptions().catch(() => {});

  return {};
})();
