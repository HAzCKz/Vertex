// src/renderer/js/pages/credential-receive.js
/* eslint-disable no-console */

const CredentialReceivePage = (() => {
  const root = document.getElementById("page-credential-receive");
  if (!root) return {};
  const DEFAULT_DID_LIMIT = 150;
  const MAX_DID_LIMIT = 1000;

  let ownDidOptions = [];
  let visibleOwnDidOptions = [];

  root.innerHTML = `
    <div class="card">
      <h2>Receber Credencial</h2>
      <p class="small">
        Importa o envelope de credencial gerado em <code>Criar Credencial</code>,
        decripta para o Holder e salva a credencial na wallet.
      </p>

      <div class="row">
        <button class="secondary" id="btn_receive_refresh_dids">Atualizar DIDs own</button>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>1) Holder</h3>

      <div class="row">
        <div class="input" style="min-width:340px">
          <label>DID holder (lista own)</label>
          <select id="sel_receive_holder_did">
            <option value="">-- selecione um DID --</option>
          </select>
        </div>

        <div class="input" style="min-width:420px">
          <label>DID holder (manual)</label>
          <input id="receive_holder_did" placeholder="ex.: did do holder" />
        </div>
      </div>
      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de DIDs</label>
          <input id="receive_holder_filter" placeholder="Filtrar por DID, alias ou verkey..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="receive_holder_limit" type="number" min="1" max="${MAX_DID_LIMIT}" value="${DEFAULT_DID_LIMIT}" />
        </div>
        <button class="secondary" id="btn_receive_holder_clear_filter">Limpar filtro</button>
      </div>
      <p class="small" id="receive_holder_stats">DIDs holder: 0</p>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Genesis path</label>
          <input id="receive_genesis_path" placeholder="/caminho/para/genesis.txn" />
        </div>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>2) Importar e salvar</h3>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Arquivo da credencial (.env.json)</label>
          <input id="receive_credential_file_path" placeholder="vazio = escolher no diálogo" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Arquivo da oferta (opcional, para inferir nonce)</label>
          <input id="receive_offer_file_path" placeholder="ex.: /caminho/cred_offer.env.json" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:320px">
          <label>Request Metadata ID (nonce)</label>
          <input id="receive_request_metadata_id" placeholder="se vazio, tenta inferir do envelope" />
        </div>
        <div class="input" style="min-width:320px">
          <label>Credential ID (local)</label>
          <input id="receive_credential_id" placeholder="vazio = auto" />
        </div>
      </div>

      <div class="row">
        <button class="primary" id="btn_receive_import_store">Importar e Salvar Credencial</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:320px">
          <label>CredDef ID</label>
          <input id="receive_creddef_id" readonly />
        </div>
        <div class="input" style="min-width:260px">
          <label>Thread ID</label>
          <input id="receive_thread_id" readonly />
        </div>
        <div class="input" style="min-width:260px">
          <label>Kind</label>
          <input id="receive_kind" readonly />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Resultado</label>
          <textarea id="receive_result" rows="10" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="receive_out">{}</pre>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#receive_out");

  function setOut(obj) {
    out.textContent = JSON.stringify(obj, null, 2);
  }

  function toStringSafe(v) {
    if (v === undefined || v === null) return "";
    return String(v);
  }

  function parseMaybeJson(raw) {
    if (raw === undefined || raw === null) return raw;
    if (typeof raw === "string") {
      try {
        return JSON.parse(raw);
      } catch (_) {
        return raw;
      }
    }
    if (typeof raw === "object") return raw;
    return raw;
  }

  function parseDidList(resp) {
    if (!resp?.ok) return [];
    const data = parseMaybeJson(resp.data);
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.items)) return data.items;
    return [];
  }

  function firstNonEmpty(...values) {
    for (const v of values) {
      const txt = toStringSafe(v).trim();
      if (txt) return txt;
    }
    return "";
  }

  function normalizeText(v) {
    return toStringSafe(v).toLocaleLowerCase("pt-BR");
  }

  function parseDidLimit(value) {
    const parsed = Number.parseInt(toStringSafe(value), 10);
    if (!Number.isFinite(parsed) || parsed < 1) return DEFAULT_DID_LIMIT;
    return Math.min(parsed, MAX_DID_LIMIT);
  }

  function didSearchBlob(d) {
    return normalizeText([
      d.did,
      d.alias,
      d.verkey,
      d.verKey,
    ].filter(Boolean).join(" "));
  }

  function renderOwnDidOptions(items) {
    const el = $("#sel_receive_holder_did");
    const currentDid = toStringSafe(el.value).trim();
    el.innerHTML = `<option value="">-- selecione um DID --</option>`;

    const fragment = document.createDocumentFragment();
    (items || []).forEach((d) => {
      const did = toStringSafe(d.did).trim();
      if (!did) return;
      const opt = document.createElement("option");
      opt.value = did;
      opt.textContent = `${did}${d.alias ? ` (${d.alias})` : ""}`;
      fragment.appendChild(opt);
    });
    el.appendChild(fragment);

    if (currentDid && (items || []).some((d) => toStringSafe(d.did).trim() === currentDid)) {
      el.value = currentDid;
    }
  }

  function updateDidStats(total, filtered, shown, limit) {
    $("#receive_holder_stats").textContent =
      `DIDs holder: total ${total} | filtrados ${filtered} | exibidos ${shown} (máx ${limit})`;
  }

  function applyHolderDidFilter() {
    const filterText = normalizeText($("#receive_holder_filter").value).trim();
    const limit = parseDidLimit($("#receive_holder_limit").value);
    $("#receive_holder_limit").value = String(limit);

    const filtered = filterText
      ? ownDidOptions.filter((d) => didSearchBlob(d).includes(filterText))
      : ownDidOptions;

    visibleOwnDidOptions = filtered.slice(0, limit);
    renderOwnDidOptions(visibleOwnDidOptions);
    updateDidStats(ownDidOptions.length, filtered.length, visibleOwnDidOptions.length, limit);
  }

  async function refreshDidOptions() {
    Api.setStatus("Carregando DIDs own do holder...");
    const r = await Api.did.list("own");
    setOut({ where: "credentialReceive.refreshDidOptions", resp: r });
    if (!r?.ok) {
      Api.setStatus(`Erro listando DIDs own: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    ownDidOptions = parseDidList(r);
    applyHolderDidFilter();
    Api.setStatus(`DIDs own carregados: ${ownDidOptions.length} (${visibleOwnDidOptions.length} exibidos).`);
  }

  function updateFromReceiveResult(data) {
    $("#receive_credential_file_path").value = firstNonEmpty(data?.credentialFilePath, $("#receive_credential_file_path").value);
    $("#receive_offer_file_path").value = firstNonEmpty(data?.inferredOfferFilePath, $("#receive_offer_file_path").value);
    $("#receive_holder_did").value = firstNonEmpty(data?.holderDid, $("#receive_holder_did").value);
    $("#receive_request_metadata_id").value = firstNonEmpty(data?.requestMetadataId, $("#receive_request_metadata_id").value);
    $("#receive_credential_id").value = firstNonEmpty(data?.credentialId, $("#receive_credential_id").value);
    $("#receive_creddef_id").value = firstNonEmpty(data?.credDefId);
    $("#receive_thread_id").value = firstNonEmpty(data?.threadId);
    $("#receive_kind").value = firstNonEmpty(data?.kind);
  }

  async function importAndStoreCredential() {
    // Evita reaproveitar offer antiga entre importações sequenciais.
    $("#receive_offer_file_path").value = "";

    const holderDid = toStringSafe($("#receive_holder_did").value).trim() || null;
    const genesisPath = toStringSafe($("#receive_genesis_path").value).trim();
    const credentialFilePath = toStringSafe($("#receive_credential_file_path").value).trim() || null;
    const offerFilePath = toStringSafe($("#receive_offer_file_path").value).trim() || null;
    const requestMetadataId = toStringSafe($("#receive_request_metadata_id").value).trim() || null;
    const credentialId = toStringSafe($("#receive_credential_id").value).trim() || null;

    if (!genesisPath) {
      Api.setStatus("Informe o genesis path.");
      return;
    }

    const input = {
      holderDid,
      genesisPath,
      credentialFilePath,
      offerFilePath,
      requestMetadataId,
      credentialId,
    };

    Api.setStatus("Importando e salvando credencial na wallet do holder...");
    const r = await Api.credReceive.importAndStoreEnvelope(input);
    setOut({ where: "credentialReceive.importAndStoreEnvelope", input, resp: r });
    $("#receive_result").value = JSON.stringify(r, null, 2);

    if (!r?.ok) {
      Api.setStatus(`Erro recebendo credencial: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (r.data?.canceled) {
      Api.setStatus("Importação cancelada.");
      return;
    }

    updateFromReceiveResult(r.data || {});
    if (r.data?.alreadyStored) {
      Api.setStatus(`Credencial já estava armazenada na wallet: ${r.data?.credentialId || "(sem id)"}`);
    } else {
      Api.setStatus(`Credencial salva com sucesso: ${r.data?.credentialId || "(sem id)"}`);
    }
  }

  $("#btn_receive_refresh_dids").addEventListener("click", refreshDidOptions);
  $("#btn_receive_import_store").addEventListener("click", importAndStoreCredential);
  $("#receive_holder_filter").addEventListener("input", applyHolderDidFilter);
  $("#receive_holder_filter").addEventListener("keyup", applyHolderDidFilter);
  $("#receive_holder_limit").addEventListener("input", applyHolderDidFilter);
  $("#receive_holder_limit").addEventListener("change", applyHolderDidFilter);
  $("#btn_receive_holder_clear_filter").addEventListener("click", () => {
    $("#receive_holder_filter").value = "";
    applyHolderDidFilter();
  });
  $("#sel_receive_holder_did").addEventListener("change", () => {
    const did = toStringSafe($("#sel_receive_holder_did").value).trim();
    if (did) $("#receive_holder_did").value = did;
  });

  refreshDidOptions().catch(() => {});
  return {};
})();
