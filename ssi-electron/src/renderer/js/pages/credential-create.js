// src/renderer/js/pages/credential-create.js
/* eslint-disable no-console */

const CredentialCreatePage = (() => {
  const root = document.getElementById("page-credential-create");
  if (!root) return {};
  const DEFAULT_DID_LIMIT = 150;
  const MAX_DID_LIMIT = 1000;

  let ownDidOptions = [];
  let visibleOwnDidOptions = [];
  let importedRequest = null;

  root.innerHTML = `
    <div class="card">
      <h2>Criar Credencial</h2>
      <p class="small">
        Importa o arquivo de aceite da oferta (request envelope), permite preencher os atributos
        do schema e exporta a credencial em envelope para o holder.
      </p>

      <div class="row">
        <button class="secondary" id="btn_create_refresh_dids">Atualizar DIDs emissor</button>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>1) Emissor</h3>

      <div class="row">
        <div class="input" style="min-width:340px">
          <label>DID emissor (lista own)</label>
          <select id="sel_create_issuer_did">
            <option value="">-- selecione um DID --</option>
          </select>
        </div>

        <div class="input" style="min-width:420px">
          <label>DID emissor (manual)</label>
          <input id="create_issuer_did" placeholder="ex.: did do emissor" />
        </div>
      </div>
      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de DIDs</label>
          <input id="create_issuer_filter" placeholder="Filtrar por DID, alias ou verkey..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="create_issuer_limit" type="number" min="1" max="${MAX_DID_LIMIT}" value="${DEFAULT_DID_LIMIT}" />
        </div>
        <button class="secondary" id="btn_create_issuer_clear_filter">Limpar filtro</button>
      </div>
      <p class="small" id="create_issuer_stats">DIDs emissor: 0</p>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>2) Importar aceite (request)</h3>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Arquivo do request (.env.json)</label>
          <input id="create_request_file_path" placeholder="vazio = escolher no diálogo" />
        </div>
        <button class="secondary" id="btn_create_import_request">Importar aceite</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Arquivo da oferta (opcional, fallback)</label>
          <input id="create_offer_file_path" placeholder="ex.: /caminho/cred_offer.env.json" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:320px">
          <label>CredDef ID</label>
          <input id="create_creddef_id" />
        </div>
        <div class="input" style="min-width:320px">
          <label>Holder DID (hint)</label>
          <input id="create_holder_did_hint" readonly />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Holder verkey (destino do envelope)</label>
          <input id="create_holder_verkey" placeholder="se vazio, tenta inferir do request envelope" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:280px">
          <label>Thread ID</label>
          <input id="create_thread_id" />
        </div>
        <div class="input" style="min-width:220px">
          <label>Nonce</label>
          <input id="create_request_nonce" readonly />
        </div>
        <div class="input" style="min-width:280px">
          <label>Offer encontrada</label>
          <input id="create_offer_matched" readonly />
        </div>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>3) Atributos da credencial</h3>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Genesis path</label>
          <input id="create_genesis_path" placeholder="/caminho/para/genesis.txn" />
        </div>
        <button class="secondary" id="btn_create_load_schema">Carregar atributos do schema</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Valores da credencial (JSON objeto)</label>
          <textarea id="create_values_json" rows="10" placeholder='{"nome":"Alice","cpf":"12345678900","idade":"29"}'></textarea>
        </div>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>4) Exportar credencial</h3>

      <div class="row">
        <div class="input" style="min-width:260px">
          <label>Kind</label>
          <input id="create_credential_kind" value="anoncreds/credential" />
        </div>
        <div class="input" style="min-width:220px">
          <label>ExpiresAt (epoch ms)</label>
          <input id="create_expires_at" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Meta JSON (opcional)</label>
          <textarea id="create_meta_json" rows="4" placeholder='{"kind":"cpf"}'></textarea>
        </div>
      </div>

      <div class="row">
        <button class="primary" id="btn_create_export_credential">Emitir e Exportar Credencial</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Resultado</label>
          <textarea id="create_result" rows="10" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="create_out">{}</pre>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#create_out");

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

  function firstNonEmpty(...values) {
    for (const v of values) {
      const s = toStringSafe(v).trim();
      if (s) return s;
    }
    return "";
  }

  function parseDidList(resp) {
    if (!resp?.ok) return [];
    const data = parseMaybeJson(resp.data);
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.items)) return data.items;
    return [];
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

  function renderDidOptions(items) {
    const el = $("#sel_create_issuer_did");
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
    $("#create_issuer_stats").textContent =
      `DIDs emissor: total ${total} | filtrados ${filtered} | exibidos ${shown} (máx ${limit})`;
  }

  function applyIssuerDidFilter() {
    const filterText = normalizeText($("#create_issuer_filter").value).trim();
    const limit = parseDidLimit($("#create_issuer_limit").value);
    $("#create_issuer_limit").value = String(limit);

    const filtered = filterText
      ? ownDidOptions.filter((d) => didSearchBlob(d).includes(filterText))
      : ownDidOptions;

    visibleOwnDidOptions = filtered.slice(0, limit);
    renderDidOptions(visibleOwnDidOptions);
    updateDidStats(ownDidOptions.length, filtered.length, visibleOwnDidOptions.length, limit);
  }

  async function refreshDids() {
    Api.setStatus("Carregando DIDs own do emissor...");
    const r = await Api.did.list("own");
    setOut({ where: "credentialCreate.refreshDids", resp: r });
    if (!r?.ok) {
      Api.setStatus(`Erro listando DIDs: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }
    ownDidOptions = parseDidList(r);
    applyIssuerDidFilter();
    Api.setStatus(`DIDs emissor carregados: ${ownDidOptions.length} (${visibleOwnDidOptions.length} exibidos).`);
  }

  function updateFromImportedRequest(data) {
    $("#create_request_file_path").value = firstNonEmpty(data?.requestFilePath, data?.filePath);
    if (Array.isArray(data?.offerCandidatesChecked) && data.offerCandidatesChecked.length > 0) {
      const candidate = firstNonEmpty(data.offerCandidatesChecked[0]);
      if (candidate && !toStringSafe($("#create_offer_file_path").value).trim()) {
        $("#create_offer_file_path").value = candidate;
      }
    }
    $("#create_issuer_did").value = firstNonEmpty(data?.issuerDidResolved, $("#create_issuer_did").value);
    $("#create_creddef_id").value = firstNonEmpty(data?.credDefId, $("#create_creddef_id").value);
    $("#create_holder_did_hint").value = firstNonEmpty(data?.holderDidHint);
    $("#create_holder_verkey").value = firstNonEmpty(data?.holderVerkeyHint, $("#create_holder_verkey").value);
    $("#create_thread_id").value = firstNonEmpty(data?.threadId, $("#create_thread_id").value);
    $("#create_request_nonce").value = firstNonEmpty(data?.requestNonce);
    const offerTxt = data?.offerMatched ? `sim (${firstNonEmpty(data?.offerMatchSource, "desconhecido")})` : "não";
    $("#create_offer_matched").value = offerTxt;
  }

  async function importRequestEnvelope() {
    // Sempre resetar o fallback de offer para evitar reuso de caminho antigo.
    $("#create_offer_file_path").value = "";

    const issuerDid = toStringSafe($("#create_issuer_did").value).trim() || null;
    const requestFilePath = toStringSafe($("#create_request_file_path").value).trim() || null;

    Api.setStatus("Importando request envelope...");
    const r = await Api.credCreate.importRequestEnvelope({ issuerDid, requestFilePath });
    setOut({ where: "credentialCreate.importRequestEnvelope", input: { issuerDid, requestFilePath }, resp: r });
    $("#create_result").value = JSON.stringify(r, null, 2);

    if (!r?.ok) {
      Api.setStatus(`Erro importando request: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (r.data?.canceled) {
      Api.setStatus("Importação cancelada.");
      return;
    }

    importedRequest = r.data;
    updateFromImportedRequest(r.data);
    Api.setStatus("Request importado com sucesso.");
  }

  async function loadSchemaTemplate() {
    const genesisPath = toStringSafe($("#create_genesis_path").value).trim();
    const credDefId = toStringSafe($("#create_creddef_id").value).trim();
    if (!genesisPath) {
      Api.setStatus("Informe Genesis path.");
      return;
    }
    if (!credDefId) {
      Api.setStatus("Informe CredDef ID.");
      return;
    }

    Api.setStatus("Carregando schema/atributos a partir da CredDef...");
    const r = await Api.credCreate.loadSchemaTemplate({ genesisPath, credDefId });
    setOut({ where: "credentialCreate.loadSchemaTemplate", input: { genesisPath, credDefId }, resp: r });
    $("#create_result").value = JSON.stringify(r, null, 2);

    if (!r?.ok) {
      Api.setStatus(`Erro carregando schema: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    const tpl = r.data?.valuesTemplate || {};
    $("#create_values_json").value = JSON.stringify(tpl, null, 2);
    Api.setStatus(`Atributos carregados (${(r.data?.attrNames || []).length}). Preencha os valores.`);
  }

  async function exportCredentialEnvelope() {
    const issuerDid = toStringSafe($("#create_issuer_did").value).trim() || null;
    const requestFilePath = toStringSafe($("#create_request_file_path").value).trim() || null;
    const offerFilePath = toStringSafe($("#create_offer_file_path").value).trim() || null;
    const credDefId = toStringSafe($("#create_creddef_id").value).trim() || null;
    const holderVerkey = toStringSafe($("#create_holder_verkey").value).trim() || null;
    const kind = toStringSafe($("#create_credential_kind").value).trim() || "anoncreds/credential";
    const threadId = toStringSafe($("#create_thread_id").value).trim() || null;

    const valuesRaw = toStringSafe($("#create_values_json").value).trim();
    if (!valuesRaw) {
      Api.setStatus("Preencha os valores da credencial em JSON.");
      return;
    }
    let valuesObj = null;
    try {
      valuesObj = JSON.parse(valuesRaw);
    } catch (_) {
      Api.setStatus("Valores da credencial: JSON inválido.");
      return;
    }

    const expiresRaw = toStringSafe($("#create_expires_at").value).trim();
    let expiresAtMs = null;
    if (expiresRaw) {
      const n = Number(expiresRaw);
      if (!Number.isFinite(n) || n <= 0) {
        Api.setStatus("ExpiresAt inválido. Use epoch em milissegundos.");
        return;
      }
      expiresAtMs = Math.trunc(n);
    }

    const metaRaw = toStringSafe($("#create_meta_json").value).trim();
    let metaObj = null;
    if (metaRaw) {
      try {
        metaObj = JSON.parse(metaRaw);
      } catch (_) {
        Api.setStatus("Meta JSON inválido.");
        return;
      }
    }

    const input = {
      issuerDid,
      requestFilePath,
      offerFilePath,
      credDefId,
      holderVerkey,
      kind,
      threadId,
      expiresAtMs,
      metaObj,
      valuesObj,
    };

    Api.setStatus("Emitindo credencial e exportando envelope...");
    const r = await Api.credCreate.exportCredentialEnvelope(input);
    setOut({ where: "credentialCreate.exportCredentialEnvelope", input, resp: r, importedRequest });
    $("#create_result").value = JSON.stringify(r, null, 2);

    if (!r?.ok) {
      Api.setStatus(`Erro emitindo/exportando credencial: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (r.data?.canceled) {
      Api.setStatus("Exportação cancelada.");
      return;
    }

    Api.setStatus(`Credencial exportada: ${r.data?.credentialFilePath || "(sem caminho)"}`);
  }

  $("#btn_create_refresh_dids").addEventListener("click", refreshDids);
  $("#btn_create_import_request").addEventListener("click", importRequestEnvelope);
  $("#btn_create_load_schema").addEventListener("click", loadSchemaTemplate);
  $("#btn_create_export_credential").addEventListener("click", exportCredentialEnvelope);
  $("#create_issuer_filter").addEventListener("input", applyIssuerDidFilter);
  $("#create_issuer_filter").addEventListener("keyup", applyIssuerDidFilter);
  $("#create_issuer_limit").addEventListener("input", applyIssuerDidFilter);
  $("#create_issuer_limit").addEventListener("change", applyIssuerDidFilter);
  $("#btn_create_issuer_clear_filter").addEventListener("click", () => {
    $("#create_issuer_filter").value = "";
    applyIssuerDidFilter();
  });

  $("#sel_create_issuer_did").addEventListener("change", () => {
    const did = toStringSafe($("#sel_create_issuer_did").value).trim();
    if (did) $("#create_issuer_did").value = did;
  });

  refreshDids().catch(() => {});
  return {};
})();
