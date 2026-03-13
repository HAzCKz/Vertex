// src/renderer/js/pages/presentation-create.js
/* eslint-disable no-console */

const PresentationCreatePage = (() => {
  const root = document.getElementById("page-presentation-create");
  if (!root) return {};
  const DEFAULT_DID_LIMIT = 150;
  const MAX_DID_LIMIT = 1000;

  let ownDidOptions = [];
  let visibleOwnDidOptions = [];
  let recipientOptions = [];
  let visibleRecipientOptions = [];
  let allCredentials = [];
  let filteredCredentials = [];
  let credentialsPageIndex = 1;
  let credentialsPageSize = 30;
  const selectedCredentialIds = new Set();
  const selectionConfig = new Map();
  let activeCredentialId = "";

  root.innerHTML = `
    <div class="card">
      <h2>Criar Apresentações</h2>
      <p class="small">
        Selecione uma ou mais credenciais da wallet, escolha atributos revelados e/ou predicados ZKP,
        gere a apresentação e exporte em envelope cifrado para um DID de destino.
      </p>

      <div class="row">
        <button class="secondary" id="btn_pres_refresh_all">Atualizar DIDs/Credenciais</button>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>1) Contexto e Destino</h3>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Genesis path</label>
          <input id="pres_genesis_path" placeholder="/caminho/para/genesis.txn" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:340px">
          <label>Holder DID (lista own)</label>
          <select id="sel_pres_holder_did">
            <option value="">-- selecione um DID --</option>
          </select>
        </div>

        <div class="input" style="min-width:420px">
          <label>Holder DID (manual)</label>
          <input id="pres_holder_did" placeholder="ex.: DID do holder" />
        </div>
      </div>
      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de DIDs (holder)</label>
          <input id="pres_holder_filter" placeholder="Filtrar por DID, alias ou verkey..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="pres_holder_limit" type="number" min="1" max="${MAX_DID_LIMIT}" value="${DEFAULT_DID_LIMIT}" />
        </div>
        <button class="secondary" id="btn_pres_holder_clear_filter">Limpar filtro</button>
      </div>
      <p class="small" id="pres_holder_stats">DIDs holder: 0</p>

      <div class="row">
        <div class="input" style="min-width:420px">
          <label>Destinatário (DID + verkey)</label>
          <select id="sel_pres_recipient">
            <option value="">-- selecione um destinatário --</option>
          </select>
        </div>

        <div class="input" style="min-width:320px">
          <label>DID destino (manual)</label>
          <input id="pres_recipient_did" placeholder="opcional (se verkey for manual)" />
        </div>

        <div class="input" style="min-width:420px">
          <label>Verkey destino (manual)</label>
          <input id="pres_recipient_verkey" placeholder="se vazio, tenta resolver via DID destino" />
        </div>
      </div>
      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de destinatários</label>
          <input id="pres_recipient_filter" placeholder="Filtrar por DID, verkey, alias ou origem..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="pres_recipient_limit" type="number" min="1" max="${MAX_DID_LIMIT}" value="${DEFAULT_DID_LIMIT}" />
        </div>
        <button class="secondary" id="btn_pres_recipient_clear_filter">Limpar filtro</button>
      </div>
      <p class="small" id="pres_recipient_stats">Destinatários: 0</p>

      <div class="row">
        <div class="input" style="min-width:260px">
          <label>Kind</label>
          <input id="pres_kind" value="ssi/proof/presentation" />
        </div>

        <div class="input" style="min-width:300px">
          <label>Thread ID (opcional)</label>
          <input id="pres_thread_id" placeholder="vazio = auto" />
        </div>

        <div class="input" style="min-width:220px">
          <label>ExpiresAt (epoch ms)</label>
          <input id="pres_expires_at" placeholder="opcional" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:280px">
          <label>Proof Name</label>
          <input id="pres_name" value="proof-from-wallet" />
        </div>

        <div class="input" style="min-width:180px">
          <label>Proof Version</label>
          <input id="pres_version" value="1.0" />
        </div>

        <div class="input" style="min-width:260px">
          <label>Proof Nonce (opcional)</label>
          <input id="pres_nonce" placeholder="vazio = auto" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Meta JSON (opcional)</label>
          <textarea id="pres_meta_json" rows="4" placeholder='{"flow":"presentation"}'></textarea>
        </div>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>2) Credenciais disponíveis</h3>

      <div class="row">
        <div class="input" style="min-width:340px">
          <label>Schema ID (filtro exato opcional)</label>
          <input id="pres_filter_schema" placeholder="ex.: V4SG...:2:nome:1.0" />
        </div>

        <div class="input" style="min-width:340px">
          <label>CredDef ID (filtro exato opcional)</label>
          <input id="pres_filter_creddef" placeholder="ex.: V4SG...:3:CL:...:TAG" />
        </div>

        <div class="input" style="min-width:300px">
          <label>Busca livre</label>
          <input id="pres_filter_text" placeholder="id, schema, creddef, atributo..." />
        </div>

        <button class="secondary" id="btn_pres_search">Buscar</button>
        <button class="secondary" id="btn_pres_clear_filter">Limpar</button>
      </div>

      <div class="row" style="align-items:flex-end">
        <div class="input" style="min-width:180px">
          <label>Itens por página</label>
          <select id="pres_cred_page_size">
            <option value="20">20</option>
            <option value="30" selected>30</option>
            <option value="50">50</option>
            <option value="100">100</option>
            <option value="200">200</option>
          </select>
        </div>
        <button class="secondary" id="btn_pres_cred_first">⏮ Primeiro</button>
        <button class="secondary" id="btn_pres_cred_prev">◀ Prev</button>
        <div class="input" style="min-width:120px">
          <label>Página</label>
          <input id="pres_cred_page_index" value="1" />
        </div>
        <button class="secondary" id="btn_pres_cred_next">Next ▶</button>
        <button class="secondary" id="btn_pres_cred_last">Último ⏭</button>
        <div class="small" id="pres_cred_page_meta"></div>
      </div>

      <div class="tableWrap">
        <table class="table" id="tbl_pres_credentials">
          <thead>
            <tr>
              <th>Usar</th>
              <th>ID local</th>
              <th>Schema ID</th>
              <th>CredDef ID</th>
              <th>Atributos</th>
              <th>Ações</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <p class="small" id="pres_selected_summary">0 credenciais selecionadas.</p>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>3) Configurar atributos das credenciais selecionadas</h3>

      <div class="row">
        <button class="secondary" id="btn_pres_mark_all_revealed">Marcar todos como revelado</button>
        <button class="secondary" id="btn_pres_clear_modes">Limpar seleção de atributos</button>
      </div>

      <div class="tableWrap">
        <table class="table" id="tbl_pres_attrs">
          <thead>
            <tr>
              <th>Credencial</th>
              <th>Atributo</th>
              <th>Valor atual</th>
              <th>Modo</th>
              <th>Operador ZKP</th>
              <th>Valor ZKP (inteiro)</th>
              <th>Info</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>4) Gerar e exportar</h3>

      <div class="row">
        <button class="primary" id="btn_pres_export">Gerar apresentação e exportar envelope</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Resultado</label>
          <textarea id="pres_result" rows="10" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="pres_out">{}</pre>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#pres_out");

  function setOut(obj) {
    out.textContent = JSON.stringify(obj, null, 2);
  }

  function toStringSafe(v) {
    if (v === undefined || v === null) return "";
    return String(v);
  }

  function firstNonEmpty(...values) {
    for (const v of values) {
      const txt = toStringSafe(v).trim();
      if (txt) return txt;
    }
    return "";
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
    return raw;
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

  function normalizeValuesRaw(rec) {
    if (!rec || typeof rec !== "object") return {};

    if (rec.values_raw && typeof rec.values_raw === "object" && !Array.isArray(rec.values_raw)) {
      return rec.values_raw;
    }

    const values = rec.values;
    if (!values || typeof values !== "object" || Array.isArray(values)) return {};

    const map = {};
    Object.entries(values).forEach(([k, v]) => {
      if (v && typeof v === "object" && !Array.isArray(v)) {
        const raw = toStringSafe(v.raw).trim();
        if (raw) map[k] = raw;
      }
    });
    return map;
  }

  function parseCredentialsData(rawData) {
    const parsed = parseMaybeJson(rawData);
    let arr = [];

    if (Array.isArray(parsed)) {
      arr = parsed;
    } else if (parsed && typeof parsed === "object") {
      if (Array.isArray(parsed.items)) arr = parsed.items;
      else if (Array.isArray(parsed.data)) arr = parsed.data;
      else if (Array.isArray(parsed.records)) arr = parsed.records;
    }

    return arr
      .map((it) => parseMaybeJson(it))
      .filter((it) => it && typeof it === "object")
      .map((rec) => ({
        ...rec,
        id_local: firstNonEmpty(rec.id_local, rec.id),
        schema_id: firstNonEmpty(rec.schema_id, rec.schemaId),
        cred_def_id: firstNonEmpty(rec.cred_def_id, rec.credDefId),
        values_raw: normalizeValuesRaw(rec),
      }))
      .filter((rec) => rec.id_local && rec.schema_id && rec.cred_def_id);
  }

  function looksIntegerString(txt) {
    return /^-?\d+$/.test(toStringSafe(txt).trim());
  }

  function shortText(txt, max = 38) {
    const s = toStringSafe(txt).trim();
    if (s.length <= max) return s;
    return `${s.slice(0, max)}...`;
  }

  function getCredentialById(credId) {
    return allCredentials.find((c) => c.id_local === credId) || null;
  }

  function ensureCredentialConfig(credId) {
    if (!selectionConfig.has(credId)) {
      selectionConfig.set(credId, { attrs: {} });
    }
    const cfg = selectionConfig.get(credId);
    if (!cfg.attrs || typeof cfg.attrs !== "object") cfg.attrs = {};
    return cfg;
  }

  function ensureAttrConfig(credId, attrName, rawValue) {
    const cfg = ensureCredentialConfig(credId);
    if (!cfg.attrs[attrName]) {
      const raw = toStringSafe(rawValue).trim();
      cfg.attrs[attrName] = {
        mode: "",
        pType: ">=",
        pValue: looksIntegerString(raw) ? raw : "",
      };
    }
    return cfg.attrs[attrName];
  }

  function renderOwnDidOptions(items) {
    const el = $("#sel_pres_holder_did");
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

  function renderRecipientOptions(items) {
    const el = $("#sel_pres_recipient");
    const currentVerkey = toStringSafe(el.value).trim();
    el.innerHTML = `<option value="">-- selecione um destinatário --</option>`;

    const fragment = document.createDocumentFragment();
    (items || []).forEach((item) => {
      const did = toStringSafe(item.did).trim();
      const verkey = toStringSafe(item.verkey).trim();
      if (!did || !verkey) return;
      const opt = document.createElement("option");
      opt.value = verkey;
      opt.dataset.did = did;
      opt.textContent = `${did} | ${verkey.slice(0, 20)}... (${item.source})`;
      fragment.appendChild(opt);
    });
    el.appendChild(fragment);

    if (currentVerkey && (items || []).some((item) => toStringSafe(item.verkey).trim() === currentVerkey)) {
      el.value = currentVerkey;
    }
  }

  function holderDidSearchBlob(d) {
    return normalizeText([
      d.did,
      d.alias,
      d.verkey,
      d.verKey,
    ].filter(Boolean).join(" "));
  }

  function recipientDidSearchBlob(item) {
    return normalizeText([
      item.did,
      item.alias,
      item.verkey,
      item.verKey,
      item.source,
    ].filter(Boolean).join(" "));
  }

  function updateHolderStats(total, filtered, shown, limit) {
    $("#pres_holder_stats").textContent =
      `DIDs holder: total ${total} | filtrados ${filtered} | exibidos ${shown} (máx ${limit})`;
  }

  function updateRecipientStats(total, filtered, shown, limit) {
    $("#pres_recipient_stats").textContent =
      `Destinatários: total ${total} | filtrados ${filtered} | exibidos ${shown} (máx ${limit})`;
  }

  function applyHolderDidFilter() {
    const filterText = normalizeText($("#pres_holder_filter").value).trim();
    const limit = parseDidLimit($("#pres_holder_limit").value);
    $("#pres_holder_limit").value = String(limit);

    const filtered = filterText
      ? ownDidOptions.filter((d) => holderDidSearchBlob(d).includes(filterText))
      : ownDidOptions;

    visibleOwnDidOptions = filtered.slice(0, limit);
    renderOwnDidOptions(visibleOwnDidOptions);
    updateHolderStats(ownDidOptions.length, filtered.length, visibleOwnDidOptions.length, limit);
  }

  function applyRecipientDidFilter() {
    const filterText = normalizeText($("#pres_recipient_filter").value).trim();
    const limit = parseDidLimit($("#pres_recipient_limit").value);
    $("#pres_recipient_limit").value = String(limit);

    const filtered = filterText
      ? recipientOptions.filter((item) => recipientDidSearchBlob(item).includes(filterText))
      : recipientOptions;

    visibleRecipientOptions = filtered.slice(0, limit);
    renderRecipientOptions(visibleRecipientOptions);
    updateRecipientStats(recipientOptions.length, filtered.length, visibleRecipientOptions.length, limit);
  }

  function buildSearchBlob(rec) {
    const attrs = rec.values_raw && typeof rec.values_raw === "object"
      ? Object.entries(rec.values_raw).map(([k, v]) => `${k}:${toStringSafe(v)}`).join(" ")
      : "";

    return [rec.id_local, rec.schema_id, rec.cred_def_id, attrs]
      .map((v) => toStringSafe(v).toLowerCase())
      .join(" | ");
  }

  function applyFilterClientSide(items) {
    const q = normalizeText($("#pres_filter_text").value).trim();
    if (!q) return items;
    return items.filter((rec) => buildSearchBlob(rec).includes(q));
  }

  function getCredentialPagination() {
    credentialsPageSize = Number($("#pres_cred_page_size").value || 30);
    if (!Number.isFinite(credentialsPageSize) || credentialsPageSize < 1) credentialsPageSize = 30;

    const total = filteredCredentials.length;
    const totalPages = Math.max(1, Math.ceil(total / credentialsPageSize));
    if (credentialsPageIndex > totalPages) credentialsPageIndex = totalPages;
    if (credentialsPageIndex < 1) credentialsPageIndex = 1;
    $("#pres_cred_page_index").value = String(credentialsPageIndex);

    const start = (credentialsPageIndex - 1) * credentialsPageSize;
    const end = start + credentialsPageSize;
    const slice = filteredCredentials.slice(start, end);
    return { total, totalPages, start, end: Math.min(end, total), slice };
  }

  function updateSelectedSummary() {
    const total = selectedCredentialIds.size;
    let configuredAttrs = 0;
    let configuredCreds = 0;
    selectedCredentialIds.forEach((credId) => {
      const cfg = selectionConfig.get(credId);
      if (!cfg || !cfg.attrs || typeof cfg.attrs !== "object") return;
      const count = Object.values(cfg.attrs).filter((a) => {
        const mode = toStringSafe(a?.mode).trim();
        return mode === "revealed" || mode === "zkp";
      }).length;
      if (count > 0) {
        configuredCreds += 1;
        configuredAttrs += count;
      }
    });
    const active = activeCredentialId ? ` | editando: ${activeCredentialId}` : "";
    $("#pres_selected_summary").textContent = `${total} credenciais selecionadas | ${configuredAttrs} atributo(s) configurado(s) em ${configuredCreds} credencial(is)${active}.`;
  }

  function renderCredentialTable() {
    const tbody = $("#tbl_pres_credentials tbody");
    tbody.innerHTML = "";
    const { total, totalPages, start, end, slice } = getCredentialPagination();

    slice.forEach((rec, idx) => {
      const attrKeys = rec.values_raw && typeof rec.values_raw === "object"
        ? Object.keys(rec.values_raw)
        : [];
      const checked = selectedCredentialIds.has(rec.id_local) ? "checked" : "";
      const selectedClass = rec.id_local === activeCredentialId ? "selectedRow" : "";

      const tr = document.createElement("tr");
      tr.dataset.idx = String(start + idx);
      tr.className = selectedClass;
      tr.innerHTML = `
        <td><input type="checkbox" data-act="toggle" data-id="${rec.id_local}" ${checked} /></td>
        <td class="mono">${rec.id_local}</td>
        <td class="mono" title="${toStringSafe(rec.schema_id)}">${shortText(rec.schema_id, 34)}</td>
        <td class="mono" title="${toStringSafe(rec.cred_def_id)}">${shortText(rec.cred_def_id, 34)}</td>
        <td title="${attrKeys.join(", ")}">${shortText(attrKeys.join(", "), 34)}</td>
        <td>
          <div class="actions">
            <button data-act="config" data-id="${rec.id_local}">Atributos</button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });

    if (total > 0) {
      $("#pres_cred_page_meta").textContent =
        `Total: ${total} | Página ${credentialsPageIndex}/${totalPages} | Itens ${start + 1}-${end}`;
    } else {
      $("#pres_cred_page_meta").textContent = "Total: 0 | Página 1/1";
    }

    updateSelectedSummary();
  }

  function renderAttrTable() {
    const tbody = $("#tbl_pres_attrs tbody");
    tbody.innerHTML = "";

    const selectedIds = Array.from(selectedCredentialIds)
      .map((id) => toStringSafe(id).trim())
      .filter((id) => !!id)
      .filter((id, idx, arr) => arr.indexOf(id) === idx);

    if (!selectedIds.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="7" class="small">Selecione uma ou mais credenciais (checkbox "Usar" ou botão "Atributos").</td>`;
      tbody.appendChild(tr);
      updateSelectedSummary();
      return;
    }

    let renderedRows = 0;
    selectedIds.forEach((credId) => {
      const rec = getCredentialById(credId);
      if (!rec) return;

      const attrsMap = rec.values_raw && typeof rec.values_raw === "object" ? rec.values_raw : {};
      const attrEntries = Object.entries(attrsMap);
      if (!attrEntries.length) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td class="mono" title="${credId}">${shortText(credId, 28)}</td>
          <td colspan="6" class="small">Credencial sem atributos em values_raw.</td>
        `;
        tbody.appendChild(tr);
        renderedRows += 1;
        return;
      }

      attrEntries.forEach(([attrName, rawValue]) => {
        const cfg = ensureAttrConfig(credId, attrName, rawValue);
        const raw = toStringSafe(rawValue).trim();
        const isInteger = looksIntegerString(raw);
        const zkpDisabled = isInteger ? "" : "disabled";
        const mode = toStringSafe(cfg.mode).trim();
        const pType = toStringSafe(cfg.pType).trim() || ">=";
        const pValue = toStringSafe(cfg.pValue).trim();
        const disabledControls = mode === "zkp" ? "" : "disabled";
        const isActive = credId === activeCredentialId;

        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td class="mono" title="${credId}">${shortText(credId, 28)}${isActive ? " *" : ""}</td>
          <td class="mono">${attrName}</td>
          <td class="mono" title="${raw}">${shortText(raw, 28)}</td>
          <td>
            <select data-act="mode" data-cred-id="${credId}" data-attr="${attrName}">
              <option value="" ${mode === "" ? "selected" : ""}>Não incluir</option>
              <option value="revealed" ${mode === "revealed" ? "selected" : ""}>Revelado</option>
              <option value="zkp" ${mode === "zkp" ? "selected" : ""} ${zkpDisabled}>ZKP</option>
            </select>
          </td>
          <td>
            <select data-act="ptype" data-cred-id="${credId}" data-attr="${attrName}" ${disabledControls}>
              <option value=">=" ${pType === ">=" ? "selected" : ""}>>=</option>
              <option value=">" ${pType === ">" ? "selected" : ""}>></option>
              <option value="<=" ${pType === "<=" ? "selected" : ""}><=</option>
              <option value="<" ${pType === "<" ? "selected" : ""}><</option>
            </select>
          </td>
          <td>
            <input data-act="pvalue" data-cred-id="${credId}" data-attr="${attrName}" value="${pValue}" ${disabledControls} style="width:120px" />
          </td>
          <td class="small">${isInteger ? "numérico (ZKP habilitado)" : "não numérico (apenas revelado)"}</td>
        `;
        tbody.appendChild(tr);
        renderedRows += 1;
      });
    });

    if (!renderedRows) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="7" class="small">Nenhum atributo disponível nas credenciais selecionadas.</td>`;
      tbody.appendChild(tr);
    }

    updateSelectedSummary();
  }

  async function refreshDidOptions() {
    Api.setStatus("Carregando DIDs para criação de apresentação...");

    const [ownResp, extResp] = await Promise.all([
      Api.did.list("own"),
      Api.did.list("external"),
    ]);

    if (!ownResp?.ok) {
      setOut({ where: "presentationCreate.refreshDidOptions", ownResp, extResp });
      Api.setStatus(`Erro listando DIDs own: ${ownResp?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (!extResp?.ok) {
      setOut({ where: "presentationCreate.refreshDidOptions", ownResp, extResp });
      Api.setStatus(`Erro listando DIDs external: ${extResp?.error?.message || "erro desconhecido"}`);
      return;
    }

    ownDidOptions = parseDidList(ownResp);
    applyHolderDidFilter();

    const own = parseDidList(ownResp).map((d) => ({ ...d, source: "own" }));
    const ext = parseDidList(extResp).map((d) => ({ ...d, source: "external" }));
    const seen = new Set();
    recipientOptions = own.concat(ext).filter((d) => {
      const did = toStringSafe(d.did).trim();
      const verkey = toStringSafe(d.verkey).trim();
      const key = `${did}|${verkey}`;
      if (!did || !verkey || seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    applyRecipientDidFilter();
  }

  async function refreshCredentials() {
    const schemaIdEq = toStringSafe($("#pres_filter_schema").value).trim() || null;
    const credDefIdEq = toStringSafe($("#pres_filter_creddef").value).trim() || null;

    Api.setStatus("Listando credenciais para apresentação...");
    const resp = await Api.credential.list(schemaIdEq, credDefIdEq);
    setOut({ where: "presentationCreate.refreshCredentials", input: { schemaIdEq, credDefIdEq }, resp });

    if (!resp?.ok) {
      Api.setStatus(`Erro listando credenciais: ${resp?.error?.message || "erro desconhecido"}`);
      allCredentials = [];
      filteredCredentials = [];
      credentialsPageIndex = 1;
      renderCredentialTable();
      renderAttrTable();
      return;
    }

    allCredentials = parseCredentialsData(resp.data);
    filteredCredentials = applyFilterClientSide(allCredentials);
    credentialsPageIndex = 1;

    // Remove seleção inválida após refresh
    Array.from(selectedCredentialIds).forEach((id) => {
      if (!allCredentials.find((it) => it.id_local === id)) {
        selectedCredentialIds.delete(id);
      }
    });
    if (activeCredentialId && !allCredentials.find((it) => it.id_local === activeCredentialId)) {
      activeCredentialId = "";
    }

    renderCredentialTable();
    renderAttrTable();
    Api.setStatus(`Credenciais carregadas: ${filteredCredentials.length}.`);
  }

  async function refreshAll() {
    await refreshDidOptions();
    await refreshCredentials();
  }

  function toggleCredentialSelection(credId, checked) {
    if (checked) selectedCredentialIds.add(credId);
    else selectedCredentialIds.delete(credId);

    if (checked && !activeCredentialId) {
      activeCredentialId = credId;
    }
    if (!checked && activeCredentialId === credId) {
      activeCredentialId = selectedCredentialIds.values().next().value || "";
    }

    renderCredentialTable();
    renderAttrTable();
  }

  function openCredentialConfig(credId) {
    if (!credId) return;
    selectedCredentialIds.add(credId);
    activeCredentialId = credId;
    renderCredentialTable();
    renderAttrTable();
    Api.setStatus(`Configurando atributos da credencial ${credId}.`);
  }

  function markAllRevealedForActive() {
    const targetIds = Array.from(selectedCredentialIds)
      .map((id) => toStringSafe(id).trim())
      .filter((id) => !!id && !!getCredentialById(id));
    if (!targetIds.length) {
      Api.setStatus("Selecione ao menos uma credencial para configurar atributos.");
      return;
    }

    targetIds.forEach((credId) => {
      const rec = getCredentialById(credId);
      if (!rec) return;
      const attrsMap = rec.values_raw && typeof rec.values_raw === "object" ? rec.values_raw : {};
      Object.entries(attrsMap).forEach(([attrName, rawValue]) => {
        const cfg = ensureAttrConfig(credId, attrName, rawValue);
        cfg.mode = "revealed";
      });
    });

    renderAttrTable();
    renderCredentialTable();
    Api.setStatus(`Todos os atributos foram marcados como revelados em ${targetIds.length} credencial(is) selecionada(s).`);
  }

  function clearModesForActive() {
    const targetIds = Array.from(selectedCredentialIds)
      .map((id) => toStringSafe(id).trim())
      .filter((id) => !!id && !!getCredentialById(id));
    if (!targetIds.length) {
      Api.setStatus("Selecione ao menos uma credencial para limpar a configuração.");
      return;
    }

    targetIds.forEach((credId) => {
      const rec = getCredentialById(credId);
      if (!rec) return;
      const attrsMap = rec.values_raw && typeof rec.values_raw === "object" ? rec.values_raw : {};
      Object.entries(attrsMap).forEach(([attrName, rawValue]) => {
        const cfg = ensureAttrConfig(credId, attrName, rawValue);
        cfg.mode = "";
        cfg.pType = ">=";
        cfg.pValue = looksIntegerString(toStringSafe(rawValue).trim()) ? toStringSafe(rawValue).trim() : "";
      });
    });

    renderAttrTable();
    Api.setStatus(`Configuração de atributos limpa em ${targetIds.length} credencial(is) selecionada(s).`);
  }

  function updateAttributeConfigFromEvent(target) {
    const act = toStringSafe(target.dataset.act).trim();
    const credId = toStringSafe(target.dataset.credId).trim();
    const attrName = toStringSafe(target.dataset.attr).trim();
    if (!act || !credId || !attrName) return;

    const rec = getCredentialById(credId);
    if (!rec) return;

    const rawValue = rec.values_raw ? rec.values_raw[attrName] : "";
    const cfg = ensureAttrConfig(credId, attrName, rawValue);

    if (act === "mode") {
      const mode = toStringSafe(target.value).trim();
      if (mode !== "" && mode !== "revealed" && mode !== "zkp") return;
      if (mode === "zkp" && !looksIntegerString(toStringSafe(rawValue).trim())) {
        cfg.mode = "revealed";
      } else {
        cfg.mode = mode;
      }
      selectedCredentialIds.add(credId);
      renderAttrTable();
      renderCredentialTable();
      return;
    }

    if (act === "ptype") {
      const pType = toStringSafe(target.value).trim();
      if ([">=", ">", "<=", "<"].includes(pType)) {
        cfg.pType = pType;
      }
      return;
    }

    if (act === "pvalue") {
      cfg.pValue = toStringSafe(target.value).trim();
    }
  }

  function buildSelectionPayload() {
    const payload = [];

    selectedCredentialIds.forEach((credId) => {
      const rec = getCredentialById(credId);
      if (!rec) return;
      const cfg = ensureCredentialConfig(credId);
      const attrsCfg = cfg.attrs || {};

      const attrs = [];
      Object.entries(attrsCfg).forEach(([attrName, attrCfgRaw]) => {
        const attrCfg = attrCfgRaw && typeof attrCfgRaw === "object" ? attrCfgRaw : {};
        const mode = toStringSafe(attrCfg.mode).trim();
        if (mode === "revealed") {
          attrs.push({ name: attrName, mode: "revealed" });
          return;
        }
        if (mode === "zkp") {
          attrs.push({
            name: attrName,
            mode: "zkp",
            pType: toStringSafe(attrCfg.pType).trim() || ">=",
            pValue: toStringSafe(attrCfg.pValue).trim(),
          });
        }
      });

      if (!attrs.length) return;

      payload.push({
        credentialId: rec.id_local,
        schemaId: rec.schema_id,
        credDefId: rec.cred_def_id,
        attributes: attrs,
      });
    });

    return payload;
  }

  async function exportPresentationEnvelope() {
    const genesisPath = toStringSafe($("#pres_genesis_path").value).trim();
    const holderDid = toStringSafe($("#pres_holder_did").value).trim();
    const recipientDid = toStringSafe($("#pres_recipient_did").value).trim() || null;
    const recipientVerkey = toStringSafe($("#pres_recipient_verkey").value).trim() || null;
    const kind = toStringSafe($("#pres_kind").value).trim() || "ssi/proof/presentation";
    const threadId = toStringSafe($("#pres_thread_id").value).trim() || null;
    const proofName = toStringSafe($("#pres_name").value).trim() || "proof-from-wallet";
    const proofVersion = toStringSafe($("#pres_version").value).trim() || "1.0";
    const proofNonce = toStringSafe($("#pres_nonce").value).trim() || null;

    if (!genesisPath) {
      Api.setStatus("Informe o Genesis path.");
      return;
    }
    if (!holderDid) {
      Api.setStatus("Informe o DID holder.");
      return;
    }

    const selection = buildSelectionPayload();
    if (!selection.length) {
      Api.setStatus("Selecione ao menos um atributo (revelado ou ZKP) em alguma credencial.");
      return;
    }

    const expiresRaw = toStringSafe($("#pres_expires_at").value).trim();
    let expiresAtMs = null;
    if (expiresRaw) {
      const n = Number(expiresRaw);
      if (!Number.isFinite(n) || n <= 0) {
        Api.setStatus("ExpiresAt inválido. Use epoch em milissegundos.");
        return;
      }
      expiresAtMs = Math.trunc(n);
    }

    const metaRaw = toStringSafe($("#pres_meta_json").value).trim();
    let metaObj = null;
    if (metaRaw) {
      try {
        metaObj = JSON.parse(metaRaw);
      } catch (_) {
        Api.setStatus("Meta JSON inválido.");
        return;
      }
      if (!metaObj || typeof metaObj !== "object" || Array.isArray(metaObj)) {
        Api.setStatus("Meta JSON deve ser um objeto.");
        return;
      }
    }

    const input = {
      genesisPath,
      holderDid,
      recipientDid,
      recipientVerkey,
      kind,
      threadId,
      expiresAtMs,
      proofName,
      proofVersion,
      proofNonce,
      metaObj,
      selection,
    };

    Api.setStatus("Gerando apresentação e exportando envelope...");
    const resp = await Api.presentation.createExportEnvelope(input);
    setOut({ where: "presentationCreate.export", input, resp });
    $("#pres_result").value = JSON.stringify(resp, null, 2);

    if (!resp?.ok) {
      Api.setStatus(`Erro gerando apresentação: ${resp?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (resp.data?.canceled) {
      Api.setStatus("Exportação cancelada.");
      return;
    }

    Api.setStatus(`Apresentação exportada: ${resp.data?.filePath || "(sem caminho)"}`);
  }

  function clearFilters() {
    $("#pres_filter_schema").value = "";
    $("#pres_filter_creddef").value = "";
    $("#pres_filter_text").value = "";
    refreshCredentials().catch(() => {});
  }

  $("#btn_pres_refresh_all").addEventListener("click", () => {
    refreshAll().catch(() => {});
  });
  $("#btn_pres_search").addEventListener("click", () => {
    refreshCredentials().catch(() => {});
  });
  $("#btn_pres_clear_filter").addEventListener("click", clearFilters);
  $("#btn_pres_mark_all_revealed").addEventListener("click", markAllRevealedForActive);
  $("#btn_pres_clear_modes").addEventListener("click", clearModesForActive);
  $("#btn_pres_export").addEventListener("click", exportPresentationEnvelope);
  $("#pres_holder_filter").addEventListener("input", applyHolderDidFilter);
  $("#pres_holder_filter").addEventListener("keyup", applyHolderDidFilter);
  $("#pres_holder_limit").addEventListener("input", applyHolderDidFilter);
  $("#pres_holder_limit").addEventListener("change", applyHolderDidFilter);
  $("#btn_pres_holder_clear_filter").addEventListener("click", () => {
    $("#pres_holder_filter").value = "";
    applyHolderDidFilter();
  });
  $("#pres_recipient_filter").addEventListener("input", applyRecipientDidFilter);
  $("#pres_recipient_filter").addEventListener("keyup", applyRecipientDidFilter);
  $("#pres_recipient_limit").addEventListener("input", applyRecipientDidFilter);
  $("#pres_recipient_limit").addEventListener("change", applyRecipientDidFilter);
  $("#btn_pres_recipient_clear_filter").addEventListener("click", () => {
    $("#pres_recipient_filter").value = "";
    applyRecipientDidFilter();
  });
  $("#pres_cred_page_size").addEventListener("change", () => {
    credentialsPageIndex = 1;
    renderCredentialTable();
  });
  $("#btn_pres_cred_first").addEventListener("click", () => {
    credentialsPageIndex = 1;
    renderCredentialTable();
  });
  $("#btn_pres_cred_prev").addEventListener("click", () => {
    credentialsPageIndex -= 1;
    renderCredentialTable();
  });
  $("#btn_pres_cred_next").addEventListener("click", () => {
    credentialsPageIndex += 1;
    renderCredentialTable();
  });
  $("#btn_pres_cred_last").addEventListener("click", () => {
    credentialsPageSize = Number($("#pres_cred_page_size").value || 30);
    if (!Number.isFinite(credentialsPageSize) || credentialsPageSize < 1) credentialsPageSize = 30;
    const totalPages = Math.max(1, Math.ceil(filteredCredentials.length / credentialsPageSize));
    credentialsPageIndex = totalPages;
    renderCredentialTable();
  });
  $("#pres_cred_page_index").addEventListener("change", () => {
    const n = Number($("#pres_cred_page_index").value);
    if (Number.isFinite(n)) credentialsPageIndex = Math.trunc(n);
    renderCredentialTable();
  });
  $("#pres_cred_page_index").addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter") return;
    const n = Number($("#pres_cred_page_index").value);
    if (Number.isFinite(n)) credentialsPageIndex = Math.trunc(n);
    renderCredentialTable();
  });

  $("#sel_pres_holder_did").addEventListener("change", () => {
    const did = toStringSafe($("#sel_pres_holder_did").value).trim();
    if (did) $("#pres_holder_did").value = did;
  });

  $("#sel_pres_recipient").addEventListener("change", () => {
    const sel = $("#sel_pres_recipient");
    const opt = sel.options[sel.selectedIndex];
    const did = opt ? toStringSafe(opt.dataset.did).trim() : "";
    const verkey = toStringSafe(sel.value).trim();
    if (did) $("#pres_recipient_did").value = did;
    if (verkey) $("#pres_recipient_verkey").value = verkey;
  });

  $("#tbl_pres_credentials").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-act]");
    if (!btn) return;
    const act = toStringSafe(btn.dataset.act).trim();
    const credId = toStringSafe(btn.dataset.id).trim();
    if (act === "config") openCredentialConfig(credId);
  });

  $("#tbl_pres_credentials").addEventListener("change", (ev) => {
    const cb = ev.target.closest("input[data-act='toggle']");
    if (!cb) return;
    const credId = toStringSafe(cb.dataset.id).trim();
    toggleCredentialSelection(credId, !!cb.checked);
  });

  $("#tbl_pres_attrs").addEventListener("change", (ev) => {
    const target = ev.target.closest("select[data-act], input[data-act]");
    if (!target) return;
    updateAttributeConfigFromEvent(target);
  });

  $("#tbl_pres_attrs").addEventListener("input", (ev) => {
    const target = ev.target.closest("input[data-act='pvalue']");
    if (!target) return;
    updateAttributeConfigFromEvent(target);
  });

  refreshAll().catch(() => {});

  return {};
})();
