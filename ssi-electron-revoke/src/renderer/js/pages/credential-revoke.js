// src/renderer/js/pages/credential-revoke.js
/* eslint-disable no-console */

const CredentialRevokePage = (() => {
  const root = document.getElementById("page-credential-revoke");
  if (!root) return {};

  const CONTROL_ATTRIBUTE_NAMES = new Set([
    "seed",
    "start_time",
    "unit_of_time",
    "time_window",
    "root_merkle_l",
    "root_merkle_L",
    "validity_end",
    "base_window_count",
    "confirmation_window_count",
    "extra_windows_for_fp",
    "window_count",
    "last_valid_window_index",
    "last_confirmation_window_index",
  ]);

  let lastItems = [];
  let filteredItemsView = [];
  let filteredItemsCacheKey = "";
  let selectedId = "";
  let lastSummaryData = null;
  let issuedSummaryCache = new Map();
  let pageIndex = 1;
  let pageSize = 30;
  let revokeConfirmResolve = null;
  let revokeConfirmPrevFocused = null;
  let deleteConfirmResolve = null;
  let deleteConfirmPrevFocused = null;

  root.innerHTML = `
    <div class="card">
      <h2>Revogar Credencial</h2>
      <p class="small">
        Lista as credenciais revogáveis salvas no wallet do emissor e permite revogá-las
        a partir de uma janela específica, escrevendo no Bloom filter dessa janela e das subsequentes.
      </p>

      <div class="row">
        <button class="secondary" id="btn_cred_revoke_refresh">Atualizar lista</button>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>1) Filtros</h3>

      <div class="row">
        <div class="input" style="min-width:220px">
          <label>Status</label>
          <select id="cred_revoke_status_filter">
            <option value="">Todos</option>
            <option value="active">active</option>
            <option value="revoked">revoked</option>
          </select>
        </div>

        <div class="input" style="min-width:420px">
          <label>Busca livre</label>
          <input id="cred_revoke_text_filter" placeholder="id local, holder DID, credDef ID, schema ID..." />
        </div>

        <button class="secondary" id="btn_cred_revoke_search">Buscar</button>
        <button class="secondary" id="btn_cred_revoke_clear">Limpar</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:220px">
          <label>Atributo da credencial</label>
          <input id="cred_revoke_attr_name_filter" placeholder="ex.: nome" />
        </div>

        <div class="input" style="min-width:420px">
          <label>Conteúdo do atributo</label>
          <input id="cred_revoke_attr_value_filter" placeholder="ex.: Mariana Dias" />
        </div>
      </div>

      <div class="row" style="align-items:flex-end">
        <div class="input" style="min-width:160px">
          <label>Tamanho da página</label>
          <select id="cred_revoke_page_size">
            <option value="20">20</option>
            <option value="30" selected>30</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
        </div>

        <button class="secondary" id="btn_cred_revoke_first">⏮ Ir para o primeiro</button>
        <button class="secondary" id="btn_cred_revoke_prev">◀ Prev</button>

        <div class="input" style="min-width:120px">
          <label>Página</label>
          <input id="cred_revoke_page_index" value="1" />
        </div>

        <button class="secondary" id="btn_cred_revoke_next">Next ▶</button>
        <button class="secondary" id="btn_cred_revoke_last">Ir para o último</button>
        <div class="small" id="cred_revoke_page_meta"></div>
      </div>

      <div class="tableWrap">
        <table class="table" id="tbl_cred_revoke">
          <thead>
            <tr>
              <th>ID local</th>
              <th>Holder DID</th>
              <th>CredDef ID</th>
              <th>Status</th>
              <th>Janela</th>
              <th>Validade</th>
              <th>Ações</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>2) Revogação</h3>

      <div class="row">
        <div class="input" style="min-width:420px">
          <label>ID local da credencial emitida</label>
          <input id="cred_revoke_id_local" readonly />
        </div>
        <div class="input" style="min-width:220px">
          <label>Revoke from window</label>
          <input id="cred_revoke_window" type="number" min="0" value="0" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:320px">
          <label>Faixa válida de janelas (0-based)</label>
          <input id="cred_revoke_window_range" readonly />
        </div>
        <div class="input" style="min-width:360px">
          <label>Data da janela escolhida</label>
          <input id="cred_revoke_window_date" readonly />
        </div>
        <div class="input" style="min-width:360px">
          <label>Data da revogação</label>
          <input id="cred_revoke_revoked_date" placeholder="DD/MM/AAAA, HH:mm:ss" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Dados da credencial selecionada</label>
          <textarea id="cred_revoke_selected_info" rows="8" readonly></textarea>
        </div>
      </div>

      <p class="small">
        A numeração das janelas neste menu é compatível com <code>Verificar Revogação</code> e começa em <code>0</code>.
        Somente janelas válidas da credencial podem ser escolhidas em <code>Revoke from window</code>.
      </p>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Genesis path</label>
          <input id="cred_revoke_genesis_path" placeholder="/caminho/para/genesis.txn" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:420px">
          <label>Bloom admin token</label>
          <input id="cred_revoke_token" placeholder="token administrativo do serviço Bloom" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:320px">
          <label>Reason (opcional)</label>
          <input id="cred_revoke_reason" placeholder="ex.: cancelamento do documento" />
        </div>
        <div class="input" style="min-width:320px">
          <label>Requested by (opcional)</label>
          <input id="cred_revoke_requested_by" placeholder="ex.: emissor-admin" />
        </div>
      </div>

      <div class="row">
        <button class="secondary" id="btn_cred_revoke_load_summary">Carregar resumo</button>
        <button class="secondary" id="btn_cred_revoke_preflight">Preflight</button>
        <button class="primary" id="btn_cred_revoke_execute">Revogar credencial</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Resumo da credencial emitida</label>
          <textarea id="cred_revoke_summary_out" rows="8" readonly></textarea>
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Preflight</label>
          <textarea id="cred_revoke_preflight_out" rows="8" readonly></textarea>
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Resultado</label>
          <textarea id="cred_revoke_result_out" rows="10" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="cred_revoke_out">{}</pre>
    </div>
    <div id="cred_revoke_confirm_overlay" style="display:none; position:fixed; inset:0; z-index:9999; background:rgba(17,24,39,0.35); align-items:center; justify-content:center; padding:16px;">
      <div style="width:min(100%, 720px); background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:16px; box-shadow:0 10px 30px rgba(17,24,39,0.2);">
        <h3 id="cred_revoke_confirm_title" style="margin:0 0 8px 0;">Confirmar Revogação</h3>
        <p id="cred_revoke_confirm_text" style="margin:0 0 12px 0; color:#111827;"></p>
        <div class="input" style="min-width:620px">
          <label>Dados da credencial</label>
          <textarea id="cred_revoke_confirm_details" rows="12" readonly></textarea>
        </div>
        <div class="row" style="margin-top:16px; justify-content:flex-end;">
          <button class="secondary" id="btn_cred_revoke_confirm_cancel">Cancelar operação</button>
          <button class="primary" id="btn_cred_revoke_confirm_ok">Confirmar Revogação</button>
        </div>
      </div>
    </div>
    <div id="cred_delete_confirm_overlay" style="display:none; position:fixed; inset:0; z-index:9999; background:rgba(17,24,39,0.35); align-items:center; justify-content:center; padding:16px;">
      <div style="width:min(100%, 680px); background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:16px; box-shadow:0 10px 30px rgba(17,24,39,0.2);">
        <h3 style="margin:0 0 8px 0;">Confirmar Exclusão</h3>
        <p id="cred_delete_confirm_text" style="margin:0 0 12px 0; color:#111827;"></p>
        <div class="input" style="min-width:620px">
          <label>Registro a excluir</label>
          <textarea id="cred_delete_confirm_details" rows="10" readonly></textarea>
        </div>
        <div class="row" style="margin-top:16px; justify-content:flex-end;">
          <button class="secondary" id="btn_cred_delete_confirm_cancel">Cancelar operação</button>
          <button class="primary" id="btn_cred_delete_confirm_ok">Excluir</button>
        </div>
      </div>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#cred_revoke_out");
  const revokeConfirmOverlay = $("#cred_revoke_confirm_overlay");
  const revokeConfirmTitle = $("#cred_revoke_confirm_title");
  const revokeConfirmText = $("#cred_revoke_confirm_text");
  const revokeConfirmDetails = $("#cred_revoke_confirm_details");
  const revokeConfirmBtnCancel = $("#btn_cred_revoke_confirm_cancel");
  const revokeConfirmBtnOk = $("#btn_cred_revoke_confirm_ok");
  const deleteConfirmOverlay = $("#cred_delete_confirm_overlay");
  const deleteConfirmText = $("#cred_delete_confirm_text");
  const deleteConfirmDetails = $("#cred_delete_confirm_details");
  const deleteConfirmBtnCancel = $("#btn_cred_delete_confirm_cancel");
  const deleteConfirmBtnOk = $("#btn_cred_delete_confirm_ok");

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
    return raw;
  }

  function firstNonEmpty(...values) {
    for (const v of values) {
      const txt = toStringSafe(v).trim();
      if (txt) return txt;
    }
    return "";
  }

  function getGenesisPathValue() {
    return firstNonEmpty(
      toStringSafe($("#cred_revoke_genesis_path")?.value).trim(),
      window.AppState?.genesisPath
    );
  }

  function syncGenesisPathInput() {
    const genesisPath = firstNonEmpty(window.AppState?.genesisPath);
    if (!genesisPath) return "";
    if (toStringSafe($("#cred_revoke_genesis_path")?.value).trim() !== genesisPath) {
      $("#cred_revoke_genesis_path").value = genesisPath;
    }
    return genesisPath;
  }

  function normalizeText(v) {
    return toStringSafe(v).toLocaleLowerCase("pt-BR");
  }

  function formatEpoch(value) {
    const n = Number(value);
    if (!Number.isFinite(n) || n <= 0) return "";
    try {
      return new Date(n * 1000).toLocaleString();
    } catch (_) {
      return String(value);
    }
  }

  function pad2(value) {
    return String(value).padStart(2, "0");
  }

  function formatCurrentLocalDateTime() {
    const now = new Date();
    return `${pad2(now.getDate())}/${pad2(now.getMonth() + 1)}/${now.getFullYear()}, ${pad2(now.getHours())}:${pad2(now.getMinutes())}:${pad2(now.getSeconds())}`;
  }

  function refreshRevocationOperationDate(force = false) {
    const el = $("#cred_revoke_revoked_date");
    if (!el) return;
    const current = toStringSafe(el.value).trim();
    if (!force && current) return;
    el.value = formatCurrentLocalDateTime();
  }

  function shortText(value, max = 40) {
    const txt = toStringSafe(value).trim();
    if (txt.length <= max) return txt;
    return `${txt.slice(0, max)}...`;
  }

  function addUnitsUtc(baseDate, unitOfTime, amount) {
    const date = new Date(baseDate.getTime());
    switch (toStringSafe(unitOfTime).trim().toLowerCase()) {
      case "second":
      case "seconds":
        date.setUTCSeconds(date.getUTCSeconds() + amount);
        return date;
      case "minute":
      case "minutes":
        date.setUTCMinutes(date.getUTCMinutes() + amount);
        return date;
      case "hour":
      case "hours":
        date.setUTCHours(date.getUTCHours() + amount);
        return date;
      case "day":
      case "days":
        date.setUTCDate(date.getUTCDate() + amount);
        return date;
      case "week":
      case "weeks":
        date.setUTCDate(date.getUTCDate() + (amount * 7));
        return date;
      case "month":
      case "months":
        date.setUTCMonth(date.getUTCMonth() + amount);
        return date;
      case "year":
      case "years":
        date.setUTCFullYear(date.getUTCFullYear() + amount);
        return date;
      case "decade":
      case "decades":
        date.setUTCFullYear(date.getUTCFullYear() + (amount * 10));
        return date;
      default:
        return null;
    }
  }

  function getRevokeControl(summaryData) {
    const control = summaryData?.issuer_record?.control;
    return control && typeof control === "object" ? control : null;
  }

  function deriveValidWindowBounds(summaryData) {
    const control = getRevokeControl(summaryData);
    if (!control) return null;

    const baseWindowCount = Number(control?.base_window_count);
    const windowCount = Number(control?.window_count);
    const extraWindows = Number(control?.extra_windows_for_fp);
    const lastValidWindowIndex = Number(control?.last_valid_window_index);

    let maxValidWindowIndex = null;
    if (Number.isFinite(lastValidWindowIndex) && lastValidWindowIndex >= 0) {
      maxValidWindowIndex = Math.trunc(lastValidWindowIndex);
    } else if (Number.isFinite(baseWindowCount) && baseWindowCount > 0) {
      maxValidWindowIndex = Math.trunc(baseWindowCount) - 1;
    } else if (Number.isFinite(windowCount) && windowCount > 0) {
      const fallbackBase = Math.max(1, Math.trunc(windowCount) - Math.max(0, Math.trunc(extraWindows || 0)));
      maxValidWindowIndex = fallbackBase - 1;
    }

    if (!Number.isFinite(maxValidWindowIndex) || maxValidWindowIndex < 0) return null;
    return {
      minValidWindowIndex: 0,
      maxValidWindowIndex,
    };
  }

  function getCredentialStartEpoch(summaryData) {
    const control = getRevokeControl(summaryData);
    const startTime = Number(control?.start_time);
    return Number.isFinite(startTime) && startTime >= 0 ? Math.trunc(startTime) : null;
  }

  function getRevokedFromWindow(summaryData) {
    const summary = summaryData?.revocation_summary || {};
    const record = summaryData?.issuer_record || {};
    const raw = summary?.revoked_from_window ?? record?.revoked_from_window;
    const n = Number(raw);
    return Number.isFinite(n) && n >= 0 ? Math.trunc(n) : null;
  }

  function isSummaryRevoked(summaryData) {
    const summary = summaryData?.revocation_summary || {};
    const record = summaryData?.issuer_record || {};
    return firstNonEmpty(summary?.status, record?.status).toLowerCase() === "revoked";
  }

  function computeRevokedWindowEpoch(summaryData) {
    const revokedFromWindow = getRevokedFromWindow(summaryData);
    if (revokedFromWindow === null) return null;
    return computeWindowStartEpoch(getRevokeControl(summaryData), revokedFromWindow);
  }

  function computeWindowStartEpoch(control, windowIndex) {
    const startTime = Number(control?.start_time);
    const timeWindow = Number(control?.time_window);
    const unitOfTime = toStringSafe(control?.unit_of_time).trim();
    const idx = Number(windowIndex);
    if (!Number.isFinite(startTime) || startTime < 0) return null;
    if (!Number.isFinite(timeWindow) || timeWindow <= 0 || !unitOfTime) return null;
    if (!Number.isFinite(idx) || idx < 0) return null;

    let cursor = new Date(Math.trunc(startTime) * 1000);
    for (let i = 0; i < Math.trunc(idx); i += 1) {
      const next = addUnitsUtc(cursor, unitOfTime, Math.trunc(timeWindow));
      if (!next) return null;
      cursor = next;
    }
    return Math.trunc(cursor.getTime() / 1000);
  }

  function setRevokeWindowPreview(summaryData, revokeFromWindow) {
    const rangeEl = $("#cred_revoke_window_range");
    const dateEl = $("#cred_revoke_window_date");
    const inputEl = $("#cred_revoke_window");
    const bounds = deriveValidWindowBounds(summaryData);
    if (!bounds) {
      rangeEl.value = "";
      dateEl.value = "";
      inputEl.removeAttribute("max");
      return;
    }

    rangeEl.value = `${bounds.minValidWindowIndex} até ${bounds.maxValidWindowIndex}`;
    inputEl.min = String(bounds.minValidWindowIndex);
    inputEl.max = String(bounds.maxValidWindowIndex);

    const idx = Number(revokeFromWindow);
    if (!Number.isFinite(idx) || idx < bounds.minValidWindowIndex || idx > bounds.maxValidWindowIndex) {
      dateEl.value = "";
      return;
    }

    const control = getRevokeControl(summaryData);
    const windowStartEpoch = computeWindowStartEpoch(control, idx);
    dateEl.value = formatEpoch(windowStartEpoch);
  }

  function validateRevokeWindow(summaryData, revokeFromWindow) {
    if (!Number.isFinite(revokeFromWindow) || revokeFromWindow < 0) {
      return "Revoke from window inválido.";
    }
    const bounds = deriveValidWindowBounds(summaryData);
    if (!bounds) {
      return "Não foi possível determinar a faixa válida de janelas da credencial.";
    }
    const idx = Math.trunc(revokeFromWindow);
    if (idx < bounds.minValidWindowIndex || idx > bounds.maxValidWindowIndex) {
      return `Revoke from window fora da faixa válida. Use um índice entre ${bounds.minValidWindowIndex} e ${bounds.maxValidWindowIndex}.`;
    }
    return "";
  }

  function focusElementSafe(el) {
    if (!el || typeof el.focus !== "function") return false;
    try {
      el.focus({ preventScroll: true });
      return true;
    } catch (_) {
      try {
        el.focus();
        return true;
      } catch (_) {
        return false;
      }
    }
  }

  function closeRevokeConfirm(result) {
    if (!revokeConfirmResolve) return;
    const resolve = revokeConfirmResolve;
    revokeConfirmResolve = null;
    revokeConfirmOverlay.style.display = "none";
    revokeConfirmTitle.textContent = "Confirmar Revogação";
    revokeConfirmBtnCancel.textContent = "Cancelar operação";
    revokeConfirmBtnOk.style.display = "";
    const previous = revokeConfirmPrevFocused;
    revokeConfirmPrevFocused = null;
    resolve(!!result);
    window.setTimeout(() => {
      if (focusElementSafe(previous)) return;
      focusElementSafe($("#btn_cred_revoke_execute"));
    }, 0);
  }

  function closeDeleteConfirm(result) {
    if (!deleteConfirmResolve) return;
    const resolve = deleteConfirmResolve;
    deleteConfirmResolve = null;
    deleteConfirmOverlay.style.display = "none";
    const previous = deleteConfirmPrevFocused;
    deleteConfirmPrevFocused = null;
    resolve(!!result);
    window.setTimeout(() => {
      if (focusElementSafe(previous)) return;
      focusElementSafe($("#btn_cred_revoke_refresh"));
    }, 0);
  }

  function onRevokeConfirmKeydown(ev) {
    if (!revokeConfirmResolve) return;
    if (ev.key === "Escape") {
      ev.preventDefault();
      closeRevokeConfirm(false);
      return;
    }
    if (ev.key !== "Tab") return;
    const focusables = [revokeConfirmBtnCancel, revokeConfirmBtnOk]
      .filter((el) => el && el.style.display !== "none");
    if (!focusables.length) return;
    const currentIdx = Math.max(0, focusables.indexOf(document.activeElement));
    const nextIdx = ev.shiftKey
      ? (currentIdx - 1 + focusables.length) % focusables.length
      : (currentIdx + 1) % focusables.length;
    ev.preventDefault();
    focusElementSafe(focusables[nextIdx]);
  }

  function onDeleteConfirmKeydown(ev) {
    if (!deleteConfirmResolve) return;
    if (ev.key === "Escape") {
      ev.preventDefault();
      closeDeleteConfirm(false);
      return;
    }
    if (ev.key !== "Tab") return;
    const focusables = [deleteConfirmBtnCancel, deleteConfirmBtnOk].filter(Boolean);
    if (!focusables.length) return;
    const currentIdx = Math.max(0, focusables.indexOf(document.activeElement));
    const nextIdx = ev.shiftKey
      ? (currentIdx - 1 + focusables.length) % focusables.length
      : (currentIdx + 1) % focusables.length;
    ev.preventDefault();
    focusElementSafe(focusables[nextIdx]);
  }

  function openRevokeConfirm(message, detailsText, options = {}) {
    if (revokeConfirmResolve) return Promise.resolve(false);
    const infoOnly = !!options.infoOnly;
    revokeConfirmPrevFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    revokeConfirmTitle.textContent = options.title || "Confirmar Revogação";
    revokeConfirmText.textContent = String(message || "");
    revokeConfirmDetails.value = String(detailsText || "");
    revokeConfirmBtnCancel.textContent = infoOnly ? "Voltar" : "Cancelar operação";
    revokeConfirmBtnOk.style.display = infoOnly ? "none" : "";
    revokeConfirmOverlay.style.display = "flex";
    focusElementSafe(infoOnly ? revokeConfirmBtnCancel : revokeConfirmBtnOk);
    return new Promise((resolve) => {
      revokeConfirmResolve = resolve;
    });
  }

  function openDeleteConfirm(message, detailsText) {
    if (deleteConfirmResolve) return Promise.resolve(false);
    deleteConfirmPrevFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    deleteConfirmText.textContent = String(message || "");
    deleteConfirmDetails.value = String(detailsText || "");
    deleteConfirmOverlay.style.display = "flex";
    focusElementSafe(deleteConfirmBtnOk);
    return new Promise((resolve) => {
      deleteConfirmResolve = resolve;
    });
  }

  function parseListResponse(resp) {
    if (!resp?.ok) return [];
    const data = parseMaybeJson(resp.data);
    const items = Array.isArray(data?.items) ? data.items : [];
    return items
      .map((item) => parseMaybeJson(item))
      .filter((item) => item && typeof item === "object");
  }

  function getSelectedId() {
    return toStringSafe($("#cred_revoke_id_local").value).trim();
  }

  function setSelectedId(idLocal) {
    selectedId = toStringSafe(idLocal).trim();
    $("#cred_revoke_id_local").value = selectedId;
    lastSummaryData = null;
    $("#cred_revoke_window_range").value = "";
    $("#cred_revoke_window_date").value = "";
    $("#cred_revoke_revoked_date").value = "";
    $("#cred_revoke_selected_info").value = "";
    $("#cred_revoke_window").removeAttribute("max");
    syncGenesisPathInput();
    refreshRevocationOperationDate(true);
  }

  function buildSearchBlob(item) {
    return normalizeText([
      item?.issuer_local_credential_id,
      item?.holder_did_hint,
      item?.cred_def_id,
      item?.schema_id,
      item?.status,
      item?.manifest_url,
    ].join(" | "));
  }

  function getAttributeFilterQuery() {
    return {
      attrName: normalizeText($("#cred_revoke_attr_name_filter").value).trim(),
      attrValue: normalizeText($("#cred_revoke_attr_value_filter").value).trim(),
    };
  }

  function hasAttributeFilter() {
    const { attrName, attrValue } = getAttributeFilterQuery();
    return !!attrName || !!attrValue;
  }

  function extractBusinessAttributesFromSummaryData(summaryData) {
    const record = summaryData?.issuer_record || {};
    const credentialObj = parseMaybeJson(record?.credential_json);
    const allAttributes = normalizeCredentialValuesRaw(credentialObj);
    return filterBusinessAttributes(allAttributes);
  }

  function matchesAttributeFilter(attributes, attrNameQuery, attrValueQuery) {
    const entries = Object.entries(attributes || {});
    if (!entries.length) return false;

    return entries.some(([key, value]) => {
      const normalizedKey = normalizeText(key);
      const normalizedValue = normalizeText(value);
      if (attrNameQuery && !normalizedKey.includes(attrNameQuery)) return false;
      if (attrValueQuery && !normalizedValue.includes(attrValueQuery)) return false;
      return true;
    });
  }

  async function fetchIssuedSummaryData(issuerLocalCredentialId, options = {}) {
    const id = toStringSafe(issuerLocalCredentialId).trim();
    if (!id) return null;

    if (
      lastSummaryData
      && firstNonEmpty(
        lastSummaryData?.issuer_record?.issuer_local_credential_id,
        lastSummaryData?.revocation_summary?.issuer_local_credential_id
      ) === id
    ) {
      issuedSummaryCache.set(id, lastSummaryData);
      return lastSummaryData;
    }

    if (issuedSummaryCache.has(id)) {
      return issuedSummaryCache.get(id) || null;
    }

    const r = await Api.credRevoke.getIssuedSummary({ issuerLocalCredentialId: id });
    if (options.updateDebug) {
      setOut({ where: "credentialRevoke.loadSummary", input: { issuerLocalCredentialId: id }, resp: r });
      showResult(r);
    }

    if (!r?.ok) {
      throw new Error(r?.error?.message || "erro desconhecido");
    }

    const data = parseMaybeJson(r.data);
    issuedSummaryCache.set(id, data);
    return data;
  }

  async function getFilteredItems() {
    const query = normalizeText($("#cred_revoke_text_filter").value).trim();
    const { attrName, attrValue } = getAttributeFilterQuery();
    const baseItems = !query
      ? lastItems.slice()
      : lastItems.filter((item) => buildSearchBlob(item).includes(query));

    if (!attrName && !attrValue) return baseItems;

    const filtered = [];
    for (const item of baseItems) {
      const issuerLocalCredentialId = firstNonEmpty(item?.issuer_local_credential_id);
      if (!issuerLocalCredentialId) continue;
      try {
        const summaryData = await fetchIssuedSummaryData(issuerLocalCredentialId, { updateDebug: false });
        const attributes = extractBusinessAttributesFromSummaryData(summaryData);
        if (matchesAttributeFilter(attributes, attrName, attrValue)) {
          filtered.push(item);
        }
      } catch (_) {
        // Ignora itens cujo resumo não pôde ser carregado para não interromper a filtragem.
      }
    }

    return filtered;
  }

  function buildCurrentFilterCacheKey() {
    return JSON.stringify({
      text: normalizeText($("#cred_revoke_text_filter").value).trim(),
      attr: getAttributeFilterQuery(),
      totalItems: lastItems.length,
      firstId: firstNonEmpty(lastItems[0]?.issuer_local_credential_id),
      lastId: firstNonEmpty(lastItems[lastItems.length - 1]?.issuer_local_credential_id),
    });
  }

  function getPagination(items) {
    pageSize = Number($("#cred_revoke_page_size").value || 30);
    if (!Number.isFinite(pageSize) || pageSize < 1) pageSize = 30;

    const total = Array.isArray(items) ? items.length : 0;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    if (pageIndex > totalPages) pageIndex = totalPages;
    if (pageIndex < 1) pageIndex = 1;
    $("#cred_revoke_page_index").value = String(pageIndex);

    const start = (pageIndex - 1) * pageSize;
    const end = start + pageSize;
    const slice = Array.isArray(items) ? items.slice(start, end) : [];
    return { total, totalPages, start, end: Math.min(end, total), slice };
  }

  function showSummary(obj) {
    $("#cred_revoke_summary_out").value = JSON.stringify(obj || {}, null, 2);
  }

  function showPreflight(obj) {
    $("#cred_revoke_preflight_out").value = JSON.stringify(obj || {}, null, 2);
  }

  function showResult(obj) {
    $("#cred_revoke_result_out").value = JSON.stringify(obj || {}, null, 2);
  }

  function normalizeCredentialValuesRaw(record) {
    if (!record || typeof record !== "object") return {};

    const direct = record.values_raw;
    if (direct && typeof direct === "object" && !Array.isArray(direct)) return direct;

    const values = record.values;
    if (!values || typeof values !== "object" || Array.isArray(values)) return {};

    const outMap = {};
    Object.entries(values).forEach(([k, v]) => {
      if (v && typeof v === "object" && !Array.isArray(v)) {
        const raw = toStringSafe(v.raw).trim();
        if (raw) outMap[k] = raw;
      }
    });
    return outMap;
  }

  function filterBusinessAttributes(attributes) {
    const outMap = {};
    Object.entries(attributes || {}).forEach(([key, value]) => {
      if (CONTROL_ATTRIBUTE_NAMES.has(String(key))) return;
      outMap[key] = value;
    });
    return outMap;
  }

  function buildSelectedCredentialInfo(summaryData) {
    const record = summaryData?.issuer_record || {};
    const summary = summaryData?.revocation_summary || {};
    const credentialObj = parseMaybeJson(record?.credential_json);
    const allAttributes = normalizeCredentialValuesRaw(credentialObj);
    const businessAttributes = filterBusinessAttributes(allAttributes);
    const control = getRevokeControl(summaryData) || {};
    const startEpoch = getCredentialStartEpoch(summaryData);
    const validityEnd = Number(summary?.validity_end ?? record?.control?.validity_end ?? control?.validity_end);
    const baseWindowCount = Number(control?.base_window_count);
    const confirmationWindowCount = Number(control?.confirmation_window_count ?? control?.extra_windows_for_fp);
    const timeWindow = Number(control?.time_window);
    const unitOfTime = toStringSafe(control?.unit_of_time).trim();

    const lines = [
      `Data de emissão: ${startEpoch === null ? "-" : formatEpoch(startEpoch)}`,
      `Data final da validade: ${Number.isFinite(validityEnd) && validityEnd > 0 ? formatEpoch(validityEnd) : "-"}`,
    ];

    if (Number.isFinite(timeWindow) && timeWindow > 0 && unitOfTime) {
      lines.push(`Janela de validade: ${Math.trunc(timeWindow)} ${unitOfTime}`);
    }
    if (Number.isFinite(baseWindowCount) && baseWindowCount > 0) {
      lines.push(`Quantidade de janelas válidas: ${Math.trunc(baseWindowCount)}`);
    }
    if (Number.isFinite(confirmationWindowCount) && confirmationWindowCount >= 0) {
      lines.push(`Janelas extras de confirmação: ${Math.trunc(confirmationWindowCount)}`);
    }

    lines.push("");
    lines.push("Atributos da credencial:");
    lines.push(JSON.stringify(businessAttributes, null, 2));
    return lines.join("\n");
  }

  function buildRevokeConfirmationPayload(summaryData, revokeFromWindow) {
    const record = summaryData?.issuer_record || {};
    const summary = summaryData?.revocation_summary || {};
    const control = getRevokeControl(summaryData);
    const credentialObj = parseMaybeJson(record?.credential_json);
    const attributes = normalizeCredentialValuesRaw(credentialObj);
    const totalWindows = Number(summary?.window_count || record?.control?.window_count || 0);
    const remainingWindows = Number.isFinite(totalWindows)
      ? Math.max(0, totalWindows - Math.trunc(revokeFromWindow))
      : null;
    const bounds = deriveValidWindowBounds(summaryData);
    const chosenWindowStartEpoch = computeWindowStartEpoch(control, revokeFromWindow);
    const revokedFromWindow = getRevokedFromWindow(summaryData);
    const revokedWindowEpoch = computeRevokedWindowEpoch(summaryData);
    const credentialStartEpoch = getCredentialStartEpoch(summaryData);
    const operationDateText = toStringSafe($("#cred_revoke_revoked_date").value).trim() || null;

    return {
      issuer_local_credential_id: firstNonEmpty(summary?.issuer_local_credential_id, record?.issuer_local_credential_id),
      issuer_did: firstNonEmpty(summary?.issuer_did, record?.manifest?.issuer_did),
      holder_did_hint: firstNonEmpty(summary?.holder_did_hint, record?.holder_did_hint),
      schema_id: firstNonEmpty(summary?.schema_id, record?.schema_id),
      cred_def_id: firstNonEmpty(summary?.cred_def_id, record?.cred_def_id),
      status_atual: firstNonEmpty(summary?.status, record?.status),
      data_de_emissao: credentialStartEpoch === null ? null : formatEpoch(credentialStartEpoch),
      revoked_at_operacao: record?.revoked_at ? formatEpoch(record.revoked_at) : (summary?.revoked_at ? formatEpoch(summary.revoked_at) : null),
      revoked_from_window: revokedFromWindow,
      data_da_revogacao: revokedWindowEpoch === null ? null : formatEpoch(revokedWindowEpoch),
      data_hora_informada_para_operacao: operationDateText,
      revoke_from_window: Math.trunc(revokeFromWindow),
      janela_indexacao: "0-based",
      faixa_valida_janelas: bounds
        ? `${bounds.minValidWindowIndex} até ${bounds.maxValidWindowIndex}`
        : null,
      data_da_janela_escolhida: chosenWindowStartEpoch ? formatEpoch(chosenWindowStartEpoch) : null,
      janelas_afetadas_estimadas: remainingWindows,
      time_window: summary?.time_window ?? record?.control?.time_window ?? null,
      unit_of_time: firstNonEmpty(summary?.unit_of_time, record?.control?.unit_of_time),
      validity_end: summary?.validity_end ?? record?.control?.validity_end ?? null,
      manifest_url: firstNonEmpty(summary?.manifest_url, record?.manifest?.manifest_url),
      attributes,
    };
  }

  async function ensureSummaryData(issuerLocalCredentialId) {
    if (!issuerLocalCredentialId) return null;
    const data = await fetchIssuedSummaryData(issuerLocalCredentialId, { updateDebug: true });
    lastSummaryData = data;
    showSummary(data);
    $("#cred_revoke_selected_info").value = buildSelectedCredentialInfo(data);
    setRevokeWindowPreview(data, Number($("#cred_revoke_window").value || 0));
    syncGenesisPathInput();
    return data;
  }

  async function renderTable(options = {}) {
    const tbody = $("#tbl_cred_revoke tbody");
    tbody.innerHTML = "";
    const reuseFiltered = options?.reuseFiltered === true;
    const cacheKey = buildCurrentFilterCacheKey();
    const items = reuseFiltered && filteredItemsCacheKey === cacheKey
      ? filteredItemsView.slice()
      : await getFilteredItems();

    filteredItemsView = items.slice();
    filteredItemsCacheKey = cacheKey;
    const { total, totalPages, start, end, slice } = getPagination(filteredItemsView);

    if (!slice.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="7" class="small">Nenhuma credencial revogável emitida encontrada.</td>`;
      tbody.appendChild(tr);
      $("#cred_revoke_page_meta").textContent = total > 0
        ? `Total: ${total} | Página ${pageIndex}/${totalPages}`
        : "Total: 0 | Página 1/1";
      return;
    }

    slice.forEach((item) => {
      const idLocal = firstNonEmpty(item?.issuer_local_credential_id);
      const tr = document.createElement("tr");
      const windowText = `${toStringSafe(item?.time_window)} ${toStringSafe(item?.unit_of_time)}`.trim();
      tr.innerHTML = `
        <td class="mono">${shortText(idLocal, 28)}</td>
        <td class="mono">${shortText(item?.holder_did_hint, 26) || "-"}</td>
        <td class="mono">${shortText(item?.cred_def_id, 34) || "-"}</td>
        <td>${shortText(item?.status || "-", 14)}</td>
        <td>${windowText || "-"}</td>
        <td>${formatEpoch(item?.validity_end) || "-"}</td>
        <td>
          <button class="secondary" data-act="select" data-id="${idLocal}">Selecionar</button>
          <button class="secondary" data-act="summary" data-id="${idLocal}">Resumo</button>
          <button class="secondary" data-act="preflight" data-id="${idLocal}">Preflight</button>
          <button class="secondary" data-act="delete" data-id="${idLocal}">Excluir</button>
        </td>
      `;
      tbody.appendChild(tr);
    });

    tbody.querySelectorAll("button[data-act]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const idLocal = toStringSafe(btn.dataset.id).trim();
        if (!idLocal) return;
        setSelectedId(idLocal);
        if (btn.dataset.act === "select") {
          await loadSummary();
          return;
        }
        if (btn.dataset.act === "summary") {
          await loadSummary();
          return;
        }
        if (btn.dataset.act === "preflight") {
          await runPreflight();
          return;
        }
        if (btn.dataset.act === "delete") {
          await deleteIssuedRecord(idLocal);
        }
      });
    });

    $("#cred_revoke_page_meta").textContent = `Total: ${total} | Página ${pageIndex}/${totalPages} | Itens ${start + 1}-${end}`;
  }

  async function applyFilters() {
    const totalLoaded = lastItems.length;
    pageIndex = 1;
    if (hasAttributeFilter()) {
      Api.setStatus("Aplicando filtro por atributo nas credenciais revogáveis emitidas...");
    }
    await renderTable();
    if (hasAttributeFilter()) {
      Api.setStatus(`Filtro por atributo aplicado: ${filteredItemsView.length} de ${totalLoaded} credencial(is) correspondem aos critérios.`);
    }
  }

  async function refreshList() {
    const statusFilter = toStringSafe($("#cred_revoke_status_filter").value).trim();
    Api.setStatus("Carregando credenciais revogáveis emitidas pelo emissor...");
    const r = await Api.credRevoke.listIssuedRevocable({ statusFilter });
    setOut({ where: "credentialRevoke.refreshList", input: { statusFilter }, resp: r });
    showResult(r);

    if (!r?.ok) {
      Api.setStatus(`Erro listando credenciais emitidas: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    lastItems = parseListResponse(r);
    issuedSummaryCache = new Map();
    filteredItemsView = [];
    filteredItemsCacheKey = "";
    lastSummaryData = null;
    pageIndex = 1;
    await renderTable();
    Api.setStatus(`Credenciais revogáveis emitidas carregadas: ${lastItems.length}.`);
  }

  async function loadSummary() {
    const issuerLocalCredentialId = getSelectedId();
    if (!issuerLocalCredentialId) {
      Api.setStatus("Selecione uma credencial emitida para carregar o resumo.");
      return;
    }

    Api.setStatus("Carregando resumo da credencial emitida...");
    try {
      const data = await ensureSummaryData(issuerLocalCredentialId);
      setRevokeWindowPreview(data, Number($("#cred_revoke_window").value || 0));
      Api.setStatus(`Resumo carregado para ${issuerLocalCredentialId}.`);
    } catch (e) {
      Api.setStatus(`Erro carregando resumo: ${e?.message || "erro desconhecido"}`);
    }
  }

  async function runPreflight() {
    const issuerLocalCredentialId = getSelectedId();
    if (!issuerLocalCredentialId) {
      Api.setStatus("Selecione uma credencial emitida para executar o preflight.");
      return;
    }

    const revokeFromWindow = Number($("#cred_revoke_window").value || 0);
    if (!Number.isFinite(revokeFromWindow) || revokeFromWindow < 0) {
      Api.setStatus("Revoke from window inválido.");
      return;
    }

    let summaryData = null;
    try {
      summaryData = await ensureSummaryData(issuerLocalCredentialId);
    } catch (e) {
      Api.setStatus(`Erro carregando dados da credencial antes do preflight: ${e?.message || "erro desconhecido"}`);
      return;
    }

    const validationError = validateRevokeWindow(summaryData, revokeFromWindow);
    if (validationError) {
      Api.setStatus(validationError);
      return;
    }

    Api.setStatus("Executando preflight de revogação...");
    const r = await Api.credRevoke.preflight({
      issuerLocalCredentialId,
      revokeFromWindow: Math.trunc(revokeFromWindow),
    });
    setOut({
      where: "credentialRevoke.preflight",
      input: { issuerLocalCredentialId, revokeFromWindow: Math.trunc(revokeFromWindow) },
      resp: r,
    });
    showResult(r);

    if (!r?.ok) {
      Api.setStatus(`Erro no preflight: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    const data = parseMaybeJson(r.data);
    showPreflight(data);
    Api.setStatus(data?.can_revoke
      ? "Preflight de revogação aprovado."
      : "Preflight concluído: a credencial ainda não pode ser revogada com esses parâmetros.");
  }

  async function executeRevoke() {
    const issuerLocalCredentialId = getSelectedId();
    const genesisPath = getGenesisPathValue();
    const bloomAdminToken = toStringSafe($("#cred_revoke_token").value).trim();
    const revokeFromWindow = Number($("#cred_revoke_window").value || 0);
    const reason = toStringSafe($("#cred_revoke_reason").value).trim() || null;
    const requestedBy = toStringSafe($("#cred_revoke_requested_by").value).trim() || null;

    if (!issuerLocalCredentialId) {
      Api.setStatus("Selecione uma credencial emitida para revogar.");
      return;
    }
    if (genesisPath && toStringSafe($("#cred_revoke_genesis_path").value).trim() !== genesisPath) {
      $("#cred_revoke_genesis_path").value = genesisPath;
    }

    let summaryData = null;
    try {
      summaryData = await ensureSummaryData(issuerLocalCredentialId);
    } catch (e) {
      Api.setStatus(`Erro carregando dados da credencial antes da revogação: ${e?.message || "erro desconhecido"}`);
      return;
    }

    if (isSummaryRevoked(summaryData)) {
      const revokedFromWindow = getRevokedFromWindow(summaryData);
      const displayWindow = revokedFromWindow === null
        ? (Number.isFinite(revokeFromWindow) && revokeFromWindow >= 0 ? Math.trunc(revokeFromWindow) : 0)
        : revokedFromWindow;
      const infoPayload = buildRevokeConfirmationPayload(summaryData, displayWindow);
      await openRevokeConfirm(
        "Esta credencial já está marcada como revogada no wallet do emissor. Nenhuma nova escrita será feita no Bloom filter.",
        JSON.stringify(infoPayload, null, 2),
        {
          title: "Credencial já revogada",
          infoOnly: true,
        }
      );
      Api.setStatus("A credencial selecionada já está revogada.");
      return;
    }

    if (!genesisPath) {
      Api.setStatus("Informe o Genesis path para atualizar o manifesto no ledger.");
      return;
    }
    if (!bloomAdminToken) {
      Api.setStatus("Informe o Bloom admin token.");
      return;
    }
    if (!Number.isFinite(revokeFromWindow) || revokeFromWindow < 0) {
      Api.setStatus("Revoke from window inválido.");
      return;
    }

    const validationError = validateRevokeWindow(summaryData, revokeFromWindow);
    if (validationError) {
      Api.setStatus(validationError);
      return;
    }

    const confirmPayload = buildRevokeConfirmationPayload(summaryData, revokeFromWindow);
    const confirmed = await openRevokeConfirm(
      `A revogação será aplicada na janela ${Math.trunc(revokeFromWindow)} e em todas as janelas posteriores da credencial selecionada.`,
      JSON.stringify(confirmPayload, null, 2)
    );
    if (!confirmed) {
      Api.setStatus("Operação de revogação cancelada.");
      return;
    }

    Api.setStatus("Revogando credencial e escrevendo nas janelas subsequentes...");
    const r = await Api.credRevoke.execute({
      issuerLocalCredentialId,
      genesisPath,
      bloomAdminToken,
      revokeFromWindow: Math.trunc(revokeFromWindow),
      reason,
      requestedBy,
    });
    setOut({
      where: "credentialRevoke.execute",
      input: {
        issuerLocalCredentialId,
        revokeFromWindow: Math.trunc(revokeFromWindow),
        reason,
        requestedBy,
      },
      resp: r,
    });
    showResult(r);

    if (!r?.ok) {
      Api.setStatus(`Erro revogando credencial: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    const data = parseMaybeJson(r.data);
    showPreflight(data);
    Api.setStatus(data?.manifestWrite?.ok === false
      ? `Credencial revogada a partir da janela ${Math.trunc(revokeFromWindow)}, mas houve falha ao atualizar o manifesto no ledger.`
      : `Credencial revogada a partir da janela ${Math.trunc(revokeFromWindow)} e manifesto atualizado no ledger.`);
    await refreshList();
    await loadSummary();
  }

  async function deleteIssuedRecord(idLocalInput) {
    const issuerLocalCredentialId = toStringSafe(idLocalInput || getSelectedId()).trim();
    if (!issuerLocalCredentialId) {
      Api.setStatus("Selecione uma credencial emitida para excluir.");
      return;
    }

    const item = lastItems.find((entry) => firstNonEmpty(entry?.issuer_local_credential_id) === issuerLocalCredentialId) || null;
    const details = {
      issuer_local_credential_id: issuerLocalCredentialId,
      holder_did_hint: firstNonEmpty(item?.holder_did_hint),
      cred_def_id: firstNonEmpty(item?.cred_def_id),
      schema_id: firstNonEmpty(item?.schema_id),
      status: firstNonEmpty(item?.status),
      validity_end: formatEpoch(item?.validity_end) || null,
      observacao: "A exclusão remove apenas o registro local do emissor. O Bloom Filter continua sendo a fonte de verdade para revogações já publicadas.",
    };

    const confirmed = await openDeleteConfirm(
      `Deseja excluir o registro local da credencial emitida ${issuerLocalCredentialId}?`,
      JSON.stringify(details, null, 2)
    );
    if (!confirmed) {
      Api.setStatus("Operação de exclusão cancelada.");
      return;
    }

    Api.setStatus("Excluindo registro local da credencial emitida...");
    const r = await Api.credRevoke.deleteIssued({ issuerLocalCredentialId });
    setOut({
      where: "credentialRevoke.deleteIssued",
      input: { issuerLocalCredentialId },
      resp: r,
    });
    showResult(r);

    if (!r?.ok) {
      Api.setStatus(`Erro excluindo registro emitido: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    if (getSelectedId() === issuerLocalCredentialId) {
      setSelectedId("");
      $("#cred_revoke_summary_out").value = "";
      $("#cred_revoke_preflight_out").value = "";
    }

    await refreshList();
    Api.setStatus(`Registro local emitido excluído: ${issuerLocalCredentialId}.`);
  }

  $("#btn_cred_revoke_refresh").addEventListener("click", refreshList);
  $("#btn_cred_revoke_search").addEventListener("click", applyFilters);
  $("#btn_cred_revoke_clear").addEventListener("click", () => {
    $("#cred_revoke_status_filter").value = "";
    $("#cred_revoke_text_filter").value = "";
    $("#cred_revoke_attr_name_filter").value = "";
    $("#cred_revoke_attr_value_filter").value = "";
    pageIndex = 1;
    filteredItemsCacheKey = "";
    renderTable().catch(() => {});
  });
  $("#cred_revoke_status_filter").addEventListener("change", refreshList);
  $("#cred_revoke_text_filter").addEventListener("input", () => {
    if (hasAttributeFilter()) return;
    pageIndex = 1;
    filteredItemsCacheKey = "";
    renderTable().catch(() => {});
  });
  $("#cred_revoke_attr_name_filter").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") applyFilters().catch(() => {});
  });
  $("#cred_revoke_attr_value_filter").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") applyFilters().catch(() => {});
  });
  $("#cred_revoke_page_size").addEventListener("change", () => {
    pageIndex = 1;
    renderTable({ reuseFiltered: true }).catch(() => {});
  });
  $("#btn_cred_revoke_first").addEventListener("click", () => {
    pageIndex = 1;
    renderTable({ reuseFiltered: true }).catch(() => {});
  });
  $("#btn_cred_revoke_prev").addEventListener("click", () => {
    pageIndex -= 1;
    renderTable({ reuseFiltered: true }).catch(() => {});
  });
  $("#btn_cred_revoke_next").addEventListener("click", () => {
    pageIndex += 1;
    renderTable({ reuseFiltered: true }).catch(() => {});
  });
  $("#btn_cred_revoke_last").addEventListener("click", () => {
    pageSize = Number($("#cred_revoke_page_size").value || 30);
    if (!Number.isFinite(pageSize) || pageSize < 1) pageSize = 30;
    const totalPages = Math.max(1, Math.ceil(filteredItemsView.length / pageSize));
    pageIndex = totalPages;
    renderTable({ reuseFiltered: true }).catch(() => {});
  });
  $("#cred_revoke_page_index").addEventListener("change", () => {
    const v = Number($("#cred_revoke_page_index").value);
    if (!Number.isNaN(v) && v >= 1) pageIndex = Math.trunc(v);
    renderTable({ reuseFiltered: true }).catch(() => {});
  });
  $("#cred_revoke_genesis_path").addEventListener("change", () => {
    window.AppState = window.AppState || {};
    window.AppState.genesisPath = toStringSafe($("#cred_revoke_genesis_path").value).trim();
  });
  $("#cred_revoke_window").addEventListener("input", async () => {
    const revokeFromWindow = Number($("#cred_revoke_window").value || 0);
    if (lastSummaryData) {
      setRevokeWindowPreview(lastSummaryData, revokeFromWindow);
      return;
    }
    const issuerLocalCredentialId = getSelectedId();
    if (!issuerLocalCredentialId) return;
    try {
      const data = await ensureSummaryData(issuerLocalCredentialId);
      setRevokeWindowPreview(data, revokeFromWindow);
    } catch (_) {
      // Status errors are shown in explicit actions; keep typing lightweight here.
    }
  });
  $("#cred_revoke_window").addEventListener("change", async () => {
    const revokeFromWindow = Number($("#cred_revoke_window").value || 0);
    if (lastSummaryData) {
      setRevokeWindowPreview(lastSummaryData, revokeFromWindow);
      return;
    }
    const issuerLocalCredentialId = getSelectedId();
    if (!issuerLocalCredentialId) return;
    try {
      const data = await ensureSummaryData(issuerLocalCredentialId);
      setRevokeWindowPreview(data, revokeFromWindow);
    } catch (_) {
      // No-op: explicit actions already surface errors.
    }
  });
  $("#btn_cred_revoke_load_summary").addEventListener("click", loadSummary);
  $("#btn_cred_revoke_preflight").addEventListener("click", runPreflight);
  $("#btn_cred_revoke_execute").addEventListener("click", executeRevoke);
  revokeConfirmBtnCancel.addEventListener("click", () => closeRevokeConfirm(false));
  revokeConfirmBtnOk.addEventListener("click", () => closeRevokeConfirm(true));
  revokeConfirmOverlay.addEventListener("click", (ev) => {
    if (ev.target === revokeConfirmOverlay) closeRevokeConfirm(false);
  });
  revokeConfirmOverlay.addEventListener("keydown", onRevokeConfirmKeydown);
  deleteConfirmBtnCancel.addEventListener("click", () => closeDeleteConfirm(false));
  deleteConfirmBtnOk.addEventListener("click", () => closeDeleteConfirm(true));
  deleteConfirmOverlay.addEventListener("click", (ev) => {
    if (ev.target === deleteConfirmOverlay) closeDeleteConfirm(false);
  });
  deleteConfirmOverlay.addEventListener("keydown", onDeleteConfirmKeydown);

  syncGenesisPathInput();
  refreshRevocationOperationDate(true);
  refreshList().catch(() => {});
  return {};
})();
