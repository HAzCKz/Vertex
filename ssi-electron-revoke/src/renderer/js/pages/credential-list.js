// src/renderer/js/pages/credential-list.js
/* eslint-disable no-console */

const CredentialListPage = (() => {
  const root = document.getElementById("page-credential-list");
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
  let pageIndex = 1;
  let pageSize = 30;
  let selectedRecord = null;
  let confirmResolve = null;
  let confirmPrevFocused = null;
  let confirmFallbackSelector = "#btn_cred_delete_selected";

  root.innerHTML = `
    <div class="card">
      <h2>Listar Credenciais</h2>
      <p class="small">
        Lista credenciais salvas na wallet, permite filtrar e visualizar os atributos.
      </p>

      <div class="row">
        <button class="secondary" id="btn_cred_list_refresh">Atualizar lista</button>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>Filtros</h3>

      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Schema ID (opcional, exato)</label>
          <input id="cred_filter_schema_id" placeholder="ex.: V4SG...:2:nome:1.0" />
        </div>

        <div class="input" style="min-width:360px">
          <label>CredDef ID (opcional, exato)</label>
          <input id="cred_filter_creddef_id" placeholder="ex.: V4SG...:3:CL:...:TAG" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:420px">
          <label>Busca livre (id/schema/creddef/atributos)</label>
          <input id="cred_filter_text" placeholder="ex.: cpf, nome, 123..." />
        </div>

        <button class="secondary" id="btn_cred_list_search">Buscar</button>
        <button class="secondary" id="btn_cred_list_clear">Limpar filtros</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:220px">
          <label>Atributo da credencial</label>
          <input id="cred_filter_attr_name" placeholder="ex.: nome" />
        </div>
        <div class="input" style="min-width:420px">
          <label>Conteúdo do atributo</label>
          <input id="cred_filter_attr_value" placeholder="ex.: Mariana Dias" />
        </div>
      </div>

      <div class="row" style="align-items:flex-end">
        <div class="input" style="min-width:180px">
          <label>Itens por página</label>
          <select id="cred_page_size">
            <option value="20">20</option>
            <option value="30" selected>30</option>
            <option value="50">50</option>
            <option value="100">100</option>
            <option value="200">200</option>
          </select>
        </div>
        <button class="secondary" id="btn_cred_first">⏮ Primeiro</button>
        <button class="secondary" id="btn_cred_prev">◀ Prev</button>
        <div class="input" style="min-width:120px">
          <label>Página</label>
          <input id="cred_page_index" value="1" />
        </div>
        <button class="secondary" id="btn_cred_next">Next ▶</button>
        <button class="secondary" id="btn_cred_last">Último ⏭</button>
        <div class="small" id="cred_page_meta"></div>
      </div>

      <div class="tableWrap">
        <table class="table" id="tbl_cred_list">
          <thead>
            <tr>
              <th>ID local</th>
              <th>Schema ID</th>
              <th>CredDef ID</th>
              <th>Atributos</th>
              <th>Armazenada em</th>
              <th>Ações</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Atributos (values_raw)</label>
          <textarea id="cred_attrs_out" rows="8" readonly></textarea>
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Validade da credencial</label>
          <textarea id="cred_validity_out" rows="4" readonly></textarea>
        </div>
      </div>

      <div class="row">
        <button class="secondary" id="btn_cred_delete_selected">Deletar credencial</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Registro completo</label>
          <textarea id="cred_record_out" rows="10" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="cred_list_out">{}</pre>
    </div>
    <div id="cred_confirm_overlay" style="display:none; position:fixed; inset:0; z-index:9999; background:rgba(17,24,39,0.35); align-items:center; justify-content:center; padding:16px;">
      <div style="width:min(100%, 420px); background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:16px; box-shadow:0 10px 30px rgba(17,24,39,0.2);">
        <h3 style="margin:0 0 8px 0;">Confirmar ação</h3>
        <p id="cred_confirm_text" style="margin:0; color:#111827;"></p>
        <div class="row" style="margin-top:16px; justify-content:flex-end;">
          <button class="secondary" id="btn_cred_confirm_cancel">Cancelar</button>
          <button class="primary" id="btn_cred_confirm_ok">Confirmar</button>
        </div>
      </div>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#cred_list_out");
  const confirmOverlay = $("#cred_confirm_overlay");
  const confirmText = $("#cred_confirm_text");
  const confirmBtnOk = $("#btn_cred_confirm_ok");
  const confirmBtnCancel = $("#btn_cred_confirm_cancel");

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
    for (const value of values) {
      const txt = toStringSafe(value).trim();
      if (txt) return txt;
    }
    return "";
  }

  function normalizeValuesRaw(rec) {
    if (!rec || typeof rec !== "object") return {};

    const direct = rec.values_raw;
    if (direct && typeof direct === "object" && !Array.isArray(direct)) return direct;

    const values = rec.values;
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

  function parseCredentialsList(rawData) {
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
        id_local: toStringSafe(rec.id_local || rec.id).trim(),
        schema_id: toStringSafe(rec.schema_id || rec.schemaId).trim(),
        cred_def_id: toStringSafe(rec.cred_def_id || rec.credDefId).trim(),
        stored_at: toStringSafe(rec.stored_at || rec.storedAt).trim(),
        values_raw: normalizeValuesRaw(rec),
      }));
  }

  function formatStoredAt(storedAtRaw) {
    const txt = toStringSafe(storedAtRaw).trim();
    if (!txt) return "";
    const n = Number(txt);
    if (!Number.isFinite(n) || n <= 0) return txt;
    const ms = n > 1_000_000_000_000 ? n : n * 1000;
    try {
      return new Date(ms).toLocaleString();
    } catch (_) {
      return txt;
    }
  }

  function pad2(value) {
    return String(value).padStart(2, "0");
  }

  function formatUtcDate(date) {
    return `${pad2(date.getUTCDate())}/${pad2(date.getUTCMonth() + 1)}/${date.getUTCFullYear()}`;
  }

  function formatUtcDateTime(date) {
    return `${formatUtcDate(date)} ${pad2(date.getUTCHours())}:${pad2(date.getUTCMinutes())}:${pad2(date.getUTCSeconds())} UTC`;
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

  function computeCredentialValidityText(attrs) {
    const startTimeRaw = toStringSafe(attrs?.start_time).trim();
    const timeWindowRaw = toStringSafe(attrs?.time_window).trim();
    const unitOfTime = toStringSafe(attrs?.unit_of_time).trim();

    if (!startTimeRaw || !timeWindowRaw || !unitOfTime) {
      return "";
    }

    const startTime = Number(startTimeRaw);
    const timeWindow = Number(timeWindowRaw);
    if (!Number.isFinite(startTime) || startTime < 0 || !Number.isFinite(timeWindow) || timeWindow <= 0) {
      return "";
    }

    const startDate = new Date(Math.trunc(startTime) * 1000);
    const nextBoundary = addUnitsUtc(startDate, unitOfTime, Math.trunc(timeWindow));
    if (!nextBoundary) return "";

    const validityEndEpoch = Math.trunc(nextBoundary.getTime() / 1000) - 1;
    if (!Number.isFinite(validityEndEpoch) || validityEndEpoch < Math.trunc(startTime)) {
      return "";
    }

    const validityEndDate = new Date(validityEndEpoch * 1000);
    return [
      `Data inicial: ${formatUtcDateTime(startDate)}`,
      `Data final da validade: ${formatUtcDateTime(validityEndDate)}`,
      `Janela de validade: ${Math.trunc(timeWindow)} ${unitOfTime}`,
    ].join("\n");
  }

  function isLikelyRevocableCredential(attrs) {
    return !!(
      toStringSafe(attrs?.seed).trim()
      && toStringSafe(attrs?.start_time).trim()
      && toStringSafe(attrs?.unit_of_time).trim()
      && toStringSafe(attrs?.time_window).trim()
      && (toStringSafe(attrs?.root_merkle_L).trim() || toStringSafe(attrs?.root_merkle_l).trim())
    );
  }

  function deriveHolderBundleId(rec) {
    const credentialId = toStringSafe(rec?.id_local || rec?.id).trim();
    if (!credentialId) return "";
    return `revocation-bundle-${credentialId}`;
  }

  function computeCredentialValidityTextFromBundle(attrs, bundle) {
    const control = bundle?.holder_bundle?.control || bundle?.control || {};
    const startTime = Number(firstNonEmpty(control?.start_time, attrs?.start_time));
    const validityEnd = Number(control?.validity_end);
    const timeWindow = Number(firstNonEmpty(control?.time_window, attrs?.time_window));
    const unitOfTime = toStringSafe(firstNonEmpty(control?.unit_of_time, attrs?.unit_of_time)).trim();
    const baseWindowCount = Number(control?.base_window_count);
    const confirmationWindowCount = Number(firstNonEmpty(control?.confirmation_window_count, control?.extra_windows_for_fp));

    if (!Number.isFinite(startTime) || startTime < 0 || !Number.isFinite(validityEnd) || validityEnd < startTime) {
      return computeCredentialValidityText(attrs);
    }

    const startDate = new Date(Math.trunc(startTime) * 1000);
    const validityEndDate = new Date(Math.trunc(validityEnd) * 1000);
    const lines = [
      `Data inicial: ${formatUtcDateTime(startDate)}`,
      `Data final da validade: ${formatUtcDateTime(validityEndDate)}`,
      `Janela de validade: ${Number.isFinite(timeWindow) && timeWindow > 0 ? Math.trunc(timeWindow) : "-"} ${unitOfTime || ""}`.trim(),
    ];

    if (Number.isFinite(baseWindowCount) && baseWindowCount > 0) {
      lines.push(`Quantidade de janelas válidas: ${Math.trunc(baseWindowCount)}`);
    }
    if (Number.isFinite(confirmationWindowCount) && confirmationWindowCount >= 0) {
      lines.push(`Janelas extras de confirmação: ${Math.trunc(confirmationWindowCount)}`);
    }

    return lines.join("\n");
  }

  function shortText(txt, max = 42) {
    const s = toStringSafe(txt).trim();
    if (s.length <= max) return s;
    return `${s.slice(0, max)}...`;
  }

  function buildSearchBlob(rec) {
    const attrs = rec.values_raw && typeof rec.values_raw === "object"
      ? Object.entries(rec.values_raw).map(([k, v]) => `${k}:${toStringSafe(v)}`).join(" ")
      : "";

    return [
      rec.id_local,
      rec.schema_id,
      rec.cred_def_id,
      attrs,
      toStringSafe(rec.stored_at),
    ]
      .map((v) => toStringSafe(v).toLowerCase())
      .join(" | ");
  }

  function getAttributeFilterQuery() {
    return {
      attrName: toStringSafe($("#cred_filter_attr_name").value).trim().toLowerCase(),
      attrValue: toStringSafe($("#cred_filter_attr_value").value).trim().toLowerCase(),
    };
  }

  function matchesCredentialAttributeFilter(rec, attrNameQuery, attrValueQuery) {
    const values = filterBusinessAttributes(normalizeValuesRaw(rec));
    const entries = Object.entries(values);
    if (!entries.length) return false;

    return entries.some(([key, value]) => {
      const normalizedKey = toStringSafe(key).trim().toLowerCase();
      const normalizedValue = toStringSafe(value).trim().toLowerCase();
      if (attrNameQuery && !normalizedKey.includes(attrNameQuery)) return false;
      if (attrValueQuery && !normalizedValue.includes(attrValueQuery)) return false;
      return true;
    });
  }

  function applyClientFilter(items) {
    const query = toStringSafe($("#cred_filter_text").value).trim().toLowerCase();
    const { attrName, attrValue } = getAttributeFilterQuery();
    const baseItems = !query
      ? items
      : items.filter((rec) => buildSearchBlob(rec).includes(query));

    if (!attrName && !attrValue) return baseItems;
    return baseItems.filter((rec) => matchesCredentialAttributeFilter(rec, attrName, attrValue));
  }

  function clearDetails() {
    selectedRecord = null;
    $("#cred_attrs_out").value = "";
    $("#cred_validity_out").value = "";
    $("#cred_record_out").value = "";
  }

  async function showRecord(rec) {
    selectedRecord = rec || null;
    const attrs = rec?.values_raw && typeof rec.values_raw === "object" ? rec.values_raw : {};
    $("#cred_attrs_out").value = JSON.stringify(attrs, null, 2);
    $("#cred_record_out").value = JSON.stringify(rec || {}, null, 2);
    $("#cred_validity_out").value = computeCredentialValidityText(attrs);

    if (!isLikelyRevocableCredential(attrs)) return;

    const bundleIdLocal = deriveHolderBundleId(rec);
    if (!bundleIdLocal) return;

    $("#cred_validity_out").value = "Calculando validade da credencial revogável...";
    const bundleResp = await Api.revocationVerify.getHolderBundle({ bundleIdLocal });
    setOut({
      where: "credential.list.showRecord.bundleLookup",
      input: { credentialIdLocal: toStringSafe(rec?.id_local), bundleIdLocal },
      resp: bundleResp,
    });

    if (!bundleResp?.ok) {
      $("#cred_validity_out").value = computeCredentialValidityText(attrs);
      return;
    }

    const bundleObj = parseMaybeJson(bundleResp.data) || {};
    $("#cred_validity_out").value = computeCredentialValidityTextFromBundle(attrs, bundleObj);
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

  function closeInlineConfirm(result) {
    if (!confirmResolve) return;
    const resolve = confirmResolve;
    confirmResolve = null;
    confirmOverlay.style.display = "none";
    const previous = confirmPrevFocused;
    const fallbackSelector = confirmFallbackSelector;
    confirmPrevFocused = null;
    confirmFallbackSelector = "#btn_cred_delete_selected";
    resolve(!!result);
    window.setTimeout(() => {
      if (focusElementSafe(previous)) return;
      const fallbackEl = fallbackSelector ? root.querySelector(fallbackSelector) : null;
      focusElementSafe(fallbackEl);
    }, 0);
  }

  function onInlineConfirmKeydown(ev) {
    if (!confirmResolve) return;
    if (ev.key === "Escape") {
      ev.preventDefault();
      closeInlineConfirm(false);
      return;
    }
    if (ev.key !== "Tab") return;
    const focusables = [confirmBtnCancel, confirmBtnOk].filter(Boolean);
    if (!focusables.length) return;
    const currentIdx = Math.max(0, focusables.indexOf(document.activeElement));
    const nextIdx = ev.shiftKey
      ? (currentIdx - 1 + focusables.length) % focusables.length
      : (currentIdx + 1) % focusables.length;
    ev.preventDefault();
    focusElementSafe(focusables[nextIdx]);
  }

  function openInlineConfirm(message, fallbackSelector) {
    if (confirmResolve) return Promise.resolve(false);
    confirmPrevFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    confirmFallbackSelector = fallbackSelector || "#btn_cred_delete_selected";
    confirmText.textContent = String(message || "");
    confirmOverlay.style.display = "flex";
    focusElementSafe(confirmBtnOk);
    return new Promise((resolve) => {
      confirmResolve = resolve;
    });
  }

  function getPagination() {
    pageSize = Number($("#cred_page_size").value || 30);
    if (!Number.isFinite(pageSize) || pageSize < 1) pageSize = 30;

    const total = lastItems.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    if (pageIndex > totalPages) pageIndex = totalPages;
    if (pageIndex < 1) pageIndex = 1;
    $("#cred_page_index").value = String(pageIndex);

    const start = (pageIndex - 1) * pageSize;
    const end = start + pageSize;
    const slice = lastItems.slice(start, end);
    return { total, totalPages, start, end: Math.min(end, total), slice };
  }

  function renderTable() {
    const tbody = $("#tbl_cred_list tbody");
    tbody.innerHTML = "";
    const { total, totalPages, start, end, slice } = getPagination();

    slice.forEach((rec, idx) => {
      const id = toStringSafe(rec.id_local).trim();
      const attrKeys = rec.values_raw && typeof rec.values_raw === "object"
        ? Object.keys(rec.values_raw)
        : [];

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">${id}</td>
        <td class="mono" title="${toStringSafe(rec.schema_id)}">${shortText(rec.schema_id, 36)}</td>
        <td class="mono" title="${toStringSafe(rec.cred_def_id)}">${shortText(rec.cred_def_id, 36)}</td>
        <td title="${attrKeys.join(", ")}">${shortText(attrKeys.join(", "), 34)}</td>
        <td>${formatStoredAt(rec.stored_at)}</td>
        <td>
          <div class="actions">
            <button data-act="view">Ver atributos</button>
            <button data-act="del">Excluir</button>
          </div>
        </td>
      `;
      tr.dataset.idx = String(start + idx);
      tbody.appendChild(tr);
    });

    if (total > 0) {
      $("#cred_page_meta").textContent = `Total: ${total} | Página ${pageIndex}/${totalPages} | Itens ${start + 1}-${end}`;
    } else {
      $("#cred_page_meta").textContent = "Total: 0 | Página 1/1";
    }
  }

  async function refreshList() {
    const schemaIdEq = toStringSafe($("#cred_filter_schema_id").value).trim() || null;
    const credDefIdEq = toStringSafe($("#cred_filter_creddef_id").value).trim() || null;

    Api.setStatus("Listando credenciais da wallet...");
    const r = await Api.credential.list(schemaIdEq, credDefIdEq);
    setOut({ where: "credential.list", input: { schemaIdEq, credDefIdEq }, resp: r });

    if (!r?.ok) {
      Api.setStatus(`Erro listando credenciais: ${r?.error?.message || "erro desconhecido"}`);
      lastItems = [];
      pageIndex = 1;
      renderTable();
      clearDetails();
      return;
    }

    const parsed = parseCredentialsList(r.data);
    const filtered = applyClientFilter(parsed);
    lastItems = filtered;
    pageIndex = 1;
    renderTable();
    clearDetails();
    Api.setStatus(`Credenciais carregadas: ${filtered.length}.`);
  }

  async function deleteSelectedCredential(rec) {
    const id = toStringSafe(rec?.id_local).trim();
    if (!id) {
      Api.setStatus("Selecione uma credencial válida para excluir.");
      return;
    }

    const ok = await openInlineConfirm(`Excluir credencial local "${id}"?`, "#btn_cred_delete_selected");
    if (!ok) return;

    Api.setStatus(`Excluindo credencial ${id}...`);
    const r = await Api.credential.delete(id);
    setOut({ where: "credential.delete", input: { credentialIdLocal: id }, resp: r });

    if (!r?.ok) {
      Api.setStatus(`Erro excluindo credencial: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    const data = parseMaybeJson(r.data) || r;
    const deletedBundles = Array.isArray(data?.holder_bundle_ids_deleted)
      ? data.holder_bundle_ids_deleted.length
      : 0;

    await refreshList();
    clearDetails();
    Api.setStatus(`Credencial excluída: ${id}${deletedBundles ? ` | bundles removidos: ${deletedBundles}` : ""}`);
  }

  function clearFilters() {
    $("#cred_filter_schema_id").value = "";
    $("#cred_filter_creddef_id").value = "";
    $("#cred_filter_text").value = "";
    $("#cred_filter_attr_name").value = "";
    $("#cred_filter_attr_value").value = "";
    refreshList().catch(() => {});
  }

  $("#btn_cred_list_refresh").addEventListener("click", refreshList);
  $("#btn_cred_list_search").addEventListener("click", refreshList);
  $("#btn_cred_list_clear").addEventListener("click", clearFilters);
  $("#btn_cred_delete_selected").addEventListener("click", () => {
    if (!selectedRecord) {
      Api.setStatus("Selecione uma credencial antes de excluir.");
      return;
    }
    deleteSelectedCredential(selectedRecord).catch(() => {});
  });
  confirmBtnOk.addEventListener("click", () => closeInlineConfirm(true));
  confirmBtnCancel.addEventListener("click", () => closeInlineConfirm(false));
  confirmOverlay.addEventListener("click", (ev) => {
    if (ev.target === confirmOverlay) closeInlineConfirm(false);
  });
  document.addEventListener("keydown", onInlineConfirmKeydown, true);
  $("#cred_page_size").addEventListener("change", () => {
    pageIndex = 1;
    renderTable();
  });
  $("#btn_cred_first").addEventListener("click", () => {
    pageIndex = 1;
    renderTable();
  });
  $("#btn_cred_prev").addEventListener("click", () => {
    pageIndex -= 1;
    renderTable();
  });
  $("#btn_cred_next").addEventListener("click", () => {
    pageIndex += 1;
    renderTable();
  });
  $("#btn_cred_last").addEventListener("click", () => {
    pageSize = Number($("#cred_page_size").value || 30);
    if (!Number.isFinite(pageSize) || pageSize < 1) pageSize = 30;
    const totalPages = Math.max(1, Math.ceil(lastItems.length / pageSize));
    pageIndex = totalPages;
    renderTable();
  });
  $("#cred_page_index").addEventListener("change", () => {
    const n = Number($("#cred_page_index").value);
    if (Number.isFinite(n)) pageIndex = Math.trunc(n);
    renderTable();
  });
  $("#cred_page_index").addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter") return;
    const n = Number($("#cred_page_index").value);
    if (Number.isFinite(n)) pageIndex = Math.trunc(n);
    renderTable();
  });

  $("#tbl_cred_list").addEventListener("click", async (ev) => {
    const btn = ev.target.closest("button[data-act]");
    const tr = ev.target.closest("tr[data-idx]");
    if (!btn || !tr) return;

    const idx = Number(tr.dataset.idx);
    const rec = Number.isFinite(idx) ? lastItems[idx] : null;
    if (!rec) return;

    if (btn.dataset.act === "view") {
      await showRecord(rec);
      Api.setStatus(`Visualizando atributos da credencial: ${toStringSafe(rec.id_local)}`);
      return;
    }

    if (btn.dataset.act === "del") {
      await showRecord(rec);
      deleteSelectedCredential(rec).catch(() => {});
    }
  });

  refreshList().catch(() => {});
  return {};
})();
