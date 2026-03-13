// src/renderer/js/pages/credential-list.js
/* eslint-disable no-console */

const CredentialListPage = (() => {
  const root = document.getElementById("page-credential-list");
  if (!root) return {};

  let lastItems = [];
  let pageIndex = 1;
  let pageSize = 30;

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
          <label>Registro completo</label>
          <textarea id="cred_record_out" rows="10" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="cred_list_out">{}</pre>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#cred_list_out");

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

  function applyClientFilter(items) {
    const query = toStringSafe($("#cred_filter_text").value).trim().toLowerCase();
    if (!query) return items;
    return items.filter((rec) => buildSearchBlob(rec).includes(query));
  }

  function clearDetails() {
    $("#cred_attrs_out").value = "";
    $("#cred_record_out").value = "";
  }

  function showRecord(rec) {
    const attrs = rec?.values_raw && typeof rec.values_raw === "object" ? rec.values_raw : {};
    $("#cred_attrs_out").value = JSON.stringify(attrs, null, 2);
    $("#cred_record_out").value = JSON.stringify(rec || {}, null, 2);
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

  function clearFilters() {
    $("#cred_filter_schema_id").value = "";
    $("#cred_filter_creddef_id").value = "";
    $("#cred_filter_text").value = "";
    refreshList().catch(() => {});
  }

  $("#btn_cred_list_refresh").addEventListener("click", refreshList);
  $("#btn_cred_list_search").addEventListener("click", refreshList);
  $("#btn_cred_list_clear").addEventListener("click", clearFilters);
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

  $("#tbl_cred_list").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-act]");
    const tr = ev.target.closest("tr[data-idx]");
    if (!btn || !tr) return;

    const idx = Number(tr.dataset.idx);
    const rec = Number.isFinite(idx) ? lastItems[idx] : null;
    if (!rec) return;

    if (btn.dataset.act === "view") {
      showRecord(rec);
      Api.setStatus(`Visualizando atributos da credencial: ${toStringSafe(rec.id_local)}`);
    }
  });

  refreshList().catch(() => {});
  return {};
})();
