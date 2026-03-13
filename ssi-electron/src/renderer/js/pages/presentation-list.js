// src/renderer/js/pages/presentation-list.js
/* eslint-disable no-console */

const PresentationListPage = (() => {
  const root = document.getElementById("page-presentation-list");
  if (!root) return {};
  const DEFAULT_DID_LIMIT = 150;
  const MAX_DID_LIMIT = 1000;

  let ownDidOptions = [];
  let visibleOwnDidOptions = [];
  let recipientOptions = [];
  let visibleRecipientOptions = [];
  let allItems = [];
  let filteredItems = [];
  let listPageIndex = 1;
  let listPageSize = 30;
  let selectedPresentationId = "";
  let revealedSort = { key: "", dir: "asc" };
  let predicateSort = { key: "", dir: "asc" };
  let revealedItemsCache = [];
  let predicateItemsCache = [];

  root.innerHTML = `
    <div class="card">
      <h2>Listar Apresentações</h2>
      <p class="small">
        Lista apresentações armazenadas na wallet, permite filtrar, visualizar atributos/provas ZKP
        e exportar a apresentação selecionada em envelope JSON cifrado.
      </p>

      <div class="row">
        <button class="secondary" id="btn_pres_list_refresh_all">Atualizar lista/DIDs</button>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>1) Filtros</h3>

      <div class="row">
        <div class="input" style="min-width:360px">
          <label>ID local (opcional, exato)</label>
          <input id="pres_list_filter_id" placeholder="ex.: pres-received-..." />
        </div>

        <div class="input" style="min-width:280px">
          <label>Request nonce (opcional)</label>
          <input id="pres_list_filter_nonce" placeholder="ex.: 123456..." />
        </div>

        <div class="input" style="min-width:340px">
          <label>Busca livre</label>
          <input id="pres_list_filter_text" placeholder="id, tag, nonce..." />
        </div>

        <button class="secondary" id="btn_pres_list_search">Buscar</button>
        <button class="secondary" id="btn_pres_list_clear">Limpar</button>
      </div>

      <div class="row" style="align-items:flex-end">
        <div class="input" style="min-width:180px">
          <label>Itens por página</label>
          <select id="pres_list_page_size">
            <option value="20">20</option>
            <option value="30" selected>30</option>
            <option value="50">50</option>
            <option value="100">100</option>
            <option value="200">200</option>
          </select>
        </div>
        <button class="secondary" id="btn_pres_list_first">⏮ Primeiro</button>
        <button class="secondary" id="btn_pres_list_prev">◀ Prev</button>
        <div class="input" style="min-width:120px">
          <label>Página</label>
          <input id="pres_list_page_index" value="1" />
        </div>
        <button class="secondary" id="btn_pres_list_next">Next ▶</button>
        <button class="secondary" id="btn_pres_list_last">Último ⏭</button>
        <div class="small" id="pres_list_page_meta"></div>
      </div>

      <div class="tableWrap">
        <table class="table" id="tbl_pres_list">
          <thead>
            <tr>
              <th>ID local</th>
              <th>Request nonce</th>
              <th>Criada em</th>
              <th>Tags</th>
              <th>Ações</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <p class="small" id="pres_list_selected_info">Nenhuma apresentação selecionada.</p>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>2) Atributos e Provas da apresentação</h3>

      <div class="tableWrap">
        <table class="table" id="tbl_pres_list_revealed">
          <thead>
            <tr>
              <th data-sort-table="revealed" data-sort-key="referent">Referent</th>
              <th data-sort-table="revealed" data-sort-key="name">Atributo</th>
              <th data-sort-table="revealed" data-sort-key="raw">Valor revelado</th>
              <th data-sort-table="revealed" data-sort-key="subProofIndex">Sub-proof</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <div class="tableWrap">
        <table class="table" id="tbl_pres_list_predicates">
          <thead>
            <tr>
              <th data-sort-table="predicates" data-sort-key="referent">Referent</th>
              <th data-sort-table="predicates" data-sort-key="name">Atributo</th>
              <th data-sort-table="predicates" data-sort-key="rule">Regra ZKP</th>
              <th data-sort-table="predicates" data-sort-key="validAfterVerify">Provada</th>
              <th data-sort-table="predicates" data-sort-key="subProofIndex">Sub-proof</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Record completo</label>
          <textarea id="pres_list_record_out" rows="10" readonly></textarea>
        </div>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>3) Exportar apresentação selecionada</h3>

      <div class="row">
        <div class="input" style="min-width:340px">
          <label>DID emissor (own)</label>
          <select id="sel_pres_list_sender_did">
            <option value="">-- selecione um DID --</option>
          </select>
        </div>

        <div class="input" style="min-width:420px">
          <label>DID emissor (manual)</label>
          <input id="pres_list_sender_did" placeholder="ex.: DID do verificador" />
        </div>
      </div>
      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de DIDs (emissor)</label>
          <input id="pres_list_sender_filter" placeholder="Filtrar por DID, alias ou verkey..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="pres_list_sender_limit" type="number" min="1" max="${MAX_DID_LIMIT}" value="${DEFAULT_DID_LIMIT}" />
        </div>
        <button class="secondary" id="btn_pres_list_sender_clear_filter">Limpar filtro</button>
      </div>
      <p class="small" id="pres_list_sender_stats">DIDs emissor: 0</p>

      <div class="row">
        <div class="input" style="min-width:420px">
          <label>Destinatário (DID + verkey)</label>
          <select id="sel_pres_list_recipient">
            <option value="">-- selecione um destinatário --</option>
          </select>
        </div>

        <div class="input" style="min-width:320px">
          <label>DID destino (manual)</label>
          <input id="pres_list_recipient_did" placeholder="opcional" />
        </div>

        <div class="input" style="min-width:420px">
          <label>Verkey destino (manual)</label>
          <input id="pres_list_recipient_verkey" placeholder="se vazio, tenta resolver pelo DID" />
        </div>
      </div>
      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de destinatários</label>
          <input id="pres_list_recipient_filter" placeholder="Filtrar por DID, verkey, alias ou origem..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="pres_list_recipient_limit" type="number" min="1" max="${MAX_DID_LIMIT}" value="${DEFAULT_DID_LIMIT}" />
        </div>
        <button class="secondary" id="btn_pres_list_recipient_clear_filter">Limpar filtro</button>
      </div>
      <p class="small" id="pres_list_recipient_stats">Destinatários: 0</p>

      <div class="row">
        <div class="input" style="min-width:260px">
          <label>Kind</label>
          <input id="pres_list_kind" value="ssi/proof/presentation" />
        </div>

        <div class="input" style="min-width:300px">
          <label>Thread ID (opcional)</label>
          <input id="pres_list_thread_id" placeholder="vazio = auto/meta" />
        </div>

        <div class="input" style="min-width:220px">
          <label>ExpiresAt (epoch ms)</label>
          <input id="pres_list_expires_at" placeholder="opcional" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Meta JSON (opcional)</label>
          <textarea id="pres_list_meta_json" rows="4" placeholder='{"flow":"presentation_list_export"}'></textarea>
        </div>
      </div>

      <div class="row">
        <button class="primary" id="btn_pres_list_export">Exportar envelope da apresentação selecionada</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Resultado</label>
          <textarea id="pres_list_result" rows="10" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="pres_list_out">{}</pre>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#pres_list_out");

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

  function senderDidSearchBlob(d) {
    return normalizeText([
      d.did,
      d.alias,
      d.verkey,
      d.verKey,
    ].filter(Boolean).join(" "));
  }

  function recipientDidSearchBlob(d) {
    return normalizeText([
      d.did,
      d.alias,
      d.verkey,
      d.verKey,
      d.source,
    ].filter(Boolean).join(" "));
  }

  function parsePresentationList(rawData) {
    const parsed = parseMaybeJson(rawData);
    let arr = [];

    if (Array.isArray(parsed)) arr = parsed;
    else if (parsed && typeof parsed === "object") {
      if (Array.isArray(parsed.items)) arr = parsed.items;
      else if (Array.isArray(parsed.data)) arr = parsed.data;
      else if (Array.isArray(parsed.records)) arr = parsed.records;
    }

    return arr
      .map((it) => parseMaybeJson(it))
      .filter((it) => it && typeof it === "object")
      .map((rec) => {
        const idLocal = firstNonEmpty(rec?.id_local, rec?.idLocal, rec?.id);
        const tags = rec?.tags && typeof rec.tags === "object" ? rec.tags : {};
        const requestNonce = firstNonEmpty(tags?.request_nonce, tags?.requestNonce);
        const createdAt = firstNonEmpty(tags?.created_at, tags?.createdAt);
        return {
          id_local: idLocal,
          request_nonce: requestNonce,
          created_at: createdAt,
          tags,
        };
      })
      .filter((rec) => rec.id_local);
  }

  function formatCreatedAt(tsRaw) {
    const txt = toStringSafe(tsRaw).trim();
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

  function buildSearchBlob(item) {
    const tagsTxt = item.tags && typeof item.tags === "object"
      ? Object.entries(item.tags).map(([k, v]) => `${k}:${toStringSafe(v)}`).join(" ")
      : "";

    return [item.id_local, item.request_nonce, item.created_at, tagsTxt]
      .map((v) => toStringSafe(v).toLowerCase())
      .join(" | ");
  }

  function applyClientFilters(items) {
    const idEq = toStringSafe($("#pres_list_filter_id").value).trim();
    const nonceEq = toStringSafe($("#pres_list_filter_nonce").value).trim();
    const query = normalizeText($("#pres_list_filter_text").value).trim();

    return items.filter((it) => {
      if (idEq && it.id_local !== idEq) return false;
      if (nonceEq && it.request_nonce !== nonceEq) return false;
      if (query && !buildSearchBlob(it).includes(query)) return false;
      return true;
    });
  }

  function getListPagination() {
    listPageSize = Number($("#pres_list_page_size").value || 30);
    if (!Number.isFinite(listPageSize) || listPageSize < 1) listPageSize = 30;

    const total = filteredItems.length;
    const totalPages = Math.max(1, Math.ceil(total / listPageSize));
    if (listPageIndex > totalPages) listPageIndex = totalPages;
    if (listPageIndex < 1) listPageIndex = 1;
    $("#pres_list_page_index").value = String(listPageIndex);

    const start = (listPageIndex - 1) * listPageSize;
    const end = start + listPageSize;
    const slice = filteredItems.slice(start, end);
    return { total, totalPages, start, end: Math.min(end, total), slice };
  }

  function renderListTable() {
    const tbody = $("#tbl_pres_list tbody");
    tbody.innerHTML = "";
    const { total, totalPages, start, end, slice } = getListPagination();

    slice.forEach((it, idx) => {
      const selectedClass = it.id_local === selectedPresentationId ? "selectedRow" : "";
      const tagsPreview = it.tags && typeof it.tags === "object"
        ? Object.keys(it.tags).slice(0, 4).join(", ")
        : "";

      const tr = document.createElement("tr");
      tr.dataset.idx = String(start + idx);
      tr.className = selectedClass;
      tr.innerHTML = `
        <td class="mono">${it.id_local}</td>
        <td class="mono">${shortText(it.request_nonce, 24)}</td>
        <td>${formatCreatedAt(it.created_at)}</td>
        <td title="${toStringSafe(JSON.stringify(it.tags || {}))}">${shortText(tagsPreview, 36)}</td>
        <td>
          <div class="actions">
            <button data-act="view" data-id="${it.id_local}">Ver atributos</button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });

    if (!slice.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="5" class="small">Nenhuma apresentação encontrada.</td>`;
      tbody.appendChild(tr);
    }

    if (total > 0) {
      $("#pres_list_page_meta").textContent =
        `Total: ${total} | Página ${listPageIndex}/${totalPages} | Itens ${start + 1}-${end}`;
    } else {
      $("#pres_list_page_meta").textContent = "Total: 0 | Página 1/1";
    }

    if (selectedPresentationId) {
      $("#pres_list_selected_info").textContent = `Selecionada: ${selectedPresentationId}`;
    } else {
      $("#pres_list_selected_info").textContent = "Nenhuma apresentação selecionada.";
    }
  }

  function parseSortNumber(v) {
    const n = Number.parseFloat(toStringSafe(v).trim());
    return Number.isFinite(n) ? n : null;
  }

  function compareSortValues(a, b) {
    if (typeof a === "boolean" || typeof b === "boolean") {
      const av = a ? 1 : 0;
      const bv = b ? 1 : 0;
      return av - bv;
    }

    const an = parseSortNumber(a);
    const bn = parseSortNumber(b);
    if (an !== null && bn !== null) return an - bn;

    const as = toStringSafe(a).trim();
    const bs = toStringSafe(b).trim();
    return as.localeCompare(bs, "pt-BR", { sensitivity: "base", numeric: true });
  }

  function getRevealedSortValue(item, key) {
    if (key === "referent") return firstNonEmpty(item?.referent);
    if (key === "name") return firstNonEmpty(item?.name);
    if (key === "raw") return firstNonEmpty(item?.raw);
    if (key === "subProofIndex") return firstNonEmpty(item?.subProofIndex);
    return "";
  }

  function getPredicateSortValue(item, key) {
    if (key === "referent") return firstNonEmpty(item?.referent);
    if (key === "name") return firstNonEmpty(item?.name);
    if (key === "rule") return `${firstNonEmpty(item?.pType, "?")} ${firstNonEmpty(item?.pValue, "?")}`;
    if (key === "validAfterVerify") return !!item?.validAfterVerify;
    if (key === "subProofIndex") return firstNonEmpty(item?.subProofIndex);
    return "";
  }

  function applySort(list, sortState, valueGetter) {
    const arr = Array.isArray(list) ? [...list] : [];
    if (!sortState?.key) return arr;

    const dir = sortState.dir === "desc" ? -1 : 1;
    arr.sort((a, b) => dir * compareSortValues(valueGetter(a, sortState.key), valueGetter(b, sortState.key)));
    return arr;
  }

  function updateDetailSortHeaderLabels() {
    const headers = root.querySelectorAll("th[data-sort-key][data-sort-table]");
    headers.forEach((th) => {
      const baseLabel = firstNonEmpty(th.dataset.label, th.textContent);
      th.dataset.label = baseLabel;
      th.style.cursor = "pointer";
      th.title = "Clique para ordenar";

      const tableId = toStringSafe(th.dataset.sortTable).trim();
      const key = toStringSafe(th.dataset.sortKey).trim();
      const state = tableId === "revealed" ? revealedSort : predicateSort;
      const isActive = state.key === key;
      const icon = isActive ? (state.dir === "desc" ? " ▼" : " ▲") : "";
      th.textContent = `${baseLabel}${icon}`;
    });
  }

  function toggleDetailSort(tableId, key) {
    const state = tableId === "revealed" ? revealedSort : predicateSort;
    if (state.key === key) {
      state.dir = state.dir === "asc" ? "desc" : "asc";
    } else {
      state.key = key;
      state.dir = "asc";
    }
    updateDetailSortHeaderLabels();
    if (tableId === "revealed") renderRevealed(revealedItemsCache);
    else renderPredicates(predicateItemsCache);
  }

  function renderRevealed(items) {
    const tbody = $("#tbl_pres_list_revealed tbody");
    tbody.innerHTML = "";
    revealedItemsCache = Array.isArray(items) ? [...items] : [];
    const list = applySort(revealedItemsCache, revealedSort, getRevealedSortValue);

    if (!list.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="4" class="small">Nenhum atributo revelado.</td>`;
      tbody.appendChild(tr);
      return;
    }

    list.forEach((it) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">${firstNonEmpty(it?.referent, "-")}</td>
        <td>${firstNonEmpty(it?.name, "-")}</td>
        <td class="mono">${firstNonEmpty(it?.raw, "-")}</td>
        <td>${firstNonEmpty(it?.subProofIndex, "-")}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  function renderPredicates(items) {
    const tbody = $("#tbl_pres_list_predicates tbody");
    tbody.innerHTML = "";
    predicateItemsCache = Array.isArray(items) ? [...items] : [];
    const list = applySort(predicateItemsCache, predicateSort, getPredicateSortValue);

    if (!list.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="5" class="small">Nenhuma prova ZKP solicitada.</td>`;
      tbody.appendChild(tr);
      return;
    }

    list.forEach((it) => {
      const rule = `${firstNonEmpty(it?.pType, "?")} ${firstNonEmpty(it?.pValue, "?")}`;
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">${firstNonEmpty(it?.referent, "-")}</td>
        <td>${firstNonEmpty(it?.name, "-")}</td>
        <td class="mono">${rule}</td>
        <td>${it?.validAfterVerify ? "Sim" : "Não"}</td>
        <td>${firstNonEmpty(it?.subProofIndex, "-")}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  function clearDetails() {
    renderRevealed([]);
    renderPredicates([]);
    $("#pres_list_record_out").value = "";
  }

  function renderSenderDidOptions(items) {
    const sel = $("#sel_pres_list_sender_did");
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

  function renderRecipientOptions(items) {
    const sel = $("#sel_pres_list_recipient");
    const currentVerkey = toStringSafe(sel.value).trim();
    sel.innerHTML = `<option value="">-- selecione um destinatário --</option>`;

    const fragment = document.createDocumentFragment();
    (items || []).forEach((d) => {
      const did = toStringSafe(d.did).trim();
      const verkey = toStringSafe(d.verkey).trim();
      if (!did || !verkey) return;
      const opt = document.createElement("option");
      opt.value = verkey;
      opt.dataset.did = did;
      opt.textContent = `${did} | ${verkey.slice(0, 20)}... (${d.source})`;
      fragment.appendChild(opt);
    });
    sel.appendChild(fragment);

    if (currentVerkey && (items || []).some((d) => toStringSafe(d.verkey).trim() === currentVerkey)) {
      sel.value = currentVerkey;
    }
  }

  function updateSenderDidStats(total, filtered, shown, limit) {
    $("#pres_list_sender_stats").textContent =
      `DIDs emissor: total ${total} | filtrados ${filtered} | exibidos ${shown} (máx ${limit})`;
  }

  function updateRecipientDidStats(total, filtered, shown, limit) {
    $("#pres_list_recipient_stats").textContent =
      `Destinatários: total ${total} | filtrados ${filtered} | exibidos ${shown} (máx ${limit})`;
  }

  function applySenderDidFilter() {
    const filterText = normalizeText($("#pres_list_sender_filter").value).trim();
    const limit = parseDidLimit($("#pres_list_sender_limit").value);
    $("#pres_list_sender_limit").value = String(limit);

    const filtered = filterText
      ? ownDidOptions.filter((d) => senderDidSearchBlob(d).includes(filterText))
      : ownDidOptions;

    visibleOwnDidOptions = filtered.slice(0, limit);
    renderSenderDidOptions(visibleOwnDidOptions);
    updateSenderDidStats(ownDidOptions.length, filtered.length, visibleOwnDidOptions.length, limit);
  }

  function applyRecipientDidFilter() {
    const filterText = normalizeText($("#pres_list_recipient_filter").value).trim();
    const limit = parseDidLimit($("#pres_list_recipient_limit").value);
    $("#pres_list_recipient_limit").value = String(limit);

    const filtered = filterText
      ? recipientOptions.filter((d) => recipientDidSearchBlob(d).includes(filterText))
      : recipientOptions;

    visibleRecipientOptions = filtered.slice(0, limit);
    renderRecipientOptions(visibleRecipientOptions);
    updateRecipientDidStats(recipientOptions.length, filtered.length, visibleRecipientOptions.length, limit);
  }

  async function refreshDidOptions() {
    const [ownResp, extResp] = await Promise.all([
      Api.did.list("own"),
      Api.did.list("external"),
    ]);

    if (!ownResp?.ok) {
      Api.setStatus(`Erro listando DIDs own: ${ownResp?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (!extResp?.ok) {
      Api.setStatus(`Erro listando DIDs external: ${extResp?.error?.message || "erro desconhecido"}`);
      return;
    }

    ownDidOptions = parseDidList(ownResp);
    applySenderDidFilter();

    const own = parseDidList(ownResp).map((d) => ({ ...d, source: "own" }));
    const ext = parseDidList(extResp).map((d) => ({ ...d, source: "external" }));
    const seen = new Set();
    recipientOptions = own.concat(ext).filter((d) => {
      const key = `${toStringSafe(d.did).trim()}|${toStringSafe(d.verkey).trim()}`;
      if (!toStringSafe(d.did).trim() || !toStringSafe(d.verkey).trim() || seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    applyRecipientDidFilter();

    if (!toStringSafe($("#pres_list_sender_did").value).trim() && ownDidOptions.length > 0) {
      const did = toStringSafe(ownDidOptions[0].did).trim();
      $("#pres_list_sender_did").value = did;
      $("#sel_pres_list_sender_did").value = did;
    }
  }

  async function refreshList() {
    Api.setStatus("Listando apresentações armazenadas...");
    const resp = await Api.presentation.listLocal();
    setOut({ where: "presentationList.refresh", resp });

    if (!resp?.ok) {
      allItems = [];
      filteredItems = [];
      listPageIndex = 1;
      selectedPresentationId = "";
      renderListTable();
      clearDetails();
      Api.setStatus(`Erro listando apresentações: ${resp?.error?.message || "erro desconhecido"}`);
      return;
    }

    allItems = parsePresentationList(resp.data);
    filteredItems = applyClientFilters(allItems);
    listPageIndex = 1;

    if (selectedPresentationId && !allItems.find((it) => it.id_local === selectedPresentationId)) {
      selectedPresentationId = "";
      clearDetails();
    }

    renderListTable();
    Api.setStatus(`Apresentações carregadas: ${filteredItems.length}.`);
  }

  async function refreshAll() {
    Api.setStatus("Atualizando DIDs e apresentações...");
    await refreshDidOptions();
    await refreshList();
  }

  async function loadPresentationDetails(presentationIdLocal) {
    if (!presentationIdLocal) return;

    Api.setStatus(`Carregando apresentação ${presentationIdLocal}...`);
    const resp = await Api.presentation.getLocal(presentationIdLocal);
    setOut({ where: "presentationList.getLocal", presentationIdLocal, resp });

    if (!resp?.ok) {
      Api.setStatus(`Erro carregando apresentação: ${resp?.error?.message || "erro desconhecido"}`);
      return;
    }

    selectedPresentationId = presentationIdLocal;
    renderListTable();

    const d = resp.data || {};
    renderRevealed(d?.revealedAttributes || []);
    renderPredicates(d?.predicateProofs || []);
    $("#pres_list_record_out").value = JSON.stringify(d?.record || {}, null, 2);
    $("#pres_list_selected_info").textContent = `Selecionada: ${presentationIdLocal}`;

    const threadIdHint = firstNonEmpty(d?.meta?.thread_id, d?.meta?.threadId);
    if (threadIdHint && !toStringSafe($("#pres_list_thread_id").value).trim()) {
      $("#pres_list_thread_id").value = threadIdHint;
    }

    Api.setStatus(`Apresentação selecionada: ${presentationIdLocal}.`);
  }

  async function exportSelectedPresentationEnvelope() {
    if (!selectedPresentationId) {
      Api.setStatus("Selecione uma apresentação para exportar.");
      return;
    }

    const senderDid = toStringSafe($("#pres_list_sender_did").value).trim();
    if (!senderDid) {
      Api.setStatus("Informe o DID emissor (sender)." );
      return;
    }

    const recipientDid = toStringSafe($("#pres_list_recipient_did").value).trim() || null;
    const recipientVerkey = toStringSafe($("#pres_list_recipient_verkey").value).trim() || null;
    const kind = toStringSafe($("#pres_list_kind").value).trim() || "ssi/proof/presentation";
    const threadId = toStringSafe($("#pres_list_thread_id").value).trim() || null;

    const expiresRaw = toStringSafe($("#pres_list_expires_at").value).trim();
    let expiresAtMs = null;
    if (expiresRaw) {
      const n = Number(expiresRaw);
      if (!Number.isFinite(n) || n <= 0) {
        Api.setStatus("ExpiresAt inválido. Use epoch em milissegundos.");
        return;
      }
      expiresAtMs = Math.trunc(n);
    }

    const metaRaw = toStringSafe($("#pres_list_meta_json").value).trim();
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
      presentationIdLocal: selectedPresentationId,
      senderDid,
      recipientDid,
      recipientVerkey,
      kind,
      threadId,
      expiresAtMs,
      metaObj,
    };

    Api.setStatus("Exportando envelope da apresentação selecionada...");
    const resp = await Api.presentation.exportStoredEnvelope(input);
    setOut({ where: "presentationList.exportStoredEnvelope", input, resp });
    $("#pres_list_result").value = JSON.stringify(resp, null, 2);

    if (!resp?.ok) {
      Api.setStatus(`Erro exportando envelope: ${resp?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (resp.data?.canceled) {
      Api.setStatus("Exportação cancelada.");
      return;
    }

    Api.setStatus(`Envelope exportado: ${firstNonEmpty(resp?.data?.filePath, "(sem caminho)")}`);
  }

  function clearFilters() {
    $("#pres_list_filter_id").value = "";
    $("#pres_list_filter_nonce").value = "";
    $("#pres_list_filter_text").value = "";
    refreshList().catch(() => {});
  }

  $("#btn_pres_list_refresh_all").addEventListener("click", () => {
    refreshAll().catch(() => {});
  });
  $("#btn_pres_list_search").addEventListener("click", () => {
    refreshList().catch(() => {});
  });
  $("#btn_pres_list_clear").addEventListener("click", clearFilters);
  $("#btn_pres_list_export").addEventListener("click", exportSelectedPresentationEnvelope);
  $("#pres_list_page_size").addEventListener("change", () => {
    listPageIndex = 1;
    renderListTable();
  });
  $("#btn_pres_list_first").addEventListener("click", () => {
    listPageIndex = 1;
    renderListTable();
  });
  $("#btn_pres_list_prev").addEventListener("click", () => {
    listPageIndex -= 1;
    renderListTable();
  });
  $("#btn_pres_list_next").addEventListener("click", () => {
    listPageIndex += 1;
    renderListTable();
  });
  $("#btn_pres_list_last").addEventListener("click", () => {
    listPageSize = Number($("#pres_list_page_size").value || 30);
    if (!Number.isFinite(listPageSize) || listPageSize < 1) listPageSize = 30;
    const totalPages = Math.max(1, Math.ceil(filteredItems.length / listPageSize));
    listPageIndex = totalPages;
    renderListTable();
  });
  $("#pres_list_page_index").addEventListener("change", () => {
    const n = Number($("#pres_list_page_index").value);
    if (Number.isFinite(n)) listPageIndex = Math.trunc(n);
    renderListTable();
  });
  $("#pres_list_page_index").addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter") return;
    const n = Number($("#pres_list_page_index").value);
    if (Number.isFinite(n)) listPageIndex = Math.trunc(n);
    renderListTable();
  });
  $("#pres_list_sender_filter").addEventListener("input", applySenderDidFilter);
  $("#pres_list_sender_filter").addEventListener("keyup", applySenderDidFilter);
  $("#pres_list_sender_limit").addEventListener("input", applySenderDidFilter);
  $("#pres_list_sender_limit").addEventListener("change", applySenderDidFilter);
  $("#btn_pres_list_sender_clear_filter").addEventListener("click", () => {
    $("#pres_list_sender_filter").value = "";
    applySenderDidFilter();
  });
  $("#pres_list_recipient_filter").addEventListener("input", applyRecipientDidFilter);
  $("#pres_list_recipient_filter").addEventListener("keyup", applyRecipientDidFilter);
  $("#pres_list_recipient_limit").addEventListener("input", applyRecipientDidFilter);
  $("#pres_list_recipient_limit").addEventListener("change", applyRecipientDidFilter);
  $("#btn_pres_list_recipient_clear_filter").addEventListener("click", () => {
    $("#pres_list_recipient_filter").value = "";
    applyRecipientDidFilter();
  });

  $("#sel_pres_list_sender_did").addEventListener("change", () => {
    const did = toStringSafe($("#sel_pres_list_sender_did").value).trim();
    if (did) $("#pres_list_sender_did").value = did;
  });

  $("#sel_pres_list_recipient").addEventListener("change", () => {
    const sel = $("#sel_pres_list_recipient");
    const opt = sel.options[sel.selectedIndex];
    const did = opt ? toStringSafe(opt.dataset.did).trim() : "";
    const verkey = toStringSafe(sel.value).trim();
    if (did) $("#pres_list_recipient_did").value = did;
    if (verkey) $("#pres_list_recipient_verkey").value = verkey;
  });

  $("#tbl_pres_list").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-act='view']");
    if (!btn) return;
    const id = toStringSafe(btn.dataset.id).trim();
    loadPresentationDetails(id).catch(() => {});
  });

  $("#tbl_pres_list_revealed thead").addEventListener("click", (ev) => {
    const th = ev.target.closest("th[data-sort-key][data-sort-table='revealed']");
    if (!th) return;
    toggleDetailSort("revealed", toStringSafe(th.dataset.sortKey).trim());
  });

  $("#tbl_pres_list_predicates thead").addEventListener("click", (ev) => {
    const th = ev.target.closest("th[data-sort-key][data-sort-table='predicates']");
    if (!th) return;
    toggleDetailSort("predicates", toStringSafe(th.dataset.sortKey).trim());
  });

  updateDetailSortHeaderLabels();
  clearDetails();
  refreshAll().catch(() => {});

  return {};
})();
