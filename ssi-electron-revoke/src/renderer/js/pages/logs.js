const LogsPage = (() => {
  const root = document.getElementById("page-logs");
  if (!root) return {};

  let allItems = [];
  let filteredItems = [];
  let pageIndex = 1;
  let pageSize = 30;

  root.innerHTML = `
    <div class="card">
      <h2>Logs</h2>
      <p class="small">
        Lista os logs de status da UI com filtro, paginação e exclusão.
      </p>

      <div class="row">
        <button class="secondary" id="btn_logs_refresh">Atualizar lista</button>
        <button class="secondary" id="btn_logs_clear_all">Limpar todos os logs</button>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>Filtros</h3>

      <div class="row">
        <div class="input" style="min-width:240px">
          <label>ID (opcional, exato)</label>
          <input id="logs_filter_id" placeholder="ex.: 1772800000000-1" />
        </div>
        <div class="input" style="min-width:420px">
          <label>Busca livre (mensagem/id/data)</label>
          <input id="logs_filter_text" placeholder="ex.: wallet, erro, 06/03..." />
        </div>
        <button class="secondary" id="btn_logs_search">Buscar</button>
        <button class="secondary" id="btn_logs_clear_filters">Limpar filtros</button>
      </div>

      <div class="row" style="align-items:flex-end">
        <div class="input" style="min-width:180px">
          <label>Itens por página</label>
          <select id="logs_page_size">
            <option value="20">20</option>
            <option value="30" selected>30</option>
            <option value="50">50</option>
            <option value="100">100</option>
            <option value="200">200</option>
          </select>
        </div>
        <button class="secondary" id="btn_logs_first">⏮ Primeiro</button>
        <button class="secondary" id="btn_logs_prev">◀ Prev</button>
        <div class="input" style="min-width:120px">
          <label>Página</label>
          <input id="logs_page_index" value="1" />
        </div>
        <button class="secondary" id="btn_logs_next">Next ▶</button>
        <button class="secondary" id="btn_logs_last">Último ⏭</button>
        <div class="small" id="logs_page_meta"></div>
      </div>

      <div class="tableWrap">
        <table class="table" id="tbl_logs">
          <thead>
            <tr>
              <th>#</th>
              <th>Data/Hora</th>
              <th>Mensagem</th>
              <th>ID</th>
              <th>Ações</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
    </div>
    <div id="logs_confirm_overlay" style="display:none; position:fixed; inset:0; z-index:9999; background:rgba(17,24,39,0.35); align-items:center; justify-content:center; padding:16px;">
      <div style="width:min(100%, 420px); background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:16px; box-shadow:0 10px 30px rgba(17,24,39,0.2);">
        <h3 style="margin:0 0 8px 0;">Confirmar ação</h3>
        <p id="logs_confirm_text" style="margin:0; color:#111827;"></p>
        <div class="row" style="margin-top:16px; justify-content:flex-end;">
          <button class="secondary" id="btn_logs_confirm_cancel">Cancelar</button>
          <button class="primary" id="btn_logs_confirm_ok">Confirmar</button>
        </div>
      </div>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);

  function toStringSafe(v) {
    if (v === undefined || v === null) return "";
    return String(v);
  }

  function escapeHtml(v) {
    return toStringSafe(v).replace(/[&<>"']/g, (m) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#039;",
    }[m]));
  }

  function parseTsMs(raw) {
    const n = Number(raw || 0);
    return Number.isFinite(n) && n > 0 ? n : 0;
  }

  function formatTsMs(tsMs) {
    if (!tsMs) return "";
    try {
      return new Date(tsMs).toLocaleString();
    } catch (_) {
      return toStringSafe(tsMs);
    }
  }

  function shortText(txt, max = 120) {
    const s = toStringSafe(txt);
    if (s.length <= max) return s;
    return `${s.slice(0, max)}...`;
  }

  function focusElementSafe(el) {
    if (!el || typeof el.focus !== "function") return false;
    if (el.disabled) return false;
    if (!el.isConnected) return false;
    try {
      el.focus({ preventScroll: true });
      return true;
    } catch (_) {
      return false;
    }
  }

  const confirmOverlay = $("#logs_confirm_overlay");
  const confirmText = $("#logs_confirm_text");
  const confirmBtnOk = $("#btn_logs_confirm_ok");
  const confirmBtnCancel = $("#btn_logs_confirm_cancel");
  let confirmResolve = null;
  let confirmFallbackSelector = "#logs_filter_text";
  let confirmPrevFocused = null;

  function closeInlineConfirm(result) {
    if (!confirmResolve) return;
    const resolve = confirmResolve;
    confirmResolve = null;
    confirmOverlay.style.display = "none";
    resolve(result);

    window.setTimeout(() => {
      const previousOk = focusElementSafe(confirmPrevFocused);
      if (previousOk) return;
      const fallbackEl = confirmFallbackSelector ? root.querySelector(confirmFallbackSelector) : null;
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
    if (ev.key !== "Enter") return;
    ev.preventDefault();
    if (ev.target === confirmBtnCancel) closeInlineConfirm(false);
    else closeInlineConfirm(true);
  }

  function openInlineConfirm(message, fallbackSelector) {
    if (confirmResolve) return Promise.resolve(false);
    confirmPrevFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    confirmFallbackSelector = fallbackSelector || "#logs_filter_text";
    confirmText.textContent = toStringSafe(message);
    confirmOverlay.style.display = "flex";
    focusElementSafe(confirmBtnOk);
    return new Promise((resolve) => {
      confirmResolve = resolve;
    });
  }

  function normalizeItems(list) {
    if (!Array.isArray(list)) return [];
    return list
      .filter((it) => it && typeof it === "object")
      .map((it) => ({
        id: toStringSafe(it.id).trim(),
        tsMs: parseTsMs(it.tsMs),
        message: toStringSafe(it.message),
      }))
      .filter((it) => it.id);
  }

  function getSearchBlob(rec) {
    const tsLabel = formatTsMs(rec.tsMs);
    return `${rec.id} ${rec.message} ${tsLabel}`.toLowerCase();
  }

  function applyFilters(items) {
    const idEq = toStringSafe($("#logs_filter_id").value).trim();
    const query = toStringSafe($("#logs_filter_text").value).trim().toLowerCase();

    let arr = items;
    if (idEq) {
      arr = arr.filter((it) => it.id === idEq);
    }
    if (query) {
      arr = arr.filter((it) => getSearchBlob(it).includes(query));
    }
    return arr;
  }

  function updateData(resetPage) {
    allItems = normalizeItems(Api.logs?.list?.() || []);
    filteredItems = applyFilters(allItems);
    if (resetPage) pageIndex = 1;
    renderTable();
  }

  function getPagination() {
    pageSize = Number($("#logs_page_size").value || 30);
    if (!Number.isFinite(pageSize) || pageSize < 1) pageSize = 30;

    const total = filteredItems.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));

    if (pageIndex > totalPages) pageIndex = totalPages;
    if (pageIndex < 1) pageIndex = 1;
    $("#logs_page_index").value = String(pageIndex);

    const start = (pageIndex - 1) * pageSize;
    const end = Math.min(total, start + pageSize);
    const slice = filteredItems.slice(start, end);
    return { total, totalPages, start, end, slice };
  }

  function renderTable() {
    const tbody = $("#tbl_logs tbody");
    tbody.innerHTML = "";

    const { total, totalPages, start, end, slice } = getPagination();
    slice.forEach((rec, idx) => {
      const tr = document.createElement("tr");
      tr.dataset.id = rec.id;
      tr.innerHTML = `
        <td>${start + idx + 1}</td>
        <td>${escapeHtml(formatTsMs(rec.tsMs))}</td>
        <td title="${escapeHtml(rec.message)}">${escapeHtml(shortText(rec.message, 140))}</td>
        <td class="mono">${escapeHtml(rec.id)}</td>
        <td>
          <div class="actions">
            <button data-act="del" data-id="${escapeHtml(rec.id)}">Excluir</button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });

    if (total > 0) {
      $("#logs_page_meta").textContent = `Total: ${total} | Página ${pageIndex}/${totalPages} | Itens ${start + 1}-${end}`;
    } else {
      $("#logs_page_meta").textContent = "Total: 0 | Página 1/1";
    }
  }

  function refreshList() {
    updateData(true);
  }

  function clearFilters() {
    $("#logs_filter_id").value = "";
    $("#logs_filter_text").value = "";
    updateData(true);
  }

  async function clearAll() {
    const ok = await openInlineConfirm("Excluir todos os logs?", "#btn_logs_clear_all");
    if (!ok) return;
    Api.logs?.clear?.();
    updateData(true);
  }

  $("#btn_logs_refresh").addEventListener("click", refreshList);
  $("#btn_logs_search").addEventListener("click", () => updateData(true));
  $("#btn_logs_clear_filters").addEventListener("click", clearFilters);
  $("#btn_logs_clear_all").addEventListener("click", () => {
    clearAll().catch(() => {});
  });
  confirmBtnOk.addEventListener("click", () => closeInlineConfirm(true));
  confirmBtnCancel.addEventListener("click", () => closeInlineConfirm(false));
  confirmOverlay.addEventListener("click", (ev) => {
    if (ev.target === confirmOverlay) closeInlineConfirm(false);
  });
  document.addEventListener("keydown", onInlineConfirmKeydown, true);

  $("#logs_page_size").addEventListener("change", () => {
    pageIndex = 1;
    renderTable();
  });
  $("#btn_logs_first").addEventListener("click", () => {
    pageIndex = 1;
    renderTable();
  });
  $("#btn_logs_prev").addEventListener("click", () => {
    pageIndex -= 1;
    renderTable();
  });
  $("#btn_logs_next").addEventListener("click", () => {
    pageIndex += 1;
    renderTable();
  });
  $("#btn_logs_last").addEventListener("click", () => {
    pageSize = Number($("#logs_page_size").value || 30);
    if (!Number.isFinite(pageSize) || pageSize < 1) pageSize = 30;
    const totalPages = Math.max(1, Math.ceil(filteredItems.length / pageSize));
    pageIndex = totalPages;
    renderTable();
  });
  $("#logs_page_index").addEventListener("change", () => {
    const n = Number($("#logs_page_index").value);
    if (Number.isFinite(n)) pageIndex = Math.trunc(n);
    renderTable();
  });
  $("#logs_page_index").addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter") return;
    const n = Number($("#logs_page_index").value);
    if (Number.isFinite(n)) pageIndex = Math.trunc(n);
    renderTable();
  });

  $("#tbl_logs").addEventListener("click", async (ev) => {
    const btn = ev.target.closest("button[data-act='del']");
    if (!btn) return;
    const id = toStringSafe(btn.dataset.id).trim();
    if (!id) return;
    const ok = await openInlineConfirm(`Excluir log ${id}?`, "#logs_filter_text");
    if (!ok) return;
    Api.logs?.remove?.(id);
    updateData(false);
  });

  if (typeof Api.logs?.subscribe === "function") {
    Api.logs.subscribe(() => {
      if (root.classList.contains("hidden")) return;
      updateData(false);
    });
  }

  const visibilityObserver = new MutationObserver(() => {
    if (!root.classList.contains("hidden")) {
      updateData(true);
    }
  });
  visibilityObserver.observe(root, { attributes: true, attributeFilter: ["class"] });

  refreshList();
  return {};
})();
