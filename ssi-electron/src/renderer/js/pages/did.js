// src/renderer/js/pages/did.js

const DidPage = (() => {
  const root = document.getElementById("page-did");
  if (!root) return {};

  // -------------------------
  // State
  // -------------------------
  let didsAll = [];
  let didsView = [];
  let selectedDid = null;

  let pageIndex = 1; // 1-based
  let pageSize = 30;

  // -------------------------
  // UI
  // -------------------------
  root.innerHTML = `
    <div class="card">
      <h2>DIDs</h2>
      <p class="small">Criar DID próprio (own), listar com paginação/ordenação e registrar no ledger.</p>

      <div class="row">
        <button class="primary" id="btn_create">Criar DID</button>
        <button class="secondary" id="btn_refresh">Atualizar lista</button>
        <button class="secondary" id="btn_export">Exportar (batch)</button>
        <button class="secondary" id="btn_import">Importar (batch)</button>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <div class="row">
        <div class="input" style="min-width:180px">
          <label>Tipo</label>
          <select id="cat">
            <option value="own" selected>own</option>
            <option value="external">external</option>
          </select>
        </div>

        <div class="input" style="min-width:260px">
          <label>Buscar (did/verkey/alias)</label>
          <input id="q" placeholder="digite para filtrar..." />
        </div>

        <div class="input" style="min-width:200px">
          <label>Ordenação</label>
          <select id="sort">
            <option value="createdAt_desc" selected>Mais recentes (createdAt ↓)</option>
            <option value="createdAt_asc">Mais antigos (createdAt ↑)</option>
            <option value="alias_asc">Alias (A→Z)</option>
            <option value="alias_desc">Alias (Z→A)</option>
            <option value="did_asc">DID (A→Z)</option>
          </select>
        </div>

        <div class="input" style="min-width:160px">
          <label>Tamanho da página</label>
          <select id="pageSize">
            <option value="20">20</option>
            <option value="30" selected>30</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
        </div>
      </div>

      <div class="row" style="align-items:flex-end">
        <button class="secondary" id="btn_first">⏮ Ir para o primeiro</button>
        <button class="secondary" id="btn_prev">◀ Prev</button>

        <div class="input" style="min-width:120px">
          <label>Página</label>
          <input id="pageIndex" value="1" />
        </div>

        <button class="secondary" id="btn_next">Next ▶</button>
        <button class="secondary" id="btn_last">Ir para o último</button>
        <div class="small" id="meta"></div>
      </div>

      <div class="tableWrap">
        <table class="table" id="tbl">
          <thead>
            <tr>
              <th>#</th>
              <th>Alias</th>
              <th>DID</th>
              <th>Verkey</th>
              <th>Criado</th>
              <th>Ações</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>Registrar DID no ledger</h3>
      <p class="small">Selecione um DID na tabela. O selecionado aparece no status abaixo.</p>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Genesis path</label>
          <input id="g_path" placeholder="/caminho/para/genesis.txn" />
        </div>
        <div class="input" style="min-width:180px">
          <label>Role (opcional)</label>
          <input id="role" placeholder="ex.: ENDORSER (ou vazio => NONE)" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>TRUSTEE_SEED</label>
          <input id="trustee_seed" placeholder="000000000000000000000000Trustee1" />
        </div>
        <div class="input" style="min-width:280px">
          <label>TRUSTEE_DID</label>
          <input id="trustee_did" placeholder="V4SGRU86Z58d6TV7PBUe6f" />
        </div>
      </div>

      <div class="row">
        <button class="secondary" id="btn_import_trustee">Importar Trustee na wallet</button>
        <button class="secondary" id="btn_register">Registrar DID selecionado</button>
      </div>

      <h3>Resultado</h3>
      <pre id="out">{}</pre>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#out");

  function setOut(obj) { out.textContent = JSON.stringify(obj, null, 2); }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (m) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
    }[m]));
  }

  function parseListData(r) {
    if (!r?.ok) return [];
    try {
      const arr = JSON.parse(r.data);
      return Array.isArray(arr) ? arr : [];
    } catch (_) {
      return [];
    }
  }

  function compareStr(a, b) {
    return String(a || "").localeCompare(String(b || ""), "pt-BR", { sensitivity: "base" });
  }

  function applyFilterAndSort() {
    const q = ($("#q").value || "").trim().toLowerCase();
    const sort = $("#sort").value;

    // filtro
    didsView = didsAll.filter(d => {
      const s = `${d.alias || ""} ${d.did || ""} ${d.verkey || ""}`.toLowerCase();
      return !q || s.includes(q);
    });

    // ordenação
    if (sort === "createdAt_desc") {
      didsView.sort((a, b) => (Number(b.createdAt || 0) - Number(a.createdAt || 0)));
    } else if (sort === "createdAt_asc") {
      didsView.sort((a, b) => (Number(a.createdAt || 0) - Number(b.createdAt || 0)));
    } else if (sort === "alias_asc") {
      didsView.sort((a, b) => compareStr(a.alias, b.alias));
    } else if (sort === "alias_desc") {
      didsView.sort((a, b) => compareStr(b.alias, a.alias));
    } else if (sort === "did_asc") {
      didsView.sort((a, b) => compareStr(a.did, b.did));
    }
  }

  function getPagination() {
    pageSize = Number($("#pageSize").value || 30);
    const total = didsView.length;
    const totalPages = Math.max(1, Math.ceil(total / pageSize));

    if (pageIndex > totalPages) pageIndex = totalPages;
    if (pageIndex < 1) pageIndex = 1;

    $("#pageIndex").value = String(pageIndex);

    const start = (pageIndex - 1) * pageSize;
    const end = start + pageSize;
    const slice = didsView.slice(start, end);

    return { total, totalPages, start, slice };
  }

  function renderTable() {
    applyFilterAndSort();
    const { total, totalPages, start, slice } = getPagination();

    const tbody = $("#tbl").querySelector("tbody");
    tbody.innerHTML = "";

    slice.forEach((d, idx) => {
      const tr = document.createElement("tr");
      const created = d.createdAt ? new Date(d.createdAt * 1000).toLocaleString() : "";
      const isSel = selectedDid && selectedDid.did === d.did && selectedDid.verkey === d.verkey;
      if (isSel) tr.classList.add("selectedRow");

      tr.innerHTML = `
        <td>${start + idx}</td>
        <td>${escapeHtml(d.alias || "")}</td>
        <td class="mono">${escapeHtml(d.did || "")}</td>
        <td class="mono">${escapeHtml(d.verkey || "")}</td>
        <td>${escapeHtml(created)}</td>
        <td>
          <div class="actions">
            <button data-act="copyDid" data-idx="${idx}">Copiar DID</button>
            <button data-act="copyVk" data-idx="${idx}">Copiar Verkey</button>
          </div>
        </td>
      `;

      tr.dataset.idx = String(idx);
      tbody.appendChild(tr);
    });

    const selTxt = selectedDid ? ` | Selecionado: ${selectedDid.did}` : " | Nenhum selecionado";
    $("#meta").textContent = `Total: ${total} | Página ${pageIndex}/${totalPages}${selTxt}`;
  }

  async function refreshList(opts = {}) {
    const silentStatus = !!opts.silentStatus;
    const silentOut = !!opts.silentOut;
    if (!silentStatus) Api.setStatus("Listando DIDs...");
    const category = $("#cat").value;

    const r = await Api.did.list(category);
    if (!silentOut) setOut({ where: "did.list", resp: r });

    if (!r.ok) {
      if (!silentStatus) Api.setStatus(`Erro em did.list: ${r.error.message}`);
      didsAll = [];
      didsView = [];
      selectedDid = null;
      renderTable();
      return;
    }

    didsAll = parseListData(r);
    pageIndex = 1;
    renderTable();
    if (!silentStatus) Api.setStatus(`OK: ${didsAll.length} DIDs (${category}).`);
  }

  // -------------------------
  // Events
  // -------------------------

  $("#btn_create").addEventListener("click", async () => {
    Api.setStatus("Criando DID próprio...");
    try {
      const sess = await Api.wallet.getSession();
      if (!sess.ok || !sess.data.activeWalletPath) {
        setOut({ where: "did.createOwn", error: "NO_ACTIVE_WALLET", sess });
        Api.setStatus("Abra uma wallet primeiro.");
        return;
      }

      const wi = await Api.wallet.info(sess.data.activeWalletPath);
      if (!wi.ok) {
        setOut({ where: "wallet.info", resp: wi });
        Api.setStatus(`WalletInfo erro: ${wi.error.message}`);
        return;
      }

      const r = await Api.did.createOwn();
      setOut({ where: "did.createOwn", resp: r });
      Api.setStatus(r.ok ? "DID criado." : `Erro: ${r.error.message}`);
      if (r.ok) await refreshList();
    } catch (e) {
      setOut({ where: "did.createOwn", exception: String(e?.message || e) });
      Api.setStatus(`Falha: ${e?.message || e}`);
    }
  });

  $("#btn_refresh").addEventListener("click", refreshList);
  $("#cat").addEventListener("change", refreshList);

  $("#q").addEventListener("input", () => {
    pageIndex = 1;
    renderTable();
  });

  $("#sort").addEventListener("change", () => {
    pageIndex = 1;
    renderTable();
  });

  $("#pageSize").addEventListener("change", () => {
    pageIndex = 1;
    renderTable();
  });

  $("#btn_prev").addEventListener("click", () => {
    pageIndex -= 1;
    renderTable();
  });

  $("#btn_next").addEventListener("click", () => {
    pageIndex += 1;
    renderTable();
  });

  $("#btn_last").addEventListener("click", () => {
    applyFilterAndSort();
    pageSize = Number($("#pageSize").value || 30);
    const totalPages = Math.max(1, Math.ceil(didsView.length / pageSize));
    pageIndex = totalPages;
    renderTable();
  });

  $("#pageIndex").addEventListener("change", () => {
    const v = Number($("#pageIndex").value);
    if (!Number.isNaN(v) && v >= 1) pageIndex = v;
    renderTable();
  });

  $("#btn_first").addEventListener("click", () => {
    pageIndex = 1;
    renderTable();
  });

  // clique tabela: seleção por linha + ações por botão
  $("#tbl").addEventListener("click", async (ev) => {
    const btn = ev.target.closest("button");
    const tr = ev.target.closest("tr");
    const idxStr = btn?.dataset?.idx || tr?.dataset?.idx;
    if (idxStr === undefined) return;

    // pega o slice atual
    applyFilterAndSort();
    const { slice } = getPagination();

    const idx = Number(idxStr);
    const d = slice[idx];
    if (!d) return;

    if (btn) {
      const act = btn.dataset.act;
      if (act === "copyDid") {
        await navigator.clipboard.writeText(d.did || "");
        Api.setStatus("DID copiado.");
      } else if (act === "copyVk") {
        await navigator.clipboard.writeText(d.verkey || "");
        Api.setStatus("Verkey copiada.");
      }
      return;
    }

    // clique na linha => seleciona
    selectedDid = d;
    renderTable();
  });

  $("#btn_export").addEventListener("click", async () => {
    Api.setStatus("Exportando DIDs...");
    try {
      const r = await Api.did.exportFile();
      setOut({ where: "did.exportFile", resp: r });
      Api.setStatus(r.ok
        ? (r.data.canceled ? "Export cancelado." : `Export OK: ${r.data.count}`)
        : `Erro: ${r.error.message}`);
    } catch (e) {
      setOut({ where: "did.exportFile", exception: String(e?.message || e) });
      Api.setStatus(`Falha: ${e?.message || e}`);
    }
  });

  $("#btn_import").addEventListener("click", async () => {
    Api.setStatus("Importando DIDs...");
    try {
      const r = await Api.did.importFile();
      setOut({ where: "did.importFile", resp: r });
      if (r.ok) {
        if (r.data.canceled) {
          Api.setStatus("Import cancelado.");
        } else {
          Api.setStatus(
            `Import OK: ${r.data.importedCount} importados | ${r.data.skippedCount} ignorados | ${r.data.errorCount} erros`
          );
        }
      } else {
        Api.setStatus(`Erro: ${r.error.message}`);
      }
      if (r.ok && !r.data.canceled) {
        if (Number(r?.data?.importedCount || 0) > 0) $("#cat").value = "external";
        await refreshList({ silentOut: true, silentStatus: true });
      }
    } catch (e) {
      setOut({ where: "did.importFile", exception: String(e?.message || e) });
      Api.setStatus(`Falha: ${e?.message || e}`);
    }
  });

  $("#btn_import_trustee").addEventListener("click", async () => {
    const seed = ($("#trustee_seed").value || "").trim();
    if (!seed) { setOut({ where: "did.importTrustee", error: "TRUSTEE_SEED vazio" }); Api.setStatus("Informe TRUSTEE_SEED."); return; }
    if (seed.length !== 32) { setOut({ where: "did.importTrustee", error: "SEED_INVALID_LEN", seedLen: seed.length }); Api.setStatus("Seed deve ter 32 caracteres."); return; }

    Api.setStatus("Importando Trustee na wallet...");
    const r = await Api.did.importTrustee(seed);
    setOut({ where: "did.importTrustee", resp: r });
    Api.setStatus(r.ok ? "Trustee importado." : `Erro: ${r.error.message}`);
  });

  $("#btn_register").addEventListener("click", async () => {
    if (!selectedDid) { Api.setStatus("Selecione um DID na tabela."); return; }

    const genesisPath = ($("#g_path").value || "").trim();
    const roleIn = ($("#role").value || "").trim();
    const seed = ($("#trustee_seed").value || "").trim();
    const trusteeDid = ($("#trustee_did").value || "").trim();

    if (!genesisPath) { Api.setStatus("Informe o Genesis path."); return; }
    if (!seed) { Api.setStatus("Informe TRUSTEE_SEED."); return; }
    if (!trusteeDid) { Api.setStatus("Informe TRUSTEE_DID."); return; }

    Api.setStatus("Importando Trustee (seed)...");
    const imp = await Api.did.importTrustee(seed);
    setOut({ where: "did.importTrustee", resp: imp });
    if (!imp.ok) { Api.setStatus(`Erro importando trustee: ${imp.error.message}`); return; }

    Api.setStatus("Registrando DID no ledger...");
    const role = roleIn === "" ? null : roleIn;

    const r = await Api.did.registerOnLedger(
      genesisPath,
      trusteeDid,
      selectedDid.did,
      selectedDid.verkey,
      role
    );

    setOut({ where: "did.registerOnLedger", selectedDid, resp: r });
    Api.setStatus(r.ok ? "DID registrado no ledger." : `Erro: ${r.error.message}`);
  });

  // Carrega lista ao abrir
  refreshList().catch(() => { });
  return {};
})();
