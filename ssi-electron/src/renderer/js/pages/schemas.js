// src/renderer/js/pages/schemas.js
/* eslint-disable no-console */

const SchemasPage = (() => {
    const root = document.getElementById("page-schemas");
    if (!root) return {};
    const DEFAULT_DID_LIMIT = 150;
    const MAX_DID_LIMIT = 1000;

    // -------------------------
    // UI
    // -------------------------
    root.innerHTML = `
    <div class="card">
      <h2>Schemas</h2>
      <p class="small">
        Catálogo local (rascunho/cache), preview antes de publicar, e operações no ledger.
      </p>

      <div class="row">
        <button class="secondary" id="btn_refresh">Atualizar lista local</button>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>1) Criar e salvar local (rascunho) + Preview</h3>

      <div class="row">
        <div class="input" style="min-width:280px">
          <label>Nome</label>
          <input id="new_name" placeholder="ex.: CPF_END_CONTATO" />
        </div>

        <div class="input" style="min-width:160px">
          <label>Versão</label>
          <input id="new_version" placeholder="ex.: 1.0" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>DID emissor (opcional no rascunho)</label>
          <select id="new_issuer_select">
            <option value="">Selecione um DID...</option>
          </select>
        </div>
        <button class="secondary" id="btn_new_issuer_refresh">Atualizar DIDs</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de DIDs</label>
          <input id="new_issuer_filter" placeholder="Filtrar por DID, alias, verkey ou categoria..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="new_issuer_limit" type="number" min="1" max="${MAX_DID_LIMIT}" value="${DEFAULT_DID_LIMIT}" />
        </div>
        <button class="secondary" id="btn_new_issuer_clear_filter">Limpar filtro</button>
      </div>
      <p class="small" id="new_issuer_stats">DIDs: 0</p>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Atributos (1 por linha ou separados por vírgula)</label>
          <textarea id="new_attrs" rows="5" placeholder="cpf\nendereco\ncontato\nidade"></textarea>
        </div>
      </div>

      <div class="row">
        <label class="small" style="display:flex; gap:10px; align-items:center;">
          <input type="checkbox" id="new_revocable" />
          Schema com suporte a revogação (seu schemaBuildPreview deve ajustar o preview)
        </label>
      </div>

      <div class="row">
        <button class="primary" id="btn_preview">Gerar preview</button>
        <button class="secondary" id="btn_save_local">Salvar local (rascunho)</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Preview</label>
          <textarea id="preview_out" rows="10" readonly></textarea>
        </div>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>2) Catálogo local</h3>

      <div class="row">
        <div class="input" style="min-width:280px">
          <label>Buscar</label>
          <input id="q" placeholder="nome/id/issuer..." />
        </div>

        <div class="input" style="min-width:140px">
          <label>Limite</label>
          <input id="limit" value="50" />
        </div>

        <button class="secondary" id="btn_search">Buscar</button>
      </div>

      <div class="tableWrap">
        <table class="table" id="tbl">
          <thead>
            <tr>
              <th>ID</th>
              <th>Nome</th>
              <th>Versão</th>
              <th>Issuer</th>
              <th>Ações</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Selecionado (ID local)</label>
          <input id="sel_id" placeholder="clique em 'Abrir/Usar'" />
        </div>
      </div>

      <div class="row">
        <button class="secondary" id="btn_get">Abrir (getLocal)</button>
        <button class="secondary" id="btn_use">Usar p/ Publicar</button>
        <button class="secondary" id="btn_delete">Excluir local</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Schema local (getLocal)</label>
          <textarea id="local_out" rows="10" readonly></textarea>
        </div>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>3) Schema no ledger</h3>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Genesis path (obrigatório p/ publicar e buscar)</label>
          <input id="genesis_path" placeholder="/caminho/para/genesis.txn" />
        </div>
      </div>

      <h4>Publicar no ledger (a partir do local)</h4>
      <div class="row">
        <div class="input" style="min-width:520px">
          <label>DID emissor (obrigatório)</label>
          <select id="pub_issuer_select">
            <option value="">Selecione um DID...</option>
          </select>
        </div>
        <button class="secondary" id="btn_pub_issuer_refresh">Atualizar DIDs</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de DIDs</label>
          <input id="pub_issuer_filter" placeholder="Filtrar por DID, alias, verkey ou categoria..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="pub_issuer_limit" type="number" min="1" max="${MAX_DID_LIMIT}" value="${DEFAULT_DID_LIMIT}" />
        </div>
        <button class="secondary" id="btn_pub_issuer_clear_filter">Limpar filtro</button>
      </div>
      <p class="small" id="pub_issuer_stats">DIDs: 0</p>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>ID local do schema</label>
          <input id="pub_local_id" placeholder="cole o id local (ou use 'Usar p/ Publicar')" />
        </div>
      </div>

      <div class="row">
        <button class="primary" id="btn_publish">Publicar</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Resultado publicação</label>
          <textarea id="pub_out" rows="10" readonly></textarea>
        </div>
      </div>

      <h4>Buscar no ledger</h4>
      <div class="row">
        <div class="input" style="min-width:520px">
          <label>SchemaId (ledger)</label>
          <input id="ledger_id" placeholder="schema_id completo" />
        </div>
        <button class="secondary" id="btn_fetch_ledger">Buscar</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Schema (ledger)</label>
          <textarea id="ledger_out" rows="10" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="out">{}</pre>
    </div>
    <div id="schemas_confirm_overlay" style="display:none; position:fixed; inset:0; z-index:9999; background:rgba(17,24,39,0.35); align-items:center; justify-content:center; padding:16px;">
      <div style="width:min(100%, 420px); background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:16px; box-shadow:0 10px 30px rgba(17,24,39,0.2);">
        <h3 style="margin:0 0 8px 0;">Confirmar ação</h3>
        <p id="schemas_confirm_text" style="margin:0; color:#111827;"></p>
        <div class="row" style="margin-top:16px; justify-content:flex-end;">
          <button class="secondary" id="btn_schemas_confirm_cancel">Cancelar</button>
          <button class="primary" id="btn_schemas_confirm_ok">Confirmar</button>
        </div>
      </div>
    </div>
  `;

    const $ = (sel) => root.querySelector(sel);
    const out = $("#out");
    const confirmOverlay = $("#schemas_confirm_overlay");
    const confirmText = $("#schemas_confirm_text");
    const confirmBtnOk = $("#btn_schemas_confirm_ok");
    const confirmBtnCancel = $("#btn_schemas_confirm_cancel");
    const didUis = {
        draft: {
            select: $("#new_issuer_select"),
            filter: $("#new_issuer_filter"),
            limit: $("#new_issuer_limit"),
            clearBtn: $("#btn_new_issuer_clear_filter"),
            refreshBtn: $("#btn_new_issuer_refresh"),
            stats: $("#new_issuer_stats"),
        },
        publish: {
            select: $("#pub_issuer_select"),
            filter: $("#pub_issuer_filter"),
            limit: $("#pub_issuer_limit"),
            clearBtn: $("#btn_pub_issuer_clear_filter"),
            refreshBtn: $("#btn_pub_issuer_refresh"),
            stats: $("#pub_issuer_stats"),
        },
    };
    let didOptions = [];
    let visibleDidOptions = {
        draft: [],
        publish: [],
    };
    let confirmResolve = null;
    let confirmFallbackSelector = "#btn_delete";
    let confirmPrevFocused = null;

    function setOut(obj) { out.textContent = JSON.stringify(obj, null, 2); }

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

    function openInlineConfirm(message, fallbackSelector) {
        if (confirmResolve) return Promise.resolve(false);
        confirmPrevFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
        confirmFallbackSelector = fallbackSelector || "#btn_delete";
        confirmText.textContent = String(message || "");
        confirmOverlay.style.display = "flex";
        focusElementSafe(confirmBtnOk);
        return new Promise((resolve) => {
            confirmResolve = resolve;
        });
    }

    function parseDidPayload(resp) {
        if (!resp || !resp.ok) return [];
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

    function normalizeDidRecord(raw, category) {
        if (!raw || typeof raw !== "object") return null;
        const did = String(raw.did || raw.id || "").trim();
        if (!did) return null;
        return {
            did,
            alias: String(raw.alias || "").trim(),
            verkey: String(raw.verkey || raw.verKey || "").trim(),
            category: String(category || "").trim(),
        };
    }

    function normalizeText(v) {
        return String(v || "").toLocaleLowerCase("pt-BR");
    }

    function parseDidLimit(value) {
        const parsed = Number.parseInt(String(value || ""), 10);
        if (!Number.isFinite(parsed) || parsed < 1) return DEFAULT_DID_LIMIT;
        return Math.min(parsed, MAX_DID_LIMIT);
    }

    function toDidSearchBlob(rec) {
        return normalizeText([
            rec.did,
            rec.alias,
            rec.verkey,
            rec.category,
        ].filter(Boolean).join(" "));
    }

    function renderDidSelect(scope, items) {
        const ui = didUis[scope];
        const currentDid = String(ui.select.value || "").trim();
        ui.select.innerHTML = `<option value="">Selecione um DID...</option>`;

        const fragment = document.createDocumentFragment();
        items.forEach((d) => {
            const opt = document.createElement("option");
            opt.value = d.did;
            const aliasPrefix = d.alias ? `${d.alias} - ` : "";
            const suffix = d.category ? ` (${d.category})` : "";
            opt.textContent = `${aliasPrefix}${d.did}${suffix}`;
            fragment.appendChild(opt);
        });
        ui.select.appendChild(fragment);

        if (currentDid && items.some((d) => d.did === currentDid)) {
            ui.select.value = currentDid;
        }
    }

    function updateDidStats(scope, total, filtered, shown, limit) {
        didUis[scope].stats.textContent = `DIDs: total ${total} | filtrados ${filtered} | exibidos ${shown} (máx ${limit})`;
    }

    function applyDidFilter(scope) {
        const ui = didUis[scope];
        const filterText = normalizeText(ui.filter.value).trim();
        const limit = parseDidLimit(ui.limit.value);
        ui.limit.value = String(limit);

        const filtered = filterText
            ? didOptions.filter((d) => toDidSearchBlob(d).includes(filterText))
            : didOptions;

        const visible = filtered.slice(0, limit);
        visibleDidOptions[scope] = visible;
        renderDidSelect(scope, visible);
        updateDidStats(scope, didOptions.length, filtered.length, visible.length, limit);
    }

    function applyDidFilters() {
        applyDidFilter("draft");
        applyDidFilter("publish");
    }

    function getSelectedDid(scope) {
        return String(didUis[scope].select.value || "").trim();
    }

    async function refreshDidOptions() {
        Api.setStatus("Carregando DIDs para seleção...");
        const [ownResp, extResp] = await Promise.all([
            Api.did.list("own"),
            Api.did.list("external"),
        ]);

        const map = new Map();
        parseDidPayload(ownResp).forEach((raw) => {
            const rec = normalizeDidRecord(raw, "own");
            if (rec && !map.has(rec.did)) map.set(rec.did, rec);
        });
        parseDidPayload(extResp).forEach((raw) => {
            const rec = normalizeDidRecord(raw, "external");
            if (rec && !map.has(rec.did)) map.set(rec.did, rec);
        });

        didOptions = Array.from(map.values()).sort((a, b) => {
            return String(a.did).localeCompare(String(b.did), "pt-BR", { sensitivity: "base" });
        });
        applyDidFilters();

        setOut({
            where: "schemas.refreshDidOptions",
            total: didOptions.length,
            visibleDraft: visibleDidOptions.draft.length,
            visiblePublish: visibleDidOptions.publish.length,
            draftFilter: String(didUis.draft.filter.value || "").trim(),
            publishFilter: String(didUis.publish.filter.value || "").trim(),
            draftLimit: parseDidLimit(didUis.draft.limit.value),
            publishLimit: parseDidLimit(didUis.publish.limit.value),
            ownResp,
            externalResp: extResp,
        });
        Api.setStatus(`DIDs carregados: ${didOptions.length}.`);
    }

    function parseSchemaRecord(raw) {
        if (!raw) return null;
        if (typeof raw === "string") {
            try { return JSON.parse(raw); } catch (_) { return null; }
        }
        if (typeof raw === "object") {
            if (typeof raw.json === "string") {
                try { return JSON.parse(raw.json); } catch (_) { return null; }
            }
            return raw;
        }
        return null;
    }

    function normalizeAttrs(txt) {
        const parts = String(txt || "")
            .split(/[\n,;]+/g)
            .map(s => s.trim())
            .filter(Boolean);

        const seen = new Set();
        const res = [];
        for (const p of parts) {
            const k = p.toLowerCase();
            if (!seen.has(k)) { seen.add(k); res.push(p); }
        }
        return res;
    }

    function renderTable(items) {
        const tbody = $("#tbl").querySelector("tbody");
        tbody.innerHTML = "";

        (items || []).forEach((it) => {
            const localId = String(it.id_local || it.id || "");
            const tr = document.createElement("tr");
            tr.dataset.id = localId;
            tr.innerHTML = `
        <td class="mono">${localId}</td>
        <td>${String(it.name || "")}</td>
        <td>${String(it.version || "")}</td>
        <td class="mono">${String(it.issuer_did || "")}</td>
        <td>
          <div class="actions">
            <button data-act="open">Abrir</button>
            <button data-act="use">Usar</button>
          </div>
        </td>
      `;
            tbody.appendChild(tr);
        });
    }

    async function refreshList() {
        Api.setStatus("Listando schemas locais...");
        const nameEq = ($("#q").value || "").trim(); // aqui vira name_eq (igualdade)
        const r = await Api.schema.listLocal(false, "template", nameEq || null);
        setOut({ where: "schema.listLocal", resp: r });

        if (!r.ok) {
            Api.setStatus(`Erro schema.listLocal: ${r.error.message}`);
            renderTable([]);
            return;
        }

        // Atenção: seu backend pode retornar JSON string ou objeto.
        // Aqui eu tento cobrir os 2 casos.
        let items = [];
        try {
            const data = r.data; // deve ser array de strings
            if (Array.isArray(data)) {
                items = data.map((s) => {
                    try { return JSON.parse(s); } catch (_) { return null; }
                }).filter(Boolean);
            }
        } catch (_) { items = []; }

        renderTable(items);
        Api.setStatus(`OK: ${items.length} schema(s) local.`);
    }

    async function doPreview() {
        const name = ($("#new_name").value || "").trim();
        const version = ($("#new_version").value || "").trim();
        const issuerDid = getSelectedDid("draft");
        const attrs = normalizeAttrs($("#new_attrs").value);
        const revocable = !!$("#new_revocable").checked;

        if (!name) { Api.setStatus("Informe nome."); return null; }
        if (!version) { Api.setStatus("Informe versão."); return null; }
        if (attrs.length === 0) { Api.setStatus("Informe atributos."); return null; }

        Api.setStatus("Gerando preview...");
        const input = { name, version, issuer_did: issuerDid || null, attrs, revocable };
        const r = await Api.schema.buildPreview(name, version, attrs, revocable);

        setOut({ where: "schema.buildPreview", input, resp: r });

        if (!r.ok) {
            Api.setStatus(`Erro preview: ${r.error.message}`);
            return null;
        }

        // idem: pode vir string/obj
        let preview = r.data;
        try { if (typeof preview === "string") preview = JSON.parse(preview); } catch (_) { /* ignore */ }

        $("#preview_out").value = JSON.stringify(preview, null, 2);
        Api.setStatus("Preview OK.");
        return preview;
    }

    async function saveLocal() {
        const preview = await doPreview();
        if (!preview) return;

        Api.setStatus("Salvando schema local...");
        const name = $("#new_name").value.trim();
        const version = $("#new_version").value.trim();
        const attrs = normalizeAttrs($("#new_attrs").value);
        const revocable = $("#new_revocable").checked;

        const r = await Api.schema.saveLocal(name, version, attrs, revocable, "template");
        setOut({ where: "schema.saveLocal", resp: r });

        Api.setStatus(r.ok ? "Salvo local." : `Erro: ${r.error.message}`);
        if (r.ok) refreshList().catch(() => { });
    }

    async function getLocal() {
        const id = ($("#sel_id").value || "").trim();
        if (!id) { Api.setStatus("Informe/Selecione o ID local."); return; }

        Api.setStatus("Carregando schema local...");
        const r = await Api.schema.getLocal(id);
        setOut({ where: "schema.getLocal", id, resp: r });

        if (!r.ok) {
            Api.setStatus(`Erro getLocal: ${r.error.message}`);
            $("#local_out").value = "";
            return;
        }

        const data = parseSchemaRecord(r.data);
        $("#local_out").value = JSON.stringify(data || r.data, null, 2);

        Api.setStatus("OK.");
    }

    async function deleteLocal() {
        const id = ($("#sel_id").value || "").trim();
        if (!id) { Api.setStatus("Informe/Selecione o ID local."); return; }

        const ok = await openInlineConfirm(`Excluir schema local "${id}"?`, "#btn_delete");
        if (!ok) return;

        Api.setStatus("Excluindo schema local...");
        const r = await Api.schema.deleteLocal(id);
        setOut({ where: "schema.deleteLocal", id, resp: r });

        Api.setStatus(r.ok ? "Excluído." : `Erro: ${r.error.message}`);
        if (r.ok) {
            $("#sel_id").value = "";
            $("#local_out").value = "";
            refreshList().catch(() => { });
        }
    }

    async function publishFromLocal() {
        const pubOut = $("#pub_out");
        const btnPublish = $("#btn_publish");
        if (btnPublish?.disabled) return;
        if (btnPublish) btnPublish.disabled = true;
        pubOut.value = "";
        try {
            const genesisPath = ($("#genesis_path").value || "").trim();
            const issuerDid = getSelectedDid("publish");
            const localId = ($("#pub_local_id").value || "").trim();
            if (!genesisPath) {
                pubOut.value = JSON.stringify({ error: "Informe Genesis path." }, null, 2);
                Api.setStatus("Informe Genesis path.");
                return;
            }
            if (!issuerDid) {
                pubOut.value = JSON.stringify({ error: "Informe DID emissor." }, null, 2);
                Api.setStatus("Informe DID emissor.");
                return;
            }
            if (!localId) {
                pubOut.value = JSON.stringify({ error: "Informe ID local do schema." }, null, 2);
                Api.setStatus("Informe ID local do schema.");
                return;
            }

            Api.setStatus("Carregando schema local p/ publicar...");
            const gl = await Api.schema.getLocal(localId);
            if (!gl.ok) {
                setOut({ where: "schema.getLocal(for publish)", localId, resp: gl });
                pubOut.value = JSON.stringify(gl, null, 2);
                Api.setStatus(`Erro getLocal: ${gl.error.message}`);
                return;
            }

            const localObj = parseSchemaRecord(gl.data);
            if (!localObj || !localObj.name || !localObj.version) {
                setOut({ where: "schema.getLocal(for publish)", localId, parsed: localObj, resp: gl });
                pubOut.value = JSON.stringify({ error: "Schema local inválido para publicação.", localObj, raw: gl }, null, 2);
                Api.setStatus("Schema local inválido para publicação.");
                return;
            }

            Api.setStatus("Publicando no ledger...");
            const name = localObj?.name;
            const version = localObj?.version;
            const attrNames = Array.isArray(localObj?.final_attr_names) ? localObj.final_attr_names
                : Array.isArray(localObj?.attr_names) ? localObj.attr_names
                    : [];
            const r = await Api.schema.createAndRegister(genesisPath, issuerDid, name, version, attrNames);
            setOut({ where: "schema.createAndRegister", issuerDid, localId, resp: r });

            if (!r.ok) {
                const msg = String(r?.error?.message || "");
                if (msg.includes("Duplicate entry")) {
                    const schemaId = `${issuerDid}:2:${name}:${version}`;
                    pubOut.value = JSON.stringify(
                        {
                            ok: true,
                            alreadyPublished: true,
                            message: "Schema já havia sido publicado anteriormente.",
                            schemaId,
                            raw: r,
                        },
                        null,
                        2
                    );
                    Api.setStatus("Schema já publicado.");
                    return;
                }
                pubOut.value = JSON.stringify(r, null, 2);
                Api.setStatus(`Erro publicar: ${r.error.message}`);
                return;
            }

            let pub = r.data;
            try { if (typeof pub === "string") pub = JSON.parse(pub); } catch (_) { /* keep raw string */ }
            if (typeof pub === "string") {
                pub = { schemaId: pub };
            }
            if (pub === undefined || pub === null || pub === "") {
                pub = {
                    message: "Publicação concluída, mas sem payload em r.data",
                    raw: r,
                };
            }
            if (pub && typeof pub === "object" && pub.schemaId) {
                $("#ledger_id").value = String(pub.schemaId);
            }
            pubOut.value = JSON.stringify(pub, null, 2);
            Api.setStatus("Publicado.");
            refreshList().catch(() => { });
        } catch (e) {
            pubOut.value = JSON.stringify(
                { error: String(e?.message || e), stack: String(e?.stack || "") },
                null,
                2
            );
            Api.setStatus(`Erro publicar: ${String(e?.message || e)}`);
        } finally {
            if (btnPublish) btnPublish.disabled = false;
        }
    }

    async function fetchLedger() {
        const genesisPath = ($("#genesis_path").value || "").trim();
        const schemaId = ($("#ledger_id").value || "").trim();
        if (!genesisPath) { Api.setStatus("Informe Genesis path."); return; }
        if (!schemaId) { Api.setStatus("Informe SchemaId."); return; }

        Api.setStatus("Buscando schema no ledger...");
        const r = await Api.schema.fetchFromLedger(genesisPath, schemaId);
        setOut({ where: "schema.fetchFromLedger", schemaId, resp: r });

        if (!r.ok) {
            Api.setStatus(`Erro fetch: ${r.error.message}`);
            $("#ledger_out").value = "";
            return;
        }

        let data = r.data;
        try { if (typeof data === "string") data = JSON.parse(data); } catch (_) { }
        $("#ledger_out").value = JSON.stringify(data, null, 2);
        Api.setStatus("OK.");
    }

    // -------------------------
    // Events
    // -------------------------
    $("#btn_refresh").addEventListener("click", refreshList);
    $("#btn_search").addEventListener("click", refreshList);
    $("#btn_preview").addEventListener("click", doPreview);
    $("#btn_save_local").addEventListener("click", saveLocal);

    $("#btn_get").addEventListener("click", getLocal);
    $("#btn_use").addEventListener("click", () => {
        const id = ($("#sel_id").value || "").trim();
        if (!id) { Api.setStatus("Selecione um ID na tabela ou digite."); return; }
        $("#pub_local_id").value = id;
        Api.setStatus("ID local aplicado para publicar.");
    });
    $("#btn_delete").addEventListener("click", () => {
        deleteLocal().catch(() => { });
    });
    confirmBtnOk.addEventListener("click", () => closeInlineConfirm(true));
    confirmBtnCancel.addEventListener("click", () => closeInlineConfirm(false));
    confirmOverlay.addEventListener("click", (ev) => {
        if (ev.target === confirmOverlay) closeInlineConfirm(false);
    });

    $("#btn_publish").addEventListener("click", publishFromLocal);
    $("#btn_fetch_ledger").addEventListener("click", fetchLedger);
    didUis.draft.filter.addEventListener("input", () => applyDidFilter("draft"));
    didUis.publish.filter.addEventListener("input", () => applyDidFilter("publish"));
    didUis.draft.filter.addEventListener("keyup", () => applyDidFilter("draft"));
    didUis.publish.filter.addEventListener("keyup", () => applyDidFilter("publish"));
    didUis.draft.limit.addEventListener("input", () => applyDidFilter("draft"));
    didUis.publish.limit.addEventListener("input", () => applyDidFilter("publish"));
    didUis.draft.limit.addEventListener("change", () => applyDidFilter("draft"));
    didUis.publish.limit.addEventListener("change", () => applyDidFilter("publish"));
    didUis.draft.clearBtn.addEventListener("click", () => {
        didUis.draft.filter.value = "";
        applyDidFilter("draft");
    });
    didUis.publish.clearBtn.addEventListener("click", () => {
        didUis.publish.filter.value = "";
        applyDidFilter("publish");
    });
    didUis.draft.refreshBtn.addEventListener("click", refreshDidOptions);
    didUis.publish.refreshBtn.addEventListener("click", refreshDidOptions);

    // clique na tabela
    $("#tbl").addEventListener("click", async (ev) => {
        const btn = ev.target.closest("button[data-act]");
        const tr = ev.target.closest("tr[data-id]");
        if (!tr) return;
        const id = tr.dataset.id;

        if (btn?.dataset?.act === "open") {
            $("#sel_id").value = id;
            await getLocal();
        } else if (btn?.dataset?.act === "use") {
            $("#sel_id").value = id;
            $("#pub_local_id").value = id;
            Api.setStatus("Selecionado para publicar.");
        } else {
            $("#sel_id").value = id;
            Api.setStatus("Selecionado.");
        }
    });

    // init
    refreshList().catch(() => { });
    refreshDidOptions().catch(() => { });
    return {};
})();
