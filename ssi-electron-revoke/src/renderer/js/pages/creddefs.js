// src/renderer/js/pages/creddefs.js
/* eslint-disable no-console */

const CredDefsPage = (() => {
  const root = document.getElementById("page-creddefs");
  if (!root) return {};
  const DEFAULT_LIST_LIMIT = 150;
  const MAX_LIST_LIMIT = 1000;

  let didOptions = [];
  let schemaOptions = [];
  let visibleDidOptions = [];
  let visibleSchemaOptions = [];

  root.innerHTML = `
    <div class="card">
      <h2>CredDefs</h2>
      <p class="small">
        Escolha o Schema e o DID emissor para criar/publicar Credential Definition no ledger.
      </p>

      <div class="row">
        <button class="secondary" id="btn_refresh_opts">Atualizar DIDs e Schemas</button>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>1) Selecao</h3>

      <div class="row">
        <div class="input" style="min-width:320px">
          <label>DID emissor (lista own)</label>
          <select id="sel_did">
            <option value="">-- selecione um DID --</option>
          </select>
        </div>

        <div class="input" style="min-width:420px">
          <label>DID emissor (manual)</label>
          <input id="issuer_did" placeholder="ex.: V4SGRU86Z58d6TV7PBUe6f" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de DIDs</label>
          <input id="did_filter" placeholder="Filtrar por DID, alias ou verkey..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="did_limit" type="number" min="1" max="${MAX_LIST_LIMIT}" value="${DEFAULT_LIST_LIMIT}" />
        </div>
        <button class="secondary" id="btn_clear_did_filter">Limpar filtro</button>
      </div>
      <p class="small" id="did_stats">DIDs: 0</p>

      <div class="row">
        <div class="input" style="min-width:420px">
          <label>Schema (a partir dos schemas locais)</label>
          <select id="sel_schema">
            <option value="">-- selecione um schema --</option>
          </select>
        </div>

        <div class="input" style="min-width:520px">
          <label>Schema ID (ledger)</label>
          <input id="schema_id" placeholder="ex.: V4SGRU86Z58d6TV7PBUe6f:2:NomeSchema:1.0" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de Schemas</label>
          <input id="schema_filter" placeholder="Filtrar por schema ID, nome, versão ou emissor..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="schema_limit" type="number" min="1" max="${MAX_LIST_LIMIT}" value="${DEFAULT_LIST_LIMIT}" />
        </div>
        <button class="secondary" id="btn_clear_schema_filter">Limpar filtro</button>
      </div>
      <p class="small" id="schema_stats">Schemas: 0</p>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Genesis path</label>
          <input id="genesis_path" placeholder="/caminho/para/genesis.txn" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:220px">
          <label>Tag</label>
          <input id="tag" value="TAG1" />
        </div>

        <div class="input" style="min-width:220px">
          <label>Env local</label>
          <input id="env_label" value="template" />
        </div>

        <label class="small" style="display:flex; gap:10px; align-items:center; min-width:240px;">
          <input type="checkbox" id="support_revocation" />
          Suporte a revogacao (fluxo local)
        </label>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>2) Operacoes</h3>

      <div class="row">
        <button class="secondary" id="btn_save_local">Salvar CredDef local</button>
        <button class="primary" id="btn_publish_local">Publicar do local</button>
        <button class="secondary" id="btn_publish_direct">Publicar no ledger</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>ID local CredDef</label>
          <input id="local_id" placeholder="preenchido apos salvar local" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>CredDef ID</label>
          <input id="creddef_id" placeholder="preenchido apos publicar" />
        </div>
        <button class="secondary" id="btn_fetch_ledger">Buscar CredDef no ledger</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Resultado</label>
          <textarea id="result_out" rows="10" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="out">{}</pre>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#out");

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
    if (typeof raw === "object") {
      return raw;
    }
    return raw;
  }

  function extractCredDefId(data) {
    if (data === undefined || data === null) return "";

    if (typeof data === "string") {
      const txt = data.trim();
      if (txt.includes(":3:CL:")) return txt;
      return "";
    }

    if (typeof data === "object") {
      const direct = toStringSafe(data.credDefId || data.cred_def_id).trim();
      if (direct) return direct;

      if (typeof data.json === "string") {
        try {
          const parsed = JSON.parse(data.json);
          const fromJson = toStringSafe(parsed?.cred_def_id || parsed?.credDefId).trim();
          if (fromJson) return fromJson;
        } catch (_) {
          // ignore parse error
        }
      }
    }

    return "";
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async function fetchCredDefWithRetry(genesisPath, credDefId, maxAttempts, delayMs) {
    const attempts = [];
    for (let i = 1; i <= maxAttempts; i += 1) {
      const r = await Api.creddef.fetchFromLedger(genesisPath, credDefId);
      attempts.push({
        attempt: i,
        ok: !!r?.ok,
        error: r?.ok ? null : r?.error,
        dataPreview: r?.ok ? parseMaybeJson(r.data) : null,
      });

      if (r?.ok) {
        return { ok: true, response: r, attempts };
      }

      if (i < maxAttempts) {
        await sleep(delayMs);
      }
    }
    return { ok: false, response: attempts[attempts.length - 1] || null, attempts };
  }

  function schemaIdFromRecord(rec) {
    if (!rec || typeof rec !== "object") return "";

    const directSchemaId = toStringSafe(rec.schema_id || rec.schemaId).trim();
    if (directSchemaId) return directSchemaId;

    const localId = toStringSafe(rec.id_local || rec.id).trim();
    if (localId && localId.includes(":2:")) return localId;

    const issuer = toStringSafe(rec.issuer_did).trim();
    const name = toStringSafe(rec.name).trim();
    const version = toStringSafe(rec.version).trim();
    if (issuer && name && version) return `${issuer}:2:${name}:${version}`;

    return "";
  }

  function normalizeText(v) {
    return toStringSafe(v).toLocaleLowerCase("pt-BR");
  }

  function parseListLimit(value) {
    const parsed = Number.parseInt(toStringSafe(value), 10);
    if (!Number.isFinite(parsed) || parsed < 1) return DEFAULT_LIST_LIMIT;
    return Math.min(parsed, MAX_LIST_LIMIT);
  }

  function didSearchBlob(d) {
    return normalizeText([
      d.did,
      d.alias,
      d.verkey,
      d.verKey,
    ].filter(Boolean).join(" "));
  }

  function schemaSearchBlob(s) {
    return normalizeText([
      s.schemaId,
      s.label,
      s.name,
      s.version,
      s.issuerDid,
    ].filter(Boolean).join(" "));
  }

  function renderDidOptions(items) {
    const el = $("#sel_did");
    const currentDid = toStringSafe(el.value).trim();
    el.innerHTML = `<option value="">-- selecione um DID --</option>`;

    const fragment = document.createDocumentFragment();
    (items || []).forEach((d) => {
      const did = toStringSafe(d.did).trim();
      if (!did) return;
      const label = `${did}${d.alias ? ` (${d.alias})` : ""}`;
      const opt = document.createElement("option");
      opt.value = did;
      opt.textContent = label;
      fragment.appendChild(opt);
    });
    el.appendChild(fragment);

    if (currentDid && (items || []).some((d) => toStringSafe(d.did).trim() === currentDid)) {
      el.value = currentDid;
    }
  }

  function renderSchemaOptions(items) {
    const el = $("#sel_schema");
    const currentSchemaId = toStringSafe(el.value).trim();
    el.innerHTML = `<option value="">-- selecione um schema --</option>`;

    const fragment = document.createDocumentFragment();
    (items || []).forEach((s) => {
      const opt = document.createElement("option");
      opt.value = s.schemaId;
      opt.textContent = `${s.schemaId}${s.label ? ` | ${s.label}` : ""}`;
      fragment.appendChild(opt);
    });
    el.appendChild(fragment);

    if (currentSchemaId && (items || []).some((s) => toStringSafe(s.schemaId).trim() === currentSchemaId)) {
      el.value = currentSchemaId;
    }
  }

  function updateListStats(elId, label, total, filtered, shown, limit) {
    $(elId).textContent = `${label}: total ${total} | filtrados ${filtered} | exibidos ${shown} (máx ${limit})`;
  }

  function applyDidFilter() {
    const filterText = normalizeText($("#did_filter").value).trim();
    const limit = parseListLimit($("#did_limit").value);
    $("#did_limit").value = String(limit);

    const filtered = filterText
      ? didOptions.filter((d) => didSearchBlob(d).includes(filterText))
      : didOptions;

    visibleDidOptions = filtered.slice(0, limit);
    renderDidOptions(visibleDidOptions);
    updateListStats("#did_stats", "DIDs", didOptions.length, filtered.length, visibleDidOptions.length, limit);
  }

  function applySchemaFilter() {
    const filterText = normalizeText($("#schema_filter").value).trim();
    const limit = parseListLimit($("#schema_limit").value);
    $("#schema_limit").value = String(limit);

    const filtered = filterText
      ? schemaOptions.filter((s) => schemaSearchBlob(s).includes(filterText))
      : schemaOptions;

    visibleSchemaOptions = filtered.slice(0, limit);
    renderSchemaOptions(visibleSchemaOptions);
    updateListStats("#schema_stats", "Schemas", schemaOptions.length, filtered.length, visibleSchemaOptions.length, limit);
  }

  function parseDidListPayload(dataRaw) {
    const data = parseMaybeJson(dataRaw);
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.items)) return data.items;
    return [];
  }

  async function refreshOptions() {
    Api.setStatus("Carregando DIDs e Schemas...");

    const [didResp, schemaResp] = await Promise.all([
      Api.did.list("own"),
      Api.schema.listLocal(undefined, null, null),
    ]);

    setOut({
      where: "creddefs.refreshOptions",
      did: didResp,
      schemas: schemaResp,
    });

    if (!didResp.ok) {
      Api.setStatus(`Erro listando DIDs: ${didResp.error.message}`);
      return;
    }
    if (!schemaResp.ok) {
      Api.setStatus(`Erro listando Schemas: ${schemaResp.error.message}`);
      return;
    }

    const dids = parseDidListPayload(didResp.data);
    didOptions = Array.isArray(dids) ? dids : [];
    applyDidFilter();

    let schemas = [];
    try {
      const arr = schemaResp.data;
      if (Array.isArray(arr)) {
        schemas = arr
          .map((it) => parseMaybeJson(it))
          .filter((it) => it && typeof it === "object");
      }
    } catch (_) {
      schemas = [];
    }

    schemaOptions = schemas
      .map((rec) => {
        const schemaId = schemaIdFromRecord(rec);
        const label = [rec.name, rec.version, rec.issuer_did]
          .map((v) => toStringSafe(v).trim())
          .filter(Boolean)
          .join(" | ");
        return {
          schemaId,
          label,
          name: toStringSafe(rec.name).trim(),
          version: toStringSafe(rec.version).trim(),
          issuerDid: toStringSafe(rec.issuer_did).trim(),
        };
      })
      .filter((it) => !!it.schemaId);

    applySchemaFilter();

    Api.setStatus(
      `Opcoes carregadas: ${didOptions.length} DID(s) (${visibleDidOptions.length} exibidos), `
      + `${schemaOptions.length} schema(s) (${visibleSchemaOptions.length} exibidos).`
    );
  }

  function ensureBaseInputs() {
    const issuerDid = toStringSafe($("#issuer_did").value).trim();
    const schemaId = toStringSafe($("#schema_id").value).trim();
    const tag = toStringSafe($("#tag").value).trim();
    const genesisPath = toStringSafe($("#genesis_path").value).trim();
    return { issuerDid, schemaId, tag, genesisPath };
  }

  async function saveLocal() {
    const { issuerDid, schemaId, tag } = ensureBaseInputs();
    const supportRevocation = !!$("#support_revocation").checked;
    const envLabel = toStringSafe($("#env_label").value).trim() || null;

    if (!issuerDid) { Api.setStatus("Informe DID emissor."); return; }
    if (!schemaId) { Api.setStatus("Informe Schema ID."); return; }
    if (!tag) { Api.setStatus("Informe tag."); return; }

    Api.setStatus("Salvando creddef local...");
    const r = await Api.creddef.saveLocal(issuerDid, schemaId, tag, supportRevocation, envLabel);
    setOut({ where: "creddef.saveLocal", input: { issuerDid, schemaId, tag, supportRevocation, envLabel }, resp: r });

    if (!r.ok) {
      Api.setStatus(`Erro saveLocal: ${r.error.message}`);
      $("#result_out").value = JSON.stringify(r, null, 2);
      return;
    }

    const data = parseMaybeJson(r.data);
    if (data && typeof data === "object" && data.id_local) {
      $("#local_id").value = String(data.id_local);
    }
    $("#result_out").value = JSON.stringify(data, null, 2);
    Api.setStatus("CredDef local salvo.");
  }

  async function publishFromLocal() {
    const { issuerDid, genesisPath } = ensureBaseInputs();
    const idLocal = toStringSafe($("#local_id").value).trim();

    if (!genesisPath) { Api.setStatus("Informe Genesis path."); return; }
    if (!idLocal) { Api.setStatus("Informe ID local da CredDef."); return; }

    Api.setStatus("Publicando creddef a partir do local...");
    const r = await Api.creddef.registerFromLocal(genesisPath, idLocal, issuerDid || null);
    setOut({ where: "creddef.registerFromLocal", input: { genesisPath, idLocal, issuerDid: issuerDid || null }, resp: r });

    if (!r.ok) {
      Api.setStatus(`Erro publish local: ${r.error.message}`);
      $("#result_out").value = JSON.stringify(r, null, 2);
      return;
    }

    const data = parseMaybeJson(r.data);
    const credDefId = toStringSafe(data?.credDefId || data);
    if (credDefId) $("#creddef_id").value = credDefId;

    $("#result_out").value = JSON.stringify(data, null, 2);
    Api.setStatus("CredDef publicada (local).");
  }

  async function publishLedger() {
    const { issuerDid, schemaId, tag, genesisPath } = ensureBaseInputs();
    if (!genesisPath) { Api.setStatus("Informe Genesis path."); return; }
    if (!issuerDid) { Api.setStatus("Informe DID emissor."); return; }
    if (!schemaId) { Api.setStatus("Informe Schema ID."); return; }
    if (!tag) { Api.setStatus("Informe tag."); return; }

    const input = { genesisPath, issuerDid, schemaId, tag };
    const diagnostics = {
      where: "creddef.publishLedger.diagnostics",
      ts: new Date().toISOString(),
      input,
      connect: null,
      precheckSchema: null,
      publish: null,
      extractedCredDefId: "",
      postFetch: null,
      retryWithNewTag: null,
    };

    Api.setStatus("Conectando ao ledger com o genesis informado...");
    const connectResp = await Api.ledger.connect(genesisPath);
    diagnostics.connect = connectResp;
    if (!connectResp?.ok) {
      Api.setStatus(`Erro connect ledger: ${connectResp?.error?.message || "erro desconhecido"}`);
      $("#result_out").value = JSON.stringify(
        { ...diagnostics, stage: "connect_failed" },
        null,
        2
      );
      setOut(diagnostics);
      return;
    }

    Api.setStatus("Pre-check schema no ledger...");
    const schemaCheck = await Api.schema.fetchFromLedger(genesisPath, schemaId);
    diagnostics.precheckSchema = schemaCheck;

    Api.setStatus("Publicando creddef no ledger...");
    const r = await Api.creddef.createAndRegister(genesisPath, issuerDid, schemaId, tag);
    diagnostics.publish = r;
    setOut(diagnostics);

    if (!r.ok) {
      const errTxt = JSON.stringify(r.error || {}, null, 2);
      Api.setStatus(`Erro publicar no ledger: ${r?.error?.message || "erro desconhecido"}`);
      $("#result_out").value = JSON.stringify(
        { ...diagnostics, stage: "createAndRegister_failed", errorText: errTxt },
        null,
        2
      );
      return;
    }

    const data = parseMaybeJson(r.data);
    const credDefId = extractCredDefId(data);
    diagnostics.extractedCredDefId = credDefId;

    if (!credDefId) {
      Api.setStatus("Publicacao retornou sem credDefId identificavel.");
      $("#result_out").value = JSON.stringify(
        { ...diagnostics, stage: "missing_credDefId", publishDataParsed: data },
        null,
        2
      );
      setOut(diagnostics);
      return;
    }

    $("#creddef_id").value = credDefId;
    Api.setStatus("Validando creddef no ledger...");
    const verification = await fetchCredDefWithRetry(genesisPath, credDefId, 5, 900);
    diagnostics.postFetch = verification;
    setOut(diagnostics);
    $("#result_out").value = JSON.stringify(diagnostics, null, 2);

    if (!verification.ok) {
      const retryTag = `${tag}_${Date.now()}`;
      diagnostics.retryWithNewTag = {
        tag: retryTag,
        publish: null,
        extractedCredDefId: "",
        postFetch: null,
      };

      Api.setStatus(`Sem confirmacao no ledger. Tentando nova tag: ${retryTag}...`);
      const retryPublish = await Api.creddef.createAndRegister(genesisPath, issuerDid, schemaId, retryTag);
      diagnostics.retryWithNewTag.publish = retryPublish;

      if (retryPublish?.ok) {
        const retryData = parseMaybeJson(retryPublish.data);
        const retryCredDefId = extractCredDefId(retryData);
        diagnostics.retryWithNewTag.extractedCredDefId = retryCredDefId;

        if (retryCredDefId) {
          $("#creddef_id").value = retryCredDefId;
          $("#tag").value = retryTag;
          const retryFetch = await fetchCredDefWithRetry(genesisPath, retryCredDefId, 5, 900);
          diagnostics.retryWithNewTag.postFetch = retryFetch;

          if (retryFetch.ok) {
            setOut(diagnostics);
            $("#result_out").value = JSON.stringify(diagnostics, null, 2);
            Api.setStatus("CredDef publicada no ledger e confirmada com nova tag.");
            return;
          }
        }
      }

      diagnostics.hints = [
        "Sem confirmacao no primeiro publish e no retry com nova tag.",
        "Verifique permissao de escrita do DID emissor para CRED_DEF no ledger.",
        "Valide a resposta de submit no backend nativo (op/reason do ledger)."
      ];
      $("#result_out").value = JSON.stringify(diagnostics, null, 2);
      setOut(diagnostics);
      Api.setStatus("Nao foi possivel confirmar a CredDef no ledger (ver diagnostico).");
      return;
    }

    Api.setStatus("CredDef publicada no ledger e confirmada via fetch.");
  }

  async function fetchFromLedger() {
    const genesisPath = toStringSafe($("#genesis_path").value).trim();
    const credDefId = toStringSafe($("#creddef_id").value).trim();

    if (!genesisPath) { Api.setStatus("Informe Genesis path."); return; }
    if (!credDefId) { Api.setStatus("Informe CredDef ID."); return; }

    Api.setStatus("Conectando ao ledger com o genesis informado...");
    const conn = await Api.ledger.connect(genesisPath);
    if (!conn?.ok) {
      Api.setStatus(`Erro connect ledger: ${conn?.error?.message || "erro desconhecido"}`);
      $("#result_out").value = JSON.stringify(
        { where: "creddef.fetchFromLedger", stage: "connect_failed", connect: conn },
        null,
        2
      );
      return;
    }

    Api.setStatus("Buscando CredDef no ledger...");
    const r = await Api.creddef.fetchFromLedger(genesisPath, credDefId);
    setOut({ where: "creddef.fetchFromLedger", input: { genesisPath, credDefId }, resp: r });

    if (!r.ok) {
      Api.setStatus(`Erro fetch creddef: ${r?.error?.message || "erro desconhecido"}`);
      $("#result_out").value = JSON.stringify(r, null, 2);
      return;
    }

    const data = parseMaybeJson(r.data);
    $("#result_out").value = JSON.stringify(data, null, 2);
    Api.setStatus("CredDef carregada do ledger.");
  }

  $("#btn_refresh_opts").addEventListener("click", refreshOptions);
  $("#btn_save_local").addEventListener("click", saveLocal);
  $("#btn_publish_local").addEventListener("click", publishFromLocal);
  $("#btn_publish_direct").addEventListener("click", publishLedger);
  $("#btn_fetch_ledger").addEventListener("click", fetchFromLedger);
  $("#did_filter").addEventListener("input", applyDidFilter);
  $("#did_filter").addEventListener("keyup", applyDidFilter);
  $("#did_limit").addEventListener("input", applyDidFilter);
  $("#did_limit").addEventListener("change", applyDidFilter);
  $("#btn_clear_did_filter").addEventListener("click", () => {
    $("#did_filter").value = "";
    applyDidFilter();
  });
  $("#schema_filter").addEventListener("input", applySchemaFilter);
  $("#schema_filter").addEventListener("keyup", applySchemaFilter);
  $("#schema_limit").addEventListener("input", applySchemaFilter);
  $("#schema_limit").addEventListener("change", applySchemaFilter);
  $("#btn_clear_schema_filter").addEventListener("click", () => {
    $("#schema_filter").value = "";
    applySchemaFilter();
  });

  $("#sel_did").addEventListener("change", () => {
    const did = toStringSafe($("#sel_did").value).trim();
    if (did) $("#issuer_did").value = did;
  });

  $("#sel_schema").addEventListener("change", () => {
    const schemaId = toStringSafe($("#sel_schema").value).trim();
    if (schemaId) $("#schema_id").value = schemaId;
  });

  refreshOptions().catch(() => { });
  return {};
})();
