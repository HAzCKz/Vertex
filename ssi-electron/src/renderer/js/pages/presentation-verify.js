// src/renderer/js/pages/presentation-verify.js
/* eslint-disable no-console */

const PresentationVerifyPage = (() => {
  const root = document.getElementById("page-presentation-verify");
  if (!root) return {};
  const DEFAULT_DID_LIMIT = 150;
  const MAX_DID_LIMIT = 1000;

  let ownDidOptions = [];
  let visibleOwnDidOptions = [];
  let lastVerifiedData = null;

  root.innerHTML = `
    <div class="card">
      <h2>Verificar Apresentações</h2>
      <p class="small">
        Importa o envelope gerado em <code>Criar Apresentações</code>, decripta,
        verifica a prova e exibe atributos revelados e provas ZKP.
      </p>

      <div class="row">
        <button class="secondary" id="btn_pres_verify_refresh_dids">Atualizar DIDs own</button>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>1) Verificador e arquivos</h3>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Genesis path</label>
          <input id="pres_verify_genesis_path" placeholder="/caminho/para/genesis.txn" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:340px">
          <label>DID verificador (lista own)</label>
          <select id="sel_pres_verify_did">
            <option value="">-- selecione um DID --</option>
          </select>
        </div>

        <div class="input" style="min-width:420px">
          <label>DID verificador (manual)</label>
          <input id="pres_verify_did" placeholder="ex.: DID receptor da apresentação" />
        </div>
      </div>
      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de DIDs</label>
          <input id="pres_verify_did_filter" placeholder="Filtrar por DID, alias ou verkey..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="pres_verify_did_limit" type="number" min="1" max="${MAX_DID_LIMIT}" value="${DEFAULT_DID_LIMIT}" />
        </div>
        <button class="secondary" id="btn_pres_verify_clear_did_filter">Limpar filtro</button>
      </div>
      <p class="small" id="pres_verify_did_stats">DIDs verificador: 0</p>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Arquivo da apresentação (.env.json)</label>
          <input id="pres_verify_file_path" placeholder="vazio = escolher no diálogo" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Arquivo da Presentation Request (opcional, fallback)</label>
          <input id="pres_verify_request_file_path" placeholder="use apenas se envelope antigo sem request embutido" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Presentation Request JSON (opcional, fallback)</label>
          <textarea id="pres_verify_request_json" rows="4" placeholder='{"nonce":"...","requested_attributes":{},"requested_predicates":{}}'></textarea>
        </div>
      </div>

      <div class="row">
        <button class="primary" id="btn_pres_verify">Importar e Verificar</button>
        <button class="secondary" id="btn_pres_reverify" disabled>Verificar</button>
        <button class="secondary" id="btn_pres_save" disabled>Salvar Apresentação</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:420px">
          <label>ID local da apresentação (opcional)</label>
          <input id="pres_save_id_local" placeholder="vazio = auto" />
        </div>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>2) Resultado da verificação</h3>

      <div class="row">
        <div class="input" style="min-width:220px">
          <label>Verificada</label>
          <input id="pres_verify_ok" readonly />
        </div>

        <div class="input" style="min-width:260px">
          <label>Kind</label>
          <input id="pres_verify_kind" readonly />
        </div>

        <div class="input" style="min-width:280px">
          <label>Thread ID</label>
          <input id="pres_verify_thread" readonly />
        </div>
      </div>

      <div class="tableWrap">
        <table class="table" id="tbl_pres_verify_revealed">
          <thead>
            <tr>
              <th>Referent</th>
              <th>Atributo</th>
              <th>Valor revelado</th>
              <th>Sub-proof</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <div class="tableWrap">
        <table class="table" id="tbl_pres_verify_predicates">
          <thead>
            <tr>
              <th>Referent</th>
              <th>Atributo</th>
              <th>Regra ZKP</th>
              <th>Provada</th>
              <th>Sub-proof</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Resultado completo</label>
          <textarea id="pres_verify_result" rows="10" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="pres_verify_out">{}</pre>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#pres_verify_out");

  function setOut(obj) {
    out.textContent = JSON.stringify(obj, null, 2);
  }

  function toStringSafe(v) {
    if (v === undefined || v === null) return "";
    return String(v);
  }

  function parseDidList(resp) {
    if (!resp?.ok) return [];
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

  function firstNonEmpty(...values) {
    for (const v of values) {
      const txt = toStringSafe(v).trim();
      if (txt) return txt;
    }
    return "";
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

  function renderOwnDidOptions(items) {
    const el = $("#sel_pres_verify_did");
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
    $("#pres_verify_did_stats").textContent =
      `DIDs verificador: total ${total} | filtrados ${filtered} | exibidos ${shown} (máx ${limit})`;
  }

  function applyVerifierDidFilter() {
    const filterText = normalizeText($("#pres_verify_did_filter").value).trim();
    const limit = parseDidLimit($("#pres_verify_did_limit").value);
    $("#pres_verify_did_limit").value = String(limit);

    const filtered = filterText
      ? ownDidOptions.filter((d) => didSearchBlob(d).includes(filterText))
      : ownDidOptions;

    visibleOwnDidOptions = filtered.slice(0, limit);
    renderOwnDidOptions(visibleOwnDidOptions);
    updateDidStats(ownDidOptions.length, filtered.length, visibleOwnDidOptions.length, limit);
  }

  function renderRevealed(items) {
    const tbody = $("#tbl_pres_verify_revealed tbody");
    tbody.innerHTML = "";
    const list = Array.isArray(items) ? items : [];

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
    const tbody = $("#tbl_pres_verify_predicates tbody");
    tbody.innerHTML = "";
    const list = Array.isArray(items) ? items : [];

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

  function clearResultTables() {
    renderRevealed([]);
    renderPredicates([]);
    $("#pres_verify_ok").value = "";
    $("#pres_verify_kind").value = "";
    $("#pres_verify_thread").value = "";
    $("#btn_pres_reverify").disabled = true;
    $("#btn_pres_save").disabled = true;
    lastVerifiedData = null;
  }

  async function refreshDidOptions() {
    Api.setStatus("Carregando DIDs own do verificador...");
    const resp = await Api.did.list("own");
    setOut({ where: "presentationVerify.refreshDidOptions", resp });

    if (!resp?.ok) {
      Api.setStatus(`Erro listando DIDs own: ${resp?.error?.message || "erro desconhecido"}`);
      return;
    }

    ownDidOptions = parseDidList(resp);
    applyVerifierDidFilter();
    Api.setStatus(`DIDs own carregados: ${ownDidOptions.length} (${visibleOwnDidOptions.length} exibidos).`);
  }

  async function verifyPresentationEnvelope() {
    const genesisPath = toStringSafe($("#pres_verify_genesis_path").value).trim();
    const verifierDid = toStringSafe($("#pres_verify_did").value).trim() || null;
    const presentationFilePath = toStringSafe($("#pres_verify_file_path").value).trim() || null;
    const presentationRequestFilePath = toStringSafe($("#pres_verify_request_file_path").value).trim() || null;
    const presentationRequestJson = toStringSafe($("#pres_verify_request_json").value).trim() || null;

    if (!genesisPath) {
      Api.setStatus("Informe o Genesis path.");
      return;
    }

    const input = {
      genesisPath,
      verifierDid,
      presentationFilePath,
      presentationRequestFilePath,
      presentationRequestJson,
    };

    Api.setStatus("Importando e verificando apresentação...");
    const resp = await Api.presentation.verifyImportEnvelope(input);
    setOut({ where: "presentationVerify.verify", input, resp });
    $("#pres_verify_result").value = JSON.stringify(resp, null, 2);

    if (!resp?.ok) {
      clearResultTables();
      Api.setStatus(`Erro verificando apresentação: ${resp?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (resp.data?.canceled) {
      clearResultTables();
      Api.setStatus("Importação cancelada.");
      return;
    }

    const d = resp.data || {};
    $("#pres_verify_file_path").value = firstNonEmpty(d?.presentationFilePath, $("#pres_verify_file_path").value);
    $("#pres_verify_did").value = firstNonEmpty(d?.verifierDid, $("#pres_verify_did").value);
    $("#pres_verify_ok").value = d?.verified ? "Sim" : "Não";
    $("#pres_verify_kind").value = firstNonEmpty(d?.kind);
    $("#pres_verify_thread").value = firstNonEmpty(d?.threadId);
    if (!toStringSafe($("#pres_save_id_local").value).trim()) {
      const threadSafe = firstNonEmpty(d?.threadId).replace(/[^a-zA-Z0-9._-]/g, "_");
      if (threadSafe) {
        $("#pres_save_id_local").value = `pres-received-${threadSafe}`;
      }
    }

    renderRevealed(d?.revealedAttributes || []);
    renderPredicates(d?.predicateProofs || []);
    lastVerifiedData = d;
    $("#btn_pres_reverify").disabled = false;
    $("#btn_pres_save").disabled = false;

    Api.setStatus(d?.verified
      ? "Apresentação verificada com sucesso."
      : "Apresentação processada, mas a verificação criptográfica falhou.");
  }

  async function savePresentationLocal() {
    if (!lastVerifiedData || typeof lastVerifiedData !== "object") {
      Api.setStatus("Importe e verifique uma apresentação antes de salvar.");
      return;
    }

    const presentationIdLocal = toStringSafe($("#pres_save_id_local").value).trim() || null;
    const metaObj = {
      role: "verifier",
      verified: !!lastVerifiedData.verified,
      verified_at: Date.now(),
      thread_id: firstNonEmpty(lastVerifiedData.threadId) || null,
      kind: firstNonEmpty(lastVerifiedData.kind) || null,
      payload_format: firstNonEmpty(lastVerifiedData.payloadFormat) || null,
      source_file: firstNonEmpty(lastVerifiedData.presentationFilePath) || null,
    };

    const input = {
      presentationIdLocal,
      presentationObj: lastVerifiedData.presentation,
      presentationRequestObj: lastVerifiedData.presentationRequest,
      metaObj,
      threadId: firstNonEmpty(lastVerifiedData.threadId) || null,
    };

    Api.setStatus("Salvando apresentação na wallet corrente...");
    const resp = await Api.presentation.storeLocal(input);
    setOut({ where: "presentationVerify.saveLocal", input, resp, lastVerifiedData });
    $("#pres_verify_result").value = JSON.stringify(resp, null, 2);

    if (!resp?.ok) {
      Api.setStatus(`Erro salvando apresentação: ${resp?.error?.message || "erro desconhecido"}`);
      return;
    }

    const savedId = firstNonEmpty(resp?.data?.presentationIdLocal);
    if (savedId) {
      $("#pres_save_id_local").value = savedId;
    }
    Api.setStatus(`Apresentação salva na wallet: ${savedId || "(sem id)"}`);
  }

  async function reverifyLoadedPresentation() {
    const presentationFilePath = toStringSafe($("#pres_verify_file_path").value).trim();
    if (!presentationFilePath) {
      Api.setStatus("Carregue uma apresentação antes de verificar novamente.");
      return;
    }
    await verifyPresentationEnvelope();
  }

  $("#btn_pres_verify_refresh_dids").addEventListener("click", refreshDidOptions);
  $("#btn_pres_verify").addEventListener("click", verifyPresentationEnvelope);
  $("#btn_pres_reverify").addEventListener("click", reverifyLoadedPresentation);
  $("#btn_pres_save").addEventListener("click", savePresentationLocal);
  $("#pres_verify_did_filter").addEventListener("input", applyVerifierDidFilter);
  $("#pres_verify_did_filter").addEventListener("keyup", applyVerifierDidFilter);
  $("#pres_verify_did_limit").addEventListener("input", applyVerifierDidFilter);
  $("#pres_verify_did_limit").addEventListener("change", applyVerifierDidFilter);
  $("#btn_pres_verify_clear_did_filter").addEventListener("click", () => {
    $("#pres_verify_did_filter").value = "";
    applyVerifierDidFilter();
  });

  $("#sel_pres_verify_did").addEventListener("change", () => {
    const did = toStringSafe($("#sel_pres_verify_did").value).trim();
    if (did) $("#pres_verify_did").value = did;
  });

  clearResultTables();
  refreshDidOptions().catch(() => {});

  return {};
})();
