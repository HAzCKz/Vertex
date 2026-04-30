// src/renderer/js/pages/presentation-verify.js
/* eslint-disable no-console */

const PresentationVerifyPage = (() => {
  const root = document.getElementById("page-presentation-verify");
  if (!root) return {};
  const DEFAULT_DID_LIMIT = 150;
  const MAX_DID_LIMIT = 1000;
  const EXTRA_REVOCATION_TAIL_WINDOWS = 11;

  let ownDidOptions = [];
  let visibleOwnDidOptions = [];
  let lastVerifiedData = null;
  let revealedSort = { key: "", dir: "asc" };
  let predicateSort = { key: "", dir: "asc" };
  let revealedItemsCache = [];
  let predicateItemsCache = [];
  const CONTROL_ATTRIBUTE_NAMES = new Set([
    "seed",
    "start_time",
    "unit_of_time",
    "time_window",
    "root_merkle_l",
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

        <div class="input" style="min-width:220px">
          <label>Criptográfica</label>
          <input id="pres_verify_crypto" readonly />
        </div>

        <div class="input" style="min-width:220px">
          <label>Provas revogação</label>
          <input id="pres_verify_revocation_proofs" readonly />
        </div>

        <div class="input" style="min-width:220px">
          <label>Revogada</label>
          <input id="pres_verify_revoked" readonly />
        </div>

        <div class="input" style="min-width:220px">
          <label>Mais janelas?</label>
          <input id="pres_verify_more_windows" readonly />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:260px">
          <label>Formato do payload</label>
          <input id="pres_verify_payload_format" readonly />
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
        <table class="table" id="tbl_pres_verify_predicates">
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

      <div class="tableWrap">
        <table class="table" id="tbl_pres_verify_revocation">
          <thead>
            <tr>
              <th>Sub-proof</th>
              <th>CredDef ID</th>
              <th>Revogável</th>
              <th>Aceita</th>
              <th>Prova rev.</th>
              <th>Revogada</th>
              <th>Data de emissão</th>
              <th>Janela de revogação</th>
              <th>Data de revogação</th>
              <th>Maior janela consultada</th>
              <th>Última janela entregue no pacote</th>
              <th>Data da maior janela consultada</th>
              <th>Data da primeira janela que sugere revogação</th>
              <th>Mais janelas?</th>
              <th>Próxima janela</th>
              <th style="min-width:360px; width:360px;">Detalhes</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <div id="pres_verify_revoked_warning_box" style="display:none; margin:10px 0 16px; padding:12px; border:2px solid #dc2626; border-radius:10px; background:#fef2f2;">
        <strong style="color:#991b1b;">Atenção: há credenciais revogadas nesta apresentação</strong>
        <div id="pres_verify_revoked_warning_summary" class="small" style="white-space:pre-wrap; margin-top:8px;"></div>
      </div>

      <div class="row">
        <div class="input" style="min-width:760px">
          <label>Atributos da credencial selecionada</label>
          <textarea id="pres_verify_selected_credential_attrs" rows="8" readonly placeholder="Clique em uma linha da tabela de credenciais para ver os atributos revelados da credencial, sem os atributos de controle."></textarea>
        </div>
      </div>

      <div id="pres_verify_false_positive_box" style="display:none; margin:10px 0 16px; padding:12px; border:1px solid #f59e0b; border-radius:10px; background:#fffbeb;">
        <strong>Probabilidade residual de falso positivo</strong>
        <div id="pres_verify_false_positive_summary" class="small" style="white-space:pre-wrap; margin-top:6px;"></div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Resultado completo</label>
          <textarea id="pres_verify_result" rows="10" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="pres_verify_out" style="max-height:320px; overflow:auto; white-space:pre-wrap; word-break:break-word;">{}</pre>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#pres_verify_out");

  function setOut(obj) {
    out.textContent = JSON.stringify(obj, null, 2);
  }

  function summarizeLargeVerifyPayload(resp) {
    if (!resp || typeof resp !== "object") return resp;
    const data = resp?.data;
    if (!data || typeof data !== "object") return resp;

    return {
      ...resp,
      data: {
        canceled: !!data?.canceled,
        presentationFilePath: firstNonEmpty(data?.presentationFilePath) || null,
        verifierDid: firstNonEmpty(data?.verifierDid) || null,
        verifierDidSource: firstNonEmpty(data?.verifierDidSource) || null,
        requestSource: firstNonEmpty(data?.requestSource) || null,
        payloadFormat: firstNonEmpty(data?.payloadFormat) || null,
        kind: firstNonEmpty(data?.kind) || null,
        threadId: firstNonEmpty(data?.threadId) || null,
        verified: !!data?.verified,
        cryptographicValid: !!data?.cryptographicValid,
        proofsVerified: data?.proofsVerified ?? null,
        revoked: !!data?.revoked,
        requiresMoreWindows: !!data?.requiresMoreWindows,
        counts: data?.counts || null,
        schemaIds: Array.isArray(data?.schemaIds) ? data.schemaIds : [],
        credDefIds: Array.isArray(data?.credDefIds) ? data.credDefIds : [],
        revealedAttributesSample: Array.isArray(data?.revealedAttributes)
          ? data.revealedAttributes.slice(0, 5)
          : [],
        predicateProofsSample: Array.isArray(data?.predicateProofs)
          ? data.predicateProofs.slice(0, 5)
          : [],
        perCredentialStatus: Array.isArray(data?.perCredentialStatus)
          ? data.perCredentialStatus
          : [],
        revocationManifestRefreshes: Array.isArray(data?.revocationManifestRefreshes)
          ? data.revocationManifestRefreshes
          : [],
        envelopeSummary: data?.envelopeSummary || null,
        presentationSummary: {
          identifiers: Array.isArray(data?.presentation?.identifiers)
            ? data.presentation.identifiers.length
            : 0,
          proofHasProofs: !!data?.presentation?.requested_proof,
        },
        presentationRequestSummary: {
          requestedAttributes: Object.keys(data?.presentationRequest?.requested_attributes || {}).length,
          requestedPredicates: Object.keys(data?.presentationRequest?.requested_predicates || {}).length,
        },
      },
    };
  }

  function toStringSafe(v) {
    if (v === undefined || v === null) return "";
    return String(v);
  }

  function parseMaybeJson(data) {
    if (typeof data !== "string") return data;
    try {
      return JSON.parse(data);
    } catch (_) {
      return data;
    }
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

  function isControlAttributeName(name) {
    return CONTROL_ATTRIBUTE_NAMES.has(toStringSafe(name).trim());
  }

  function applyBusinessAttributeRowStyle(tr, item) {
    if (!tr || isControlAttributeName(item?.name)) return;
    tr.style.background = "#effcf6";
  }

  function getBusinessAttributesForSubProof(subProofIndex) {
    const idx = Number(subProofIndex);
    if (!Number.isFinite(idx)) return [];
    return revealedItemsCache
      .filter((it) => Number(it?.subProofIndex) === idx)
      .filter((it) => !isControlAttributeName(it?.name))
      .map((it) => ({
        referent: firstNonEmpty(it?.referent),
        name: firstNonEmpty(it?.name),
        raw: firstNonEmpty(it?.raw),
      }));
  }

  function renderSelectedCredentialAttributes(item) {
    const out = $("#pres_verify_selected_credential_attrs");
    if (!out) return;
    if (!item || item?.revocable === false && item?.sub_proof_index === undefined) {
      out.value = "";
      return;
    }

    const attrs = getBusinessAttributesForSubProof(item?.sub_proof_index);
    if (!attrs.length) {
      out.value = [
        `Sub-proof: ${firstNonEmpty(item?.sub_proof_index, "-")}`,
        `CredDef ID: ${firstNonEmpty(item?.cred_def_id, "-")}`,
        "",
        "Nenhum atributo da credencial foi revelado nesta apresentação para esta credencial.",
      ].join("\n");
      return;
    }

    out.value = [
      `Sub-proof: ${firstNonEmpty(item?.sub_proof_index, "-")}`,
      `CredDef ID: ${firstNonEmpty(item?.cred_def_id, "-")}`,
      "",
      JSON.stringify(attrs, null, 2),
    ].join("\n");
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
    const tbody = $("#tbl_pres_verify_revealed tbody");
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
      applyBusinessAttributeRowStyle(tr, it);
      tbody.appendChild(tr);
    });
  }

  function renderPredicates(items) {
    const tbody = $("#tbl_pres_verify_predicates tbody");
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
      applyBusinessAttributeRowStyle(tr, it);
      tbody.appendChild(tr);
    });
  }

  function yesNoBlank(value) {
    if (value === true) return "Sim";
    if (value === false) return "Não";
    return "";
  }

  function formatEpochSeconds(value) {
    if (value === undefined || value === null || value === "") return "";
    const n = Number(value);
    if (!Number.isFinite(n) || n <= 0) return "";
    return new Date(n * 1000).toLocaleString("pt-BR");
  }

  const BLOOM_FALSE_POSITIVE_PROBABILITY_95 = 7.380567872e-11;

  function formatScientificPt(value) {
    if (!Number.isFinite(value) || value <= 0) return "";
    const [mantissa, exponent] = value.toExponential(3).split("e");
    return `${mantissa.replace(".", ",")} × 10^${Number(exponent)}`;
  }

  function formatOneIn(value) {
    if (!Number.isFinite(value) || value <= 0) return "";
    const inv = 1 / value;
    if (!Number.isFinite(inv)) return "praticamente infinito";
    return formatScientificPt(inv);
  }

  function getLastAnalyzedTraceItem(status) {
    const trace = Array.isArray(status?.trace) ? status.trace : [];
    return trace.reduce((best, item) => {
      const idx = Number(item?.window_index);
      if (!Number.isFinite(idx)) return best;
      if (!best) return item;
      const bestIdx = Number(best?.window_index);
      return idx >= bestIdx ? item : best;
    }, null);
  }

  function getFirstRevocationHintTraceItem(status) {
    const trace = Array.isArray(status?.trace) ? status.trace : [];
    return trace.reduce((best, item) => {
      if (item?.maybe_present !== true) return best;
      const idx = Number(item?.window_index);
      if (!Number.isFinite(idx)) return best;
      if (!best) return item;
      const bestIdx = Number(best?.window_index);
      return idx < bestIdx ? item : best;
    }, null);
  }

  function getRevocationProofSequence(raw) {
    const sequence = raw?.proof_sequence || raw?.proofSequence || raw;
    return sequence && typeof sequence === "object" && !Array.isArray(sequence)
      ? sequence
      : null;
  }

  function getOrderedSequenceProofs(raw) {
    const sequence = getRevocationProofSequence(raw);
    if (!sequence) return [];

    const primary = sequence?.primary_proof && typeof sequence.primary_proof === "object"
      ? [sequence.primary_proof]
      : [];
    const confirmations = Array.isArray(sequence?.confirmation_proofs)
      ? sequence.confirmation_proofs.filter((proof) => proof && typeof proof === "object")
      : [];

    return primary.concat(confirmations).sort((a, b) => {
      const aIndex = Number(a?.window_index);
      const bIndex = Number(b?.window_index);
      if (!Number.isFinite(aIndex) && !Number.isFinite(bIndex)) return 0;
      if (!Number.isFinite(aIndex)) return 1;
      if (!Number.isFinite(bIndex)) return -1;
      return aIndex - bIndex;
    });
  }

  function getLastDeliveredWindowFromSequence(sequenceItem) {
    const proofs = getOrderedSequenceProofs(sequenceItem);
    if (!proofs.length) return null;

    return proofs.reduce((best, proof) => {
      const idx = Number(proof?.window_index);
      if (!Number.isFinite(idx)) return best;
      if (!best) return proof;
      const bestIdx = Number(best?.window_index);
      return idx >= bestIdx ? proof : best;
    }, null);
  }

  function buildTailVerificationVariants(sequenceItem, maxWindows = EXTRA_REVOCATION_TAIL_WINDOWS) {
    const proofs = getOrderedSequenceProofs(sequenceItem);
    if (!proofs.length) {
      return {
        allProofs: [],
        tailProofs: [],
        variants: [],
      };
    }

    const tailProofs = proofs.slice(-Math.min(maxWindows, proofs.length));
    const variants = tailProofs.map((primaryProof, index) => ({
      primary_proof: primaryProof,
      confirmation_proofs: [],
      tail_window_index: Number.isFinite(Number(primaryProof?.window_index))
        ? Math.trunc(Number(primaryProof.window_index))
        : index,
    }));

    return {
      allProofs: proofs,
      tailProofs,
      variants,
    };
  }

  function buildTailVerificationPolicyJson(policy) {
    if (!policy) return null;
    if (typeof policy === "string") {
      const trimmed = policy.trim();
      return trimmed || null;
    }
    try {
      return JSON.stringify(policy);
    } catch (_) {
      return null;
    }
  }

  async function verifyTailSequenceVariant(sequence, genesisPath, policyJson) {
    try {
      const resp = await Api.revocationVerify.verifyProofSequence({
        proofSequenceJson: JSON.stringify(sequence),
        genesisPath: genesisPath || null,
        policyJson,
        storeEvent: false,
      });
      const data = parseMaybeJson(resp?.data);
      return {
        ok: !!resp?.ok,
        error: resp?.ok ? null : (resp?.error?.message || "Erro desconhecido na confirmação extra."),
        status: data?.status || null,
      };
    } catch (e) {
      return {
        ok: false,
        error: e?.message || "Erro desconhecido na confirmação extra.",
        status: null,
      };
    }
  }

  function appendDetailText(baseText, addition) {
    const base = toStringSafe(baseText).trim();
    const extra = toStringSafe(addition).trim();
    if (!base) return extra;
    if (!extra) return base;
    return `${base} ${extra}`;
  }

  function createTailConfirmationSummary(result) {
    const checkedWindows = Number(result?.checkedWindows ?? 0);
    const startWindow = result?.startWindowIndex;
    const endWindow = result?.endWindowIndex;
    const rangeText =
      startWindow === undefined || startWindow === null || endWindow === undefined || endWindow === null
        ? ""
        : ` (${startWindow}-${endWindow})`;
    if (checkedWindows > 0 && checkedWindows < EXTRA_REVOCATION_TAIL_WINDOWS) {
      return `Confirmação extra: todas as ${checkedWindows} janela(s) disponíveis entregues pelo Holder${rangeText} foram verificadas individualmente.`;
    }
    return `Confirmação extra: as últimas ${checkedWindows} janela(s) entregues pelo Holder${rangeText} foram verificadas individualmente.`;
  }

  function summarizeTailVerificationResult(result) {
    const base = createTailConfirmationSummary(result);
    if (result?.outcome === "clean") {
      return `${base} Nenhuma delas indicou revogação, então a credencial permanece aceita como não revogada dentro do intervalo autorizado pelo Holder.`;
    }
    if (result?.outcome === "needs_more_windows") {
      const suspiciousWindow = result?.suspiciousWindowIndex;
      const nextWindow = result?.nextRequiredWindowIndex;
      if (suspiciousWindow === undefined || suspiciousWindow === null || suspiciousWindow === "") {
        return nextWindow === undefined || nextWindow === null || nextWindow === ""
          ? `${base} Foi encontrado um indício de revogação em uma dessas janelas finais, então o Holder precisa entregar janelas extras para confirmar se era falso positivo ou revogação real.`
          : `${base} Foi encontrado um indício de revogação em uma dessas janelas finais, então o Holder precisa entregar janelas extras a partir da janela ${nextWindow} para confirmar se era falso positivo ou revogação real.`;
      }
      return nextWindow === undefined || nextWindow === null || nextWindow === ""
        ? `${base} A janela ${suspiciousWindow} apresentou indício de revogação, então o Holder precisa entregar janelas extras para confirmar se era falso positivo ou revogação real.`
        : `${base} A janela ${suspiciousWindow} apresentou indício de revogação, então o Holder precisa entregar janelas extras a partir da janela ${nextWindow} para confirmar se era falso positivo ou revogação real.`;
    }
    return `${base} A proteção extra ficou inconclusiva e a apresentação não deve ser aceita sem revisão adicional.`;
  }

  function mergeTailVerificationIntoItem(item, result) {
    const baseItem = item && typeof item === "object" ? item : {};
    const currentStatus = baseItem?.revocation_status && typeof baseItem.revocation_status === "object"
      ? baseItem.revocation_status
      : {};
    const verifiedStatus = result?.status && typeof result.status === "object"
      ? result.status
      : {};
    const tailConfirmation = {
      outcome: result?.outcome || "inconclusive",
      checked_windows: result?.checkedWindows ?? 0,
      start_window_index: result?.startWindowIndex ?? null,
      end_window_index: result?.endWindowIndex ?? null,
      checked_at_ms: Date.now(),
      verified_runs: result?.verifiedRuns ?? 0,
      fallback_used: !!result?.fallbackUsed,
      next_required_window_index: result?.nextRequiredWindowIndex ?? null,
      suspicious_window_index: result?.suspiciousWindowIndex ?? null,
      decisive_window_index: result?.decisiveWindowIndex ?? null,
      error: result?.error || null,
    };
    const detailText = summarizeTailVerificationResult(result);

    if (result?.outcome === "clean") {
      return {
        ...baseItem,
        accepted: true,
        revoked: false,
        requires_more_windows: false,
        next_required_window_index: null,
        details: appendDetailText(baseItem?.details, detailText),
        revocation_status: {
          ...currentStatus,
          accepted: true,
          revoked: false,
          requires_more_windows: false,
          next_required_window_index: null,
          tail_confirmation: tailConfirmation,
        },
      };
    }

    return {
      ...baseItem,
      accepted: false,
      requires_more_windows: true,
      next_required_window_index: result?.nextRequiredWindowIndex ?? baseItem?.next_required_window_index ?? null,
      details: detailText,
      revocation_status: {
        ...currentStatus,
        ...verifiedStatus,
        accepted: false,
        requires_more_windows: true,
        next_required_window_index: result?.nextRequiredWindowIndex ?? currentStatus?.next_required_window_index ?? null,
        tail_confirmation: tailConfirmation,
      },
    };
  }

  function buildSequenceLookupKey(credentialIdLocal, credDefId, subProofIndex) {
    return [
      toStringSafe(credentialIdLocal).trim().toLowerCase(),
      toStringSafe(credDefId).trim().toLowerCase(),
      toStringSafe(subProofIndex).trim().toLowerCase(),
    ].join("|");
  }

  function findMatchingProofSequenceIndex(item, sequenceItems, usedIndices, revocableOrdinal) {
    const exactKey = buildSequenceLookupKey(item?.credential_id_local, item?.cred_def_id, item?.sub_proof_index);
    if (exactKey !== "||") {
      for (let index = 0; index < sequenceItems.length; index += 1) {
        if (usedIndices.has(index)) continue;
        const seq = sequenceItems[index];
        const seqKey = buildSequenceLookupKey(
          seq?.credential_id_local,
          seq?.cred_def_id || seq?.proof_sequence?.primary_proof?.cred_def_id,
          seq?.sub_proof_index
        );
        if (seqKey === exactKey) return index;
      }
    }

    const credentialId = toStringSafe(item?.credential_id_local).trim().toLowerCase();
    if (credentialId) {
      for (let index = 0; index < sequenceItems.length; index += 1) {
        if (usedIndices.has(index)) continue;
        const seqCredentialId = toStringSafe(sequenceItems[index]?.credential_id_local).trim().toLowerCase();
        if (seqCredentialId && seqCredentialId === credentialId) return index;
      }
    }

    const credDefId = toStringSafe(item?.cred_def_id).trim().toLowerCase();
    const candidates = [];
    if (credDefId) {
      for (let index = 0; index < sequenceItems.length; index += 1) {
        if (usedIndices.has(index)) continue;
        const seqCredDefId = firstNonEmpty(
          sequenceItems[index]?.cred_def_id,
          sequenceItems[index]?.proof_sequence?.primary_proof?.cred_def_id
        ).trim().toLowerCase();
        if (seqCredDefId && seqCredDefId === credDefId) {
          candidates.push(index);
        }
      }
      if (candidates.length === 1) return candidates[0];
    }

    if (Number.isInteger(revocableOrdinal) && revocableOrdinal >= 0 && revocableOrdinal < sequenceItems.length) {
      if (!usedIndices.has(revocableOrdinal)) return revocableOrdinal;
    }

    for (let index = 0; index < sequenceItems.length; index += 1) {
      if (!usedIndices.has(index)) return index;
    }

    return -1;
  }

  function recomputePresentationRevocationOutcome(data) {
    const items = Array.isArray(data?.perCredentialStatus) ? data.perCredentialStatus : [];
    const revoked = items.some((item) => item?.revocable && item?.revoked);
    const requiresMoreWindows = items.some((item) => item?.revocable && item?.requires_more_windows);

    data.revoked = revoked;
    data.requiresMoreWindows = requiresMoreWindows;
    data.verified = !!data?.verified && !revoked && !requiresMoreWindows;
    return data;
  }

  async function applyExtraTailRevocationVerification(data, genesisPath) {
    if (!data || typeof data !== "object") return data;
    const items = Array.isArray(data?.perCredentialStatus) ? data.perCredentialStatus.slice() : [];
    const sequenceItems = Array.isArray(data?.revocationProofSequences) ? data.revocationProofSequences : [];
    if (!items.length || !sequenceItems.length) return data;

    const usedSequenceIndices = new Set();
    const policyJson = buildTailVerificationPolicyJson(data?.policy);
    let revocableOrdinal = -1;
    let appliedChecks = 0;

    for (let index = 0; index < items.length; index += 1) {
      const item = items[index];
      if (!item?.revocable) continue;
      revocableOrdinal += 1;

      if (item?.revoked || item?.requires_more_windows) continue;

      const sequenceIndex = findMatchingProofSequenceIndex(item, sequenceItems, usedSequenceIndices, revocableOrdinal);
      if (sequenceIndex < 0) continue;
      usedSequenceIndices.add(sequenceIndex);

      const prepared = buildTailVerificationVariants(sequenceItems[sequenceIndex], EXTRA_REVOCATION_TAIL_WINDOWS);
      const tailProofs = Array.isArray(prepared?.tailProofs) ? prepared.tailProofs : [];
      const variants = Array.isArray(prepared?.variants) ? prepared.variants : [];
      if (!tailProofs.length || !variants.length) continue;

      const firstTailWindow = Number(tailProofs[0]?.window_index);
      const lastTailWindow = Number(tailProofs[tailProofs.length - 1]?.window_index);
      const runResults = [];
      let invalidResult = null;
      let suspiciousResult = null;
      let suspiciousWindowIndex = null;

      Api.setStatus(
        `Executando proteção extra de revogação na credencial ${index + 1}/${items.length}: verificando as últimas ${tailProofs.length} janela(s) entregues pelo Holder...`
      );

      for (const variant of variants) {
        const run = await verifyTailSequenceVariant(variant, genesisPath, policyJson);
        runResults.push(run);
        const status = run?.status || null;
        const checkedWindowIndex = Number.isFinite(Number(variant?.tail_window_index))
          ? Math.trunc(Number(variant.tail_window_index))
          : (status?.primary_window_index ?? null);

        if (!run?.ok || !status?.verified) {
          if (!invalidResult) invalidResult = run;
          continue;
        }
        if (
          run?.ok
          && status?.verified
          && (
            status?.revoked
            || status?.requires_more_windows
            || Number(status?.consecutive_hits ?? 0) > 0
          )
        ) {
          suspiciousResult = run;
          suspiciousWindowIndex = checkedWindowIndex;
          break;
        }
      }

      appliedChecks += 1;
      const commonResult = {
        checkedWindows: tailProofs.length,
        startWindowIndex: Number.isFinite(firstTailWindow) ? Math.trunc(firstTailWindow) : null,
        endWindowIndex: Number.isFinite(lastTailWindow) ? Math.trunc(lastTailWindow) : null,
        verifiedRuns: runResults.filter((run) => !!run?.ok && !!run?.status?.verified).length,
      };

      if (suspiciousResult) {
        const needStatus = suspiciousResult.status || {};
        items[index] = mergeTailVerificationIntoItem(items[index], {
          ...commonResult,
          outcome: "needs_more_windows",
          status: needStatus,
          suspiciousWindowIndex,
          nextRequiredWindowIndex: (Number.isFinite(lastTailWindow) ? Math.trunc(lastTailWindow) + 1 : null),
        });
        continue;
      }

      items[index] = mergeTailVerificationIntoItem(items[index], {
        ...commonResult,
        outcome: "clean",
        fallbackUsed: !!invalidResult,
        error: invalidResult?.error || null,
      });
    }

    if (!appliedChecks) return data;

    data.perCredentialStatus = items;
    data.extraTailVerificationApplied = true;
    data.extraTailVerificationWindowCount = EXTRA_REVOCATION_TAIL_WINDOWS;
    recomputePresentationRevocationOutcome(data);
    return data;
  }

  function renderFalsePositiveSummary(items) {
    const box = $("#pres_verify_false_positive_box");
    const summary = $("#pres_verify_false_positive_summary");
    if (!box || !summary) return;

    const list = Array.isArray(items) ? items : [];
    const rows = list
      .map((it) => {
        const status = it?.revocation_status || {};
        const hits = Number(status?.consecutive_hits ?? 0);
        if (!it?.revocable || !it?.requires_more_windows || it?.revoked || !Number.isFinite(hits) || hits <= 0) {
          return null;
        }

        const probability = Math.pow(BLOOM_FALSE_POSITIVE_PROBABILITY_95, Math.trunc(hits));
        const missingWindow = firstNonEmpty(it?.next_required_window_index, status?.next_required_window_index, "-");
        const label = firstNonEmpty(
          it?.credential_id_local,
          it?.cred_def_id,
          it?.sub_proof_index !== undefined ? `sub-proof ${it.sub_proof_index}` : "credencial"
        );
        return [
          `Credencial: ${label}`,
          `Hits consecutivos observados: ${Math.trunc(hits)}.`,
          `Próxima janela necessária pelo algoritmo: ${missingWindow}.`,
          `Probabilidade estimada de esses ${Math.trunc(hits)} hit(s) serem falso positivo: ${formatScientificPt(probability)} (aprox. 1 em ${formatOneIn(probability)}).`,
        ].join("\n");
      })
      .filter(Boolean);

    if (!rows.length) {
      box.style.display = "none";
      summary.textContent = "";
      return;
    }

    summary.textContent = [
      "A regra formal ainda exige a próxima janela para confirmar a revogação, mas o PDF de falso positivo mostra que a probabilidade residual cai exponencialmente com hits consecutivos.",
      "",
      ...rows,
    ].join("\n\n");
    box.style.display = "block";
  }

  function renderRevokedCredentialsWarning(items, overallData = null) {
    const box = $("#pres_verify_revoked_warning_box");
    const summary = $("#pres_verify_revoked_warning_summary");
    if (!box || !summary) return;

    const list = Array.isArray(items) ? items : [];
    const revokedItems = list.filter((it) => it?.revocable && it?.revoked);

    if (!revokedItems.length) {
      box.style.display = "none";
      summary.textContent = "";
      return;
    }

    const details = revokedItems.map((it, index) => {
      const attrs = getBusinessAttributesForSubProof(it?.sub_proof_index);
      const issuedAt = formatEpochSeconds(firstNonEmpty(it?.issued_at, it?.revocation_status?.issued_at)) || "-";
      const revokedAt = formatEpochSeconds(
        firstNonEmpty(it?.revoked_window_start, it?.revocation_status?.revoked_window_start)
      ) || "-";
      return [
        `Credencial revogada ${index + 1}`,
        `Cred Def: ${firstNonEmpty(it?.cred_def_id, "-")}`,
        `Data de emissão: ${issuedAt}`,
        `Data da revogação: ${revokedAt}`,
        "Atributos da credencial:",
        attrs.length ? JSON.stringify(attrs, null, 2) : "Nenhum atributo de negócio revelado nesta apresentação para esta credencial.",
      ].join("\n");
    });

    const cryptographicallyValid = overallData?.cryptographicValid === true;
    const closingMessage = cryptographicallyValid
      ? "A apresentação está válida do ponto de vista criptográfico, mas existem uma ou mais credenciais revogadas que compõem a apresentação. O verificador deve analisar com cuidado se isso ainda atende ao seu caso de uso."
      : "Além de haver credenciais revogadas, a apresentação não está plenamente válida do ponto de vista criptográfico.";

    summary.textContent = [...details, "", closingMessage].join("\n\n");
    box.style.display = "block";
  }

  function applyRevocationDetailStyle(cell, item, status) {
    if (!cell) return;
    const hitsRaw = item?.consecutive_hits ?? status?.consecutive_hits ?? 0;
    const hits = Number.isFinite(Number(hitsRaw)) ? Number(hitsRaw) : 0;

    cell.style.color = "";
    cell.style.fontWeight = "";

    if (hits >= 11 && item?.revoked) {
      cell.style.color = "#b91c1c";
      cell.style.fontWeight = "700";
      return;
    }

    if (hits >= 1 && hits <= 10) {
      cell.style.color = "#c2410c";
      cell.style.fontWeight = "700";
    }
  }

  function renderRevocationStatus(items, overallData = null) {
    const tbody = $("#tbl_pres_verify_revocation tbody");
    tbody.innerHTML = "";
    const list = Array.isArray(items) ? items : [];
    const sequenceItems = Array.isArray(overallData?.revocationProofSequences)
      ? overallData.revocationProofSequences
      : [];
    const usedSequenceIndices = new Set();
    let revocableOrdinal = -1;
    tbody.dataset.items = JSON.stringify(list);

    if (!list.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="16" class="small">Nenhuma prova complementar de revogação no envelope.</td>`;
      tbody.appendChild(tr);
      renderSelectedCredentialAttributes(null);
      renderFalsePositiveSummary([]);
      renderRevokedCredentialsWarning([], overallData);
      return;
    }

    list.forEach((it, index) => {
      const status = it?.revocation_status || {};
      if (it?.revocable) revocableOrdinal += 1;
      const issuedAt = formatEpochSeconds(firstNonEmpty(it?.issued_at, status?.issued_at));
      const revokedWindowIndex = firstNonEmpty(
        it?.revoked_window_index,
        it?.revoked ? status?.primary_window_index : "",
        "-"
      );
      const revokedWindowStart = formatEpochSeconds(
        firstNonEmpty(it?.revoked_window_start, status?.revoked_window_start)
      );
      const lastAnalyzed = getLastAnalyzedTraceItem(status);
      const lastAnalyzedWindow = firstNonEmpty(lastAnalyzed?.window_index, "-");
      const lastAnalyzedDate = formatEpochSeconds(lastAnalyzed?.window_start);
      const sequenceIndex = it?.revocable
        ? findMatchingProofSequenceIndex(it, sequenceItems, usedSequenceIndices, revocableOrdinal)
        : -1;
      if (sequenceIndex >= 0) usedSequenceIndices.add(sequenceIndex);
      const lastDeliveredWindowProof = sequenceIndex >= 0
        ? getLastDeliveredWindowFromSequence(sequenceItems[sequenceIndex])
        : null;
      const lastDeliveredWindow = firstNonEmpty(lastDeliveredWindowProof?.window_index, "-");
      const firstRevocationHint = getFirstRevocationHintTraceItem(status);
      const firstRevocationHintDate = formatEpochSeconds(firstRevocationHint?.window_start);
      const tr = document.createElement("tr");
      tr.dataset.idx = String(index);
      tr.style.cursor = "pointer";
      tr.innerHTML = `
        <td>${firstNonEmpty(it?.sub_proof_index, "-")}</td>
        <td class="mono">${firstNonEmpty(it?.cred_def_id, "-")}</td>
        <td>${it?.revocable ? "Sim" : "Não"}</td>
        <td>${yesNoBlank(it?.accepted) || "-"}</td>
        <td>${yesNoBlank(it?.proof_verified) || "-"}</td>
        <td>${yesNoBlank(it?.revoked) || "-"}</td>
        <td>${issuedAt || "-"}</td>
        <td>${it?.revoked ? revokedWindowIndex : "-"}</td>
        <td>${it?.revoked ? revokedWindowStart || "-" : "-"}</td>
        <td>${it?.revocable ? lastAnalyzedWindow : "-"}</td>
        <td>${it?.revocable ? lastDeliveredWindow : "-"}</td>
        <td>${it?.revocable ? lastAnalyzedDate || "-" : "-"}</td>
        <td>${it?.revocable ? firstRevocationHintDate || "-" : "-"}</td>
        <td>${yesNoBlank(it?.requires_more_windows) || "-"}</td>
        <td>${firstNonEmpty(it?.next_required_window_index, "-")}</td>
        <td style="min-width:360px; width:360px;">${firstNonEmpty(it?.details, "-")}</td>
      `;
      applyRevocationDetailStyle(tr.lastElementChild, it, status);
      tbody.appendChild(tr);
    });

    renderSelectedCredentialAttributes(list[0]);
    renderFalsePositiveSummary(list);
    renderRevokedCredentialsWarning(list, overallData);
  }

  function clearResultTables() {
    renderRevealed([]);
    renderPredicates([]);
    renderRevocationStatus([], null);
    $("#pres_verify_selected_credential_attrs").value = "";
    $("#pres_verify_ok").value = "";
    $("#pres_verify_crypto").value = "";
    $("#pres_verify_revocation_proofs").value = "";
    $("#pres_verify_revoked").value = "";
    $("#pres_verify_more_windows").value = "";
    $("#pres_verify_payload_format").value = "";
    $("#pres_verify_kind").value = "";
    $("#pres_verify_thread").value = "";
    $("#btn_pres_reverify").disabled = true;
    $("#btn_pres_save").disabled = true;
    lastVerifiedData = null;
  }

  function releaseHeavyState() {
    clearResultTables();
    $("#pres_verify_result").value = "";
    $("#pres_verify_selected_credential_attrs").value = "";
    $("#pres_verify_out").textContent = "{}";
    $("#tbl_pres_verify_revocation tbody").dataset.items = "[]";
    revealedItemsCache = [];
    predicateItemsCache = [];
    revealedSort = { key: "", dir: "asc" };
    predicateSort = { key: "", dir: "asc" };
    updateDetailSortHeaderLabels();
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

    if (!resp?.ok) {
      clearResultTables();
      const summarizedResp = summarizeLargeVerifyPayload(resp);
      setOut({ where: "presentationVerify.verify", input, resp: summarizedResp });
      $("#pres_verify_result").value = JSON.stringify(summarizedResp, null, 2);
      Api.setStatus(`Erro verificando apresentação: ${resp?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (resp.data?.canceled) {
      clearResultTables();
      const summarizedResp = summarizeLargeVerifyPayload(resp);
      setOut({ where: "presentationVerify.verify", input, resp: summarizedResp });
      $("#pres_verify_result").value = JSON.stringify(summarizedResp, null, 2);
      Api.setStatus("Importação cancelada.");
      return;
    }

    const d = resp.data || {};
    await applyExtraTailRevocationVerification(d, genesisPath);
    const finalResp = { ...resp, data: d };
    const summarizedResp = summarizeLargeVerifyPayload(finalResp);
    setOut({ where: "presentationVerify.verify", input, resp: summarizedResp });
    $("#pres_verify_result").value = JSON.stringify(summarizedResp, null, 2);
    $("#pres_verify_file_path").value = firstNonEmpty(d?.presentationFilePath, $("#pres_verify_file_path").value);
    $("#pres_verify_did").value = firstNonEmpty(d?.verifierDid, $("#pres_verify_did").value);
    $("#pres_verify_ok").value = d?.verified ? "Sim" : "Não";
    $("#pres_verify_crypto").value = yesNoBlank(d?.cryptographicValid);
    $("#pres_verify_revocation_proofs").value = yesNoBlank(d?.proofsVerified);
    $("#pres_verify_revoked").value = yesNoBlank(d?.revoked);
    $("#pres_verify_more_windows").value = yesNoBlank(d?.requiresMoreWindows);
    $("#pres_verify_payload_format").value = firstNonEmpty(d?.payloadFormat);
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
    renderRevocationStatus(d?.perCredentialStatus || [], d);
    lastVerifiedData = d;
    $("#btn_pres_reverify").disabled = false;
    $("#btn_pres_save").disabled = false;

    if (d?.verified) {
      Api.setStatus(
        d?.extraTailVerificationApplied
          ? "Apresentação verificada com sucesso, incluindo a confirmação extra das últimas janelas de revogação."
          : "Apresentação verificada com sucesso."
      );
    } else if (d?.requiresMoreWindows) {
      Api.setStatus("Apresentação recebida, mas o verificador precisa de mais janelas de revogação.");
    } else if (d?.revoked) {
      Api.setStatus("Apresentação processada, mas há credencial revogada no pacote.");
    } else {
      Api.setStatus("Apresentação processada, mas a verificação não foi aceita.");
    }
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
      verification_genesis_path: toStringSafe($("#pres_verify_genesis_path").value).trim() || null,
      revocation_summary: Array.isArray(lastVerifiedData.perCredentialStatus)
        ? lastVerifiedData.perCredentialStatus.map((it) => ({
          sub_proof_index: it?.sub_proof_index ?? null,
          cred_def_id: firstNonEmpty(it?.cred_def_id) || null,
          revocable: !!it?.revocable,
          accepted: !!it?.accepted,
          proof_verified: !!it?.proof_verified,
          revoked: !!it?.revoked,
          requires_more_windows: !!it?.requires_more_windows,
          next_required_window_index: it?.next_required_window_index ?? null,
          issued_at: it?.issued_at ?? null,
          revoked_window_index: it?.revoked_window_index ?? null,
          revoked_window_start: it?.revoked_window_start ?? null,
          details: firstNonEmpty(it?.details) || null,
        }))
        : [],
      revocation_proof_sequences: Array.isArray(lastVerifiedData.revocationProofSequences)
        ? lastVerifiedData.revocationProofSequences
        : [],
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
    const summarizedResp = summarizeLargeVerifyPayload(resp);
    setOut({
      where: "presentationVerify.saveLocal",
      input,
      resp: summarizedResp,
      lastVerifiedData: summarizeLargeVerifyPayload({ ok: true, data: lastVerifiedData }),
    });
    $("#pres_verify_result").value = JSON.stringify(summarizedResp, null, 2);

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

  $("#tbl_pres_verify_revealed thead").addEventListener("click", (ev) => {
    const th = ev.target.closest("th[data-sort-key][data-sort-table='revealed']");
    if (!th) return;
    toggleDetailSort("revealed", toStringSafe(th.dataset.sortKey).trim());
  });

  $("#tbl_pres_verify_predicates thead").addEventListener("click", (ev) => {
    const th = ev.target.closest("th[data-sort-key][data-sort-table='predicates']");
    if (!th) return;
    toggleDetailSort("predicates", toStringSafe(th.dataset.sortKey).trim());
  });

  $("#tbl_pres_verify_revocation tbody").addEventListener("click", (ev) => {
    const tr = ev.target.closest("tr[data-idx]");
    if (!tr) return;
    let items = [];
    try {
      items = JSON.parse($("#tbl_pres_verify_revocation tbody").dataset.items || "[]");
    } catch (_) {
      items = [];
    }
    const idx = Number(tr.dataset.idx);
    if (!Number.isFinite(idx) || !Array.isArray(items) || !items[idx]) return;
    renderSelectedCredentialAttributes(items[idx]);
  });

  window.addEventListener("app:pagechange", (ev) => {
    const from = ev?.detail?.from;
    const to = ev?.detail?.to;
    if (from === "page-presentation-verify" && to !== "page-presentation-verify") {
      releaseHeavyState();
    }
  });

  updateDetailSortHeaderLabels();
  clearResultTables();
  refreshDidOptions().catch(() => {});

  return {};
})();
