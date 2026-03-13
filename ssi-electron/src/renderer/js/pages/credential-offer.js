// src/renderer/js/pages/credential-offer.js
/* eslint-disable no-console */

const CredentialOfferPage = (() => {
  const root = document.getElementById("page-credential-offer");
  if (!root) return {};
  const DEFAULT_LIST_LIMIT = 150;
  const MAX_LIST_LIMIT = 1000;

  let issuerDidOptions = [];
  let recipientOptions = [];
  let credDefOptions = [];
  let visibleIssuerDidOptions = [];
  let visibleRecipientOptions = [];
  let visibleCredDefOptions = [];

  root.innerHTML = `
    <div class="card">
      <h2>Oferta de Credencial</h2>
      <p class="small">
        Gera <code>createCredentialOffer</code> e exporta em envelope cifrado
        com <code>envelopePackAuthcrypt</code>.
      </p>

      <div class="row">
        <button class="secondary" id="btn_refresh_offer_opts">Atualizar DIDs/CredDefs</button>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>1) Dados base</h3>

      <div class="row">
        <div class="input" style="min-width:340px">
          <label>DID emissor (own)</label>
          <select id="sel_offer_issuer">
            <option value="">-- selecione um DID --</option>
          </select>
        </div>

        <div class="input" style="min-width:420px">
          <label>DID emissor (manual)</label>
          <input id="offer_issuer_did" placeholder="ex.: V4SGRU86Z58d6TV7PBUe6f" />
        </div>
      </div>
      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de DIDs (emissor)</label>
          <input id="offer_issuer_filter" placeholder="Filtrar por DID, alias ou verkey..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="offer_issuer_limit" type="number" min="1" max="${MAX_LIST_LIMIT}" value="${DEFAULT_LIST_LIMIT}" />
        </div>
        <button class="secondary" id="btn_offer_issuer_clear_filter">Limpar filtro</button>
      </div>
      <p class="small" id="offer_issuer_stats">DIDs emissor: 0</p>

      <div class="row">
        <div class="input" style="min-width:340px">
          <label>Destinatário (DID + verkey)</label>
          <select id="sel_offer_recipient">
            <option value="">-- selecione um destinatário --</option>
          </select>
        </div>

        <div class="input" style="min-width:520px">
          <label>Recipient verkey (manual)</label>
          <input id="offer_recipient_verkey" placeholder="verkey do holder" />
        </div>
      </div>
      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de destinatários</label>
          <input id="offer_recipient_filter" placeholder="Filtrar por DID, verkey, alias ou origem..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="offer_recipient_limit" type="number" min="1" max="${MAX_LIST_LIMIT}" value="${DEFAULT_LIST_LIMIT}" />
        </div>
        <button class="secondary" id="btn_offer_recipient_clear_filter">Limpar filtro</button>
      </div>
      <p class="small" id="offer_recipient_stats">Destinatários: 0</p>

      <div class="row">
        <div class="input" style="min-width:420px">
          <label>CredDef (registrada no ledger)</label>
          <select id="sel_offer_creddef">
            <option value="">-- selecione uma creddef --</option>
          </select>
        </div>

        <div class="input" style="min-width:520px">
          <label>CredDef ID (manual)</label>
          <input id="offer_creddef_id" placeholder="ex.: did:3:CL:...:TAG" />
        </div>
      </div>
      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de CredDefs</label>
          <input id="offer_creddef_filter" placeholder="Filtrar por credDef ID, emissor, schema ou tag..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="offer_creddef_limit" type="number" min="1" max="${MAX_LIST_LIMIT}" value="${DEFAULT_LIST_LIMIT}" />
        </div>
        <button class="secondary" id="btn_offer_creddef_clear_filter">Limpar filtro</button>
      </div>
      <p class="small" id="offer_creddef_stats">CredDefs: 0</p>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>2) Envelope</h3>

      <div class="row">
        <div class="input" style="min-width:240px">
          <label>Offer ID</label>
          <input id="offer_id" placeholder="vazio = auto" />
        </div>

        <div class="input" style="min-width:180px">
          <label>Kind</label>
          <input id="offer_kind" value="anoncreds/credential_offer" />
        </div>

        <div class="input" style="min-width:240px">
          <label>Thread ID (opcional)</label>
          <input id="offer_thread_id" />
        </div>

        <div class="input" style="min-width:220px">
          <label>ExpiresAt (epoch ms)</label>
          <input id="offer_expires_at" placeholder="ex.: 1772110751044" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Meta JSON (opcional)</label>
          <textarea id="offer_meta_json" rows="4" placeholder='{"step":"cpf_offer"}'></textarea>
        </div>
      </div>

      <div class="row">
        <button class="primary" id="btn_export_offer_envelope">Exportar Oferta em Envelope</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Resultado</label>
          <textarea id="offer_result" rows="10" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="offer_out">{}</pre>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#offer_out");

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

  function parseDidList(resp) {
    if (!resp?.ok) return [];
    const data = parseMaybeJson(resp.data);
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

  function unwrapRecord(raw) {
    let current = raw;

    for (let i = 0; i < 6; i += 1) {
      const parsed = parseMaybeJson(current);
      if (parsed !== current) {
        current = parsed;
        continue;
      }

      if (!current || typeof current !== "object") break;

      const nestedCandidates = [
        current.json,
        current.data,
        current.result,
        current.value,
      ];

      let moved = false;
      for (const nested of nestedCandidates) {
        const parsedNested = parseMaybeJson(nested);
        if (parsedNested && parsedNested !== nested) {
          current = parsedNested;
          moved = true;
          break;
        }
        if (parsedNested && typeof parsedNested === "object") {
          current = parsedNested;
          moved = true;
          break;
        }
      }

      if (!moved) break;
    }

    if (current && typeof current === "object") return current;
    return null;
  }

  function looksLikeCredDefId(txt) {
    const id = toStringSafe(txt).trim();
    if (!id) return false;
    if (id.includes(":3:CL:")) return true;
    if (id.includes("/anoncreds/v0/CLAIM_DEF/")) return true;
    return false;
  }

  function pickCredDefIdFromObject(obj) {
    if (!obj || typeof obj !== "object") return "";

    const direct = firstNonEmpty(
      obj.cred_def_id,
      obj.credDefId,
      obj.creddef_id,
      obj.credDefID,
      obj.credential_definition_id,
      obj.credentialDefinitionId,
      obj.ledger_id,
      obj.ledgerId,
      obj.id_ledger,
      obj.idLedger,
      obj.cred_def?.id,
      obj.credDef?.id,
      obj.credential_definition?.id,
      obj.credentialDefinition?.id
    );
    if (direct) return direct;

    const stack = [obj];
    let visited = 0;
    while (stack.length > 0 && visited < 120) {
      visited += 1;
      const cur = stack.pop();
      if (!cur || typeof cur !== "object") continue;
      const values = Object.values(cur);
      for (const v of values) {
        if (typeof v === "string" && looksLikeCredDefId(v)) return v.trim();
        if (v && typeof v === "object") stack.push(v);
      }
    }
    return "";
  }

  function normalizeRecordList(rawData) {
    const parsedRoot = parseMaybeJson(rawData);
    const rootValue = unwrapRecord(parsedRoot) || parsedRoot;

    if (Array.isArray(rootValue)) {
      return rootValue
        .map((it) => unwrapRecord(it) || parseMaybeJson(it))
        .filter((it) => it && typeof it === "object");
    }

    if (!rootValue || typeof rootValue !== "object") return [];

    const candidateArrays = [
      rootValue.items,
      rootValue.records,
      rootValue.list,
      rootValue.result,
      rootValue.data,
      rootValue.values,
    ];

    for (const arr of candidateArrays) {
      const parsed = parseMaybeJson(arr);
      if (Array.isArray(parsed)) {
        return parsed
          .map((it) => unwrapRecord(it) || parseMaybeJson(it))
          .filter((it) => it && typeof it === "object");
      }
    }

    const objectValues = Object.values(rootValue).filter((v) => v && typeof v === "object");
    if (objectValues.length > 0) {
      return objectValues
        .map((it) => unwrapRecord(it) || parseMaybeJson(it))
        .filter((it) => it && typeof it === "object");
    }

    return [];
  }

  function extractCredDefId(rec) {
    const unwrapped = unwrapRecord(rec) || rec;
    if (!unwrapped || typeof unwrapped !== "object") return "";

    const direct = pickCredDefIdFromObject(unwrapped);
    if (direct) return direct;

    const localId = firstNonEmpty(unwrapped.id_local, unwrapped.id, unwrapped.local_id);
    if (looksLikeCredDefId(localId)) return localId;

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

  function issuerSearchBlob(d) {
    return normalizeText([
      d.did,
      d.alias,
      d.verkey,
      d.verKey,
    ].filter(Boolean).join(" "));
  }

  function recipientSearchBlob(d) {
    return normalizeText([
      d.did,
      d.alias,
      d.verkey,
      d.verKey,
      d.source,
    ].filter(Boolean).join(" "));
  }

  function credDefSearchBlob(c) {
    return normalizeText([
      c.credDefId,
      c.label,
      c.issuerDid,
      c.schemaId,
      c.tag,
    ].filter(Boolean).join(" "));
  }

  function updateListStats(elId, label, total, filtered, shown, limit) {
    $(elId).textContent = `${label}: total ${total} | filtrados ${filtered} | exibidos ${shown} (máx ${limit})`;
  }

  function renderIssuerOptions(items) {
    const el = $("#sel_offer_issuer");
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

  function renderRecipientOptions(items) {
    const el = $("#sel_offer_recipient");
    const currentVerkey = toStringSafe(el.value).trim();
    el.innerHTML = `<option value="">-- selecione um destinatário --</option>`;

    const fragment = document.createDocumentFragment();
    (items || []).forEach((d) => {
      const verkey = toStringSafe(d.verkey).trim();
      const did = toStringSafe(d.did).trim();
      if (!verkey || !did) return;
      const opt = document.createElement("option");
      opt.value = verkey;
      opt.textContent = `${did} | ${verkey.slice(0, 20)}... (${d.source})`;
      fragment.appendChild(opt);
    });
    el.appendChild(fragment);

    if (currentVerkey && (items || []).some((d) => toStringSafe(d.verkey).trim() === currentVerkey)) {
      el.value = currentVerkey;
    }
  }

  function renderCredDefOptions(items) {
    const el = $("#sel_offer_creddef");
    const currentCredDefId = toStringSafe(el.value).trim();
    el.innerHTML = `<option value="">-- selecione uma creddef --</option>`;

    const fragment = document.createDocumentFragment();
    (items || []).forEach((c) => {
      const opt = document.createElement("option");
      opt.value = c.credDefId;
      opt.textContent = `${c.credDefId}${c.label ? ` | ${c.label}` : ""}`;
      fragment.appendChild(opt);
    });
    el.appendChild(fragment);

    if (currentCredDefId && (items || []).some((c) => toStringSafe(c.credDefId).trim() === currentCredDefId)) {
      el.value = currentCredDefId;
    }
  }

  function applyIssuerFilter() {
    const filterText = normalizeText($("#offer_issuer_filter").value).trim();
    const limit = parseListLimit($("#offer_issuer_limit").value);
    $("#offer_issuer_limit").value = String(limit);

    const filtered = filterText
      ? issuerDidOptions.filter((d) => issuerSearchBlob(d).includes(filterText))
      : issuerDidOptions;

    visibleIssuerDidOptions = filtered.slice(0, limit);
    renderIssuerOptions(visibleIssuerDidOptions);
    updateListStats(
      "#offer_issuer_stats",
      "DIDs emissor",
      issuerDidOptions.length,
      filtered.length,
      visibleIssuerDidOptions.length,
      limit
    );
  }

  function applyRecipientFilter() {
    const filterText = normalizeText($("#offer_recipient_filter").value).trim();
    const limit = parseListLimit($("#offer_recipient_limit").value);
    $("#offer_recipient_limit").value = String(limit);

    const filtered = filterText
      ? recipientOptions.filter((d) => recipientSearchBlob(d).includes(filterText))
      : recipientOptions;

    visibleRecipientOptions = filtered.slice(0, limit);
    renderRecipientOptions(visibleRecipientOptions);
    updateListStats(
      "#offer_recipient_stats",
      "Destinatários",
      recipientOptions.length,
      filtered.length,
      visibleRecipientOptions.length,
      limit
    );
  }

  function applyCredDefFilter() {
    const filterText = normalizeText($("#offer_creddef_filter").value).trim();
    const limit = parseListLimit($("#offer_creddef_limit").value);
    $("#offer_creddef_limit").value = String(limit);

    const filtered = filterText
      ? credDefOptions.filter((c) => credDefSearchBlob(c).includes(filterText))
      : credDefOptions;

    visibleCredDefOptions = filtered.slice(0, limit);
    renderCredDefOptions(visibleCredDefOptions);
    updateListStats(
      "#offer_creddef_stats",
      "CredDefs",
      credDefOptions.length,
      filtered.length,
      visibleCredDefOptions.length,
      limit
    );
  }

  async function refreshOptions() {
    Api.setStatus("Carregando DIDs e CredDefs para oferta...");

    const [ownResp, externalResp, credDefsAllResp, credDefsOnLedgerResp] = await Promise.all([
      Api.did.list("own"),
      Api.did.list("external"),
      Api.creddef.listLocal(null, null, null, null, null),
      Api.creddef.listLocal(true, null, null, null, null),
    ]);

    setOut({
      where: "credentialOffer.refreshOptions",
      ownResp,
      externalResp,
      credDefsAllResp,
      credDefsOnLedgerResp,
    });

    if (!ownResp?.ok) {
      Api.setStatus(`Erro listando DIDs own: ${ownResp?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (!externalResp?.ok) {
      Api.setStatus(`Erro listando DIDs external: ${externalResp?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (!credDefsAllResp?.ok && !credDefsOnLedgerResp?.ok) {
      const errAll = credDefsAllResp?.error?.message;
      const errOnLedger = credDefsOnLedgerResp?.error?.message;
      const errMsg = firstNonEmpty(errAll, errOnLedger, "erro desconhecido");
      Api.setStatus(`Erro listando CredDefs: ${errMsg}`);
      return;
    }

    issuerDidOptions = parseDidList(ownResp);
    applyIssuerFilter();

    const own = parseDidList(ownResp).map((d) => ({ ...d, source: "own" }));
    const ext = parseDidList(externalResp).map((d) => ({ ...d, source: "external" }));
    const seen = new Set();
    recipientOptions = own.concat(ext).filter((d) => {
      const key = `${toStringSafe(d.did).trim()}|${toStringSafe(d.verkey).trim()}`;
      if (!key || seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    applyRecipientFilter();

    let records = [];
    try {
      const listA = credDefsAllResp?.ok ? normalizeRecordList(credDefsAllResp.data) : [];
      const listB = credDefsOnLedgerResp?.ok ? normalizeRecordList(credDefsOnLedgerResp.data) : [];
      records = listA.concat(listB);
    } catch (_) {
      records = [];
    }

    const seenCredDefs = new Set();
    credDefOptions = records
      .map((rec) => {
        const credDefId = extractCredDefId(rec);
        const label = [
          firstNonEmpty(rec.issuer_did, rec.issuerDid),
          firstNonEmpty(rec.schema_id, rec.schemaId),
          firstNonEmpty(rec.tag),
        ]
          .map((v) => toStringSafe(v).trim())
          .filter(Boolean)
          .join(" | ");
        return {
          credDefId,
          label,
          issuerDid: firstNonEmpty(rec.issuer_did, rec.issuerDid),
          schemaId: firstNonEmpty(rec.schema_id, rec.schemaId),
          tag: firstNonEmpty(rec.tag),
        };
      })
      .filter((it) => {
        if (!it.credDefId) return false;
        if (seenCredDefs.has(it.credDefId)) return false;
        seenCredDefs.add(it.credDefId);
        return true;
      });
    applyCredDefFilter();

    const manualCredDefId = toStringSafe($("#offer_creddef_id").value).trim();
    if (manualCredDefId && seenCredDefs.has(manualCredDefId)) {
      $("#sel_offer_creddef").value = manualCredDefId;
    } else if (!manualCredDefId && credDefOptions.length === 1) {
      const onlyCredDefId = credDefOptions[0].credDefId;
      $("#sel_offer_creddef").value = onlyCredDefId;
      $("#offer_creddef_id").value = onlyCredDefId;
    }

    Api.setStatus(
      `Opções carregadas: ${issuerDidOptions.length} DID(s) emissor, ${recipientOptions.length} destinatário(s), ${credDefOptions.length} creddef(s).`
    );
  }

  async function exportOfferEnvelope() {
    const issuerDid = toStringSafe($("#offer_issuer_did").value).trim();
    const recipientVerkey = toStringSafe($("#offer_recipient_verkey").value).trim();
    const credDefId = toStringSafe($("#offer_creddef_id").value).trim();
    const kind = toStringSafe($("#offer_kind").value).trim() || "anoncreds/credential_offer";
    const threadId = toStringSafe($("#offer_thread_id").value).trim() || null;

    const offerIdInput = toStringSafe($("#offer_id").value).trim();

    if (!issuerDid) { Api.setStatus("Informe DID emissor."); return; }
    if (!recipientVerkey) { Api.setStatus("Informe recipient verkey."); return; }
    if (!credDefId) { Api.setStatus("Informe CredDef ID."); return; }

    const expiresRaw = toStringSafe($("#offer_expires_at").value).trim();
    let expiresAtMs = null;
    if (expiresRaw) {
      const parsed = Number(expiresRaw);
      if (!Number.isFinite(parsed) || parsed <= 0) {
        Api.setStatus("ExpiresAt inválido. Use epoch em milissegundos.");
        return;
      }
      expiresAtMs = Math.trunc(parsed);
    }

    const metaRaw = toStringSafe($("#offer_meta_json").value).trim();
    let metaObj = null;
    if (metaRaw) {
      try {
        metaObj = JSON.parse(metaRaw);
      } catch (_) {
        Api.setStatus("Meta JSON inválido.");
        return;
      }
    }

    const input = {
      issuerDid,
      recipientVerkey,
      credDefId,
      kind,
      threadId,
      expiresAtMs,
      metaObj,
    };
    if (offerIdInput) input.offerId = offerIdInput;

    Api.setStatus("Gerando oferta e empacotando envelope...");
    const r = await Api.credOffer.exportEnvelope(input);
    setOut({ where: "credentialOffer.exportEnvelope", input, resp: r });
    $("#offer_result").value = JSON.stringify(r, null, 2);

    if (!r?.ok) {
      Api.setStatus(`Erro na exportação: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    if (r.data?.canceled) {
      Api.setStatus("Exportação cancelada.");
      return;
    }

    Api.setStatus(`Oferta exportada em envelope: ${r.data?.filePath || "(sem caminho)"}`);
  }

  $("#btn_refresh_offer_opts").addEventListener("click", refreshOptions);
  $("#btn_export_offer_envelope").addEventListener("click", exportOfferEnvelope);
  $("#offer_issuer_filter").addEventListener("input", applyIssuerFilter);
  $("#offer_issuer_filter").addEventListener("keyup", applyIssuerFilter);
  $("#offer_issuer_limit").addEventListener("input", applyIssuerFilter);
  $("#offer_issuer_limit").addEventListener("change", applyIssuerFilter);
  $("#btn_offer_issuer_clear_filter").addEventListener("click", () => {
    $("#offer_issuer_filter").value = "";
    applyIssuerFilter();
  });
  $("#offer_recipient_filter").addEventListener("input", applyRecipientFilter);
  $("#offer_recipient_filter").addEventListener("keyup", applyRecipientFilter);
  $("#offer_recipient_limit").addEventListener("input", applyRecipientFilter);
  $("#offer_recipient_limit").addEventListener("change", applyRecipientFilter);
  $("#btn_offer_recipient_clear_filter").addEventListener("click", () => {
    $("#offer_recipient_filter").value = "";
    applyRecipientFilter();
  });
  $("#offer_creddef_filter").addEventListener("input", applyCredDefFilter);
  $("#offer_creddef_filter").addEventListener("keyup", applyCredDefFilter);
  $("#offer_creddef_limit").addEventListener("input", applyCredDefFilter);
  $("#offer_creddef_limit").addEventListener("change", applyCredDefFilter);
  $("#btn_offer_creddef_clear_filter").addEventListener("click", () => {
    $("#offer_creddef_filter").value = "";
    applyCredDefFilter();
  });

  $("#sel_offer_issuer").addEventListener("change", () => {
    const did = toStringSafe($("#sel_offer_issuer").value).trim();
    if (did) $("#offer_issuer_did").value = did;
  });

  $("#sel_offer_recipient").addEventListener("change", () => {
    const verkey = toStringSafe($("#sel_offer_recipient").value).trim();
    if (verkey) $("#offer_recipient_verkey").value = verkey;
  });

  $("#sel_offer_creddef").addEventListener("change", () => {
    const credDefId = toStringSafe($("#sel_offer_creddef").value).trim();
    if (credDefId) $("#offer_creddef_id").value = credDefId;
  });

  refreshOptions().catch(() => {});
  return {};
})();
