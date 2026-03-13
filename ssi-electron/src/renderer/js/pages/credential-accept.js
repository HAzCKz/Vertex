// src/renderer/js/pages/credential-accept.js
/* eslint-disable no-console */

const CredentialAcceptPage = (() => {
  const root = document.getElementById("page-credential-accept");
  if (!root) return {};
  const DEFAULT_DID_LIMIT = 150;
  const MAX_DID_LIMIT = 1000;

  let ownDidOptions = [];
  let visibleOwnDidOptions = [];
  let lastImportedOffer = null;
  let lastOfferAttrLoadId = 0;

  root.innerHTML = `
    <div class="card">
      <h2>Aceite de Oferta de Credencial</h2>
      <p class="small">
        Importa um arquivo de oferta (Envelope), decripta com o DID de destino e exporta
        o arquivo de aceite (<code>credential_request</code>) em novo envelope.
      </p>

      <div class="row">
        <button class="secondary" id="btn_accept_refresh_dids">Atualizar DIDs own</button>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>1) Holder (destino)</h3>

      <div class="row">
        <div class="input" style="min-width:340px">
          <label>DID holder (lista own)</label>
          <select id="sel_accept_holder_did">
            <option value="">-- selecione um DID --</option>
          </select>
        </div>

        <div class="input" style="min-width:420px">
          <label>DID holder (manual)</label>
          <input id="accept_holder_did" placeholder="ex.: did do destinatário da oferta" />
        </div>
      </div>
      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de DIDs</label>
          <input id="accept_holder_filter" placeholder="Filtrar por DID, alias ou verkey..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="accept_holder_limit" type="number" min="1" max="${MAX_DID_LIMIT}" value="${DEFAULT_DID_LIMIT}" />
        </div>
        <button class="secondary" id="btn_accept_holder_clear_filter">Limpar filtro</button>
      </div>
      <p class="small" id="accept_holder_stats">DIDs holder: 0</p>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Genesis path</label>
          <input id="accept_genesis_path" placeholder="/caminho/para/genesis.txn" />
        </div>

        <div class="input" style="min-width:200px">
          <label>Link Secret ID</label>
          <input id="accept_link_secret_id" value="default" />
        </div>

        <label class="small" style="display:flex; gap:10px; align-items:center; min-width:240px;">
          <input type="checkbox" id="accept_ensure_link_secret" checked />
          Garantir Link Secret
        </label>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>2) Importar oferta</h3>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Arquivo da oferta (.env.json)</label>
          <input id="accept_offer_file_path" placeholder="vazio = escolher no diálogo" />
        </div>
        <button class="secondary" id="btn_accept_import_offer">Importar oferta</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:320px">
          <label>CredDef ID (da oferta)</label>
          <input id="accept_offer_creddef_id" readonly />
        </div>

        <div class="input" style="min-width:220px">
          <label>Nonce (reqMetaId)</label>
          <input id="accept_offer_nonce" readonly />
        </div>

        <div class="input" style="min-width:320px">
          <label>Kind da oferta</label>
          <input id="accept_offer_kind" readonly />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Verkey do emissor (destino do request)</label>
          <input id="accept_issuer_verkey" placeholder="se vazio, tenta inferir do envelope" />
        </div>
      </div>
      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Atributos da credencial</label>
          <textarea
            id="accept_offer_attributes"
            rows="6"
            readonly
            placeholder="Os atributos da credencial aparecerão aqui após importar a oferta."
          ></textarea>
          <p class="small" id="accept_offer_attributes_hint">
            Importe a oferta para visualizar os atributos que serão solicitados na credencial.
          </p>
        </div>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>3) Exportar aceite (request envelope)</h3>

      <div class="row">
        <div class="input" style="min-width:260px">
          <label>Kind do request</label>
          <input id="accept_request_kind" value="anoncreds/credential_request" />
        </div>

        <div class="input" style="min-width:320px">
          <label>Thread ID (opcional)</label>
          <input id="accept_thread_id" placeholder="vazio = usa thread da oferta" />
        </div>

        <div class="input" style="min-width:220px">
          <label>ExpiresAt (epoch ms)</label>
          <input id="accept_expires_at" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Meta JSON (opcional)</label>
          <textarea id="accept_meta_json" rows="4" placeholder='{"kind":"cpf"}'></textarea>
        </div>
      </div>

      <div class="row">
        <button class="primary" id="btn_accept_export_request">Exportar aceite (request)</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Resultado</label>
          <textarea id="accept_result" rows="10" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="accept_out">{}</pre>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#accept_out");

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
    for (const v of values) {
      const s = toStringSafe(v).trim();
      if (s) return s;
    }
    return "";
  }

  function unwrapPayload(data) {
    if (data && typeof data === "object" && data.data && typeof data.data === "object" && !data.offerFilePath) {
      return data.data;
    }
    return data;
  }

  function normalizeText(v) {
    return toStringSafe(v).toLocaleLowerCase("pt-BR");
  }

  function setOfferAttributes(entries, hint) {
    const area = $("#accept_offer_attributes");
    const help = $("#accept_offer_attributes_hint");
    const list = Array.isArray(entries) ? entries : [];
    area.value = list.length
      ? list.map((item) => {
        const name = toStringSafe(item?.name).trim();
        const value = item?.value === undefined || item?.value === null
          ? ""
          : toStringSafe(item.value).trim();
        return value ? `${name}: ${value}` : name;
      }).filter(Boolean).join("\n")
      : "";
    help.textContent = toStringSafe(hint).trim();
  }

  function dedupeAttributeEntries(entries) {
    const seen = new Set();
    const out = [];

    (entries || []).forEach((item) => {
      const name = toStringSafe(item?.name).trim();
      if (!name) return;
      const key = normalizeText(name);
      if (seen.has(key)) return;
      seen.add(key);
      out.push({
        name,
        value: item?.value === undefined || item?.value === null
          ? null
          : toStringSafe(item.value).trim(),
      });
    });

    return out;
  }

  function collectAttributeEntriesFromCandidate(candidate) {
    if (!candidate) return [];

    if (Array.isArray(candidate)) {
      return candidate.flatMap((item) => {
        if (typeof item === "string") return [{ name: item, value: null }];
        if (!item || typeof item !== "object") return [];
        return [{
          name: firstNonEmpty(item.name, item.label, item.key),
          value: firstNonEmpty(item.value, item.raw, item.encoded),
        }];
      });
    }

    if (typeof candidate === "object") {
      return Object.entries(candidate).map(([name, value]) => ({
        name,
        value: value === undefined || value === null || typeof value === "object"
          ? null
          : String(value),
      }));
    }

    return [];
  }

  function extractOfferAttributeEntries(offerObj) {
    if (!offerObj || typeof offerObj !== "object") return [];

    const candidates = [
      offerObj.credential_preview?.attributes,
      offerObj.credentialPreview?.attributes,
      offerObj.preview?.attributes,
      offerObj.preview,
      offerObj.attributes,
      offerObj.values,
      offerObj.values_raw,
      offerObj.valuesTemplate,
      offerObj.schema?.attr_names,
      offerObj.schema?.attrNames,
      offerObj.attr_names,
      offerObj.attrNames,
    ];

    for (const candidate of candidates) {
      const parsed = dedupeAttributeEntries(collectAttributeEntriesFromCandidate(candidate));
      if (parsed.length) return parsed;
    }

    return [];
  }

  async function refreshImportedOfferAttributes() {
    const payload = unwrapPayload(lastImportedOffer) || {};
    const offerObj = payload?.offer && typeof payload.offer === "object" ? payload.offer : null;
    const previewEntries = dedupeAttributeEntries(extractOfferAttributeEntries(offerObj));
    if (previewEntries.length) {
      setOfferAttributes(
        previewEntries,
        `Atributos obtidos do preview da oferta (${previewEntries.length}).`
      );
      return;
    }

    const credDefId = toStringSafe($("#accept_offer_creddef_id").value).trim();
    if (!credDefId) {
      setOfferAttributes([], "Importe a oferta para carregar os atributos da credencial.");
      return;
    }

    const genesisPath = toStringSafe($("#accept_genesis_path").value).trim();
    if (!genesisPath) {
      setOfferAttributes(
        [],
        "A oferta não trouxe preview dos atributos. Informe o Genesis path para carregar os nomes pelo schema."
      );
      return;
    }

    const loadId = lastOfferAttrLoadId + 1;
    lastOfferAttrLoadId = loadId;
    setOfferAttributes([], "Carregando atributos da credencial a partir da CredDef...");

    const r = await Api.credCreate.loadSchemaTemplate({ genesisPath, credDefId });
    if (lastOfferAttrLoadId !== loadId) return;

    if (!r?.ok) {
      setOfferAttributes(
        [],
        `Não foi possível carregar os atributos: ${r?.error?.message || "erro desconhecido"}.`
      );
      return;
    }

    const attrNames = Array.isArray(r.data?.attrNames) ? r.data.attrNames : [];
    const entries = attrNames.map((name) => ({ name, value: null }));
    const source = toStringSafe(r.data?.attrSource).trim();
    const sourceLabel = source === "creddef_primary_r" ? "CredDef" : "schema";
    setOfferAttributes(
      entries,
      `${entries.length} atributo(s) carregado(s) do ${sourceLabel}.`
    );
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
    const el = $("#sel_accept_holder_did");
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
    $("#accept_holder_stats").textContent =
      `DIDs holder: total ${total} | filtrados ${filtered} | exibidos ${shown} (máx ${limit})`;
  }

  function applyOwnDidFilter() {
    const filterText = normalizeText($("#accept_holder_filter").value).trim();
    const limit = parseDidLimit($("#accept_holder_limit").value);
    $("#accept_holder_limit").value = String(limit);

    const filtered = filterText
      ? ownDidOptions.filter((d) => didSearchBlob(d).includes(filterText))
      : ownDidOptions;

    visibleOwnDidOptions = filtered.slice(0, limit);
    renderOwnDidOptions(visibleOwnDidOptions);
    updateDidStats(ownDidOptions.length, filtered.length, visibleOwnDidOptions.length, limit);
  }

  function parseDidList(resp) {
    if (!resp?.ok) return [];
    const data = parseMaybeJson(resp.data);
    if (Array.isArray(data)) return data;
    if (data && Array.isArray(data.items)) return data.items;
    return [];
  }

  async function refreshDidOptions() {
    Api.setStatus("Carregando DIDs own...");
    const r = await Api.did.list("own");
    setOut({ where: "credentialAccept.refreshDidOptions", resp: r });
    if (!r?.ok) {
      Api.setStatus(`Erro listando DIDs own: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    ownDidOptions = parseDidList(r);
    applyOwnDidFilter();
    Api.setStatus(`DIDs own carregados: ${ownDidOptions.length} (${visibleOwnDidOptions.length} exibidos).`);
  }

  function holderDidInput() {
    return toStringSafe($("#accept_holder_did").value).trim();
  }

  function updateImportedOfferFields(rawData) {
    const data = unwrapPayload(rawData) || {};
    const env = data?.envelopeSummary || {};
    const offer = data?.offer || {};

    const offerFilePath = firstNonEmpty(data?.offerFilePath, data?.filePath);
    const holderDidResolved = firstNonEmpty(data?.holderDidResolved, data?.holderDid);
    const credDefId = firstNonEmpty(
      data?.credDefId,
      offer?.cred_def_id,
      offer?.credDefId,
      offer?.offer?.cred_def_id,
      offer?.offer?.credDefId
    );
    const nonce = firstNonEmpty(
      data?.nonce,
      offer?.nonce,
      offer?.offer_nonce,
      offer?.offerNonce
    );
    const kind = firstNonEmpty(
      data?.kind,
      env?.kind,
      env?.envelope?.kind
    );
    const threadId = firstNonEmpty(
      data?.threadId,
      env?.thread_id,
      env?.threadId,
      env?.thid
    );
    const issuerVerkeyHint = firstNonEmpty(
      data?.issuerVerkeyHint,
      env?.sender_verkey,
      env?.crypto?.sender_verkey,
      env?.crypto?.senderVerkey,
      env?.from?.verkey
    );

    if (holderDidResolved) {
      $("#accept_holder_did").value = holderDidResolved;
    }
    $("#accept_offer_file_path").value = offerFilePath;
    $("#accept_offer_creddef_id").value = credDefId;
    $("#accept_offer_nonce").value = nonce;
    $("#accept_offer_kind").value = kind;

    if (threadId) {
      $("#accept_thread_id").value = threadId;
    }
    if (toStringSafe(data?.issuerVerkeyHint).trim()) {
      $("#accept_issuer_verkey").value = toStringSafe(data.issuerVerkeyHint).trim();
    } else if (issuerVerkeyHint && !toStringSafe($("#accept_issuer_verkey").value).trim()) {
      $("#accept_issuer_verkey").value = issuerVerkeyHint;
    }

    refreshImportedOfferAttributes().catch(() => {
      setOfferAttributes([], "Não foi possível atualizar a lista de atributos da credencial.");
    });
  }

  async function importOfferEnvelope() {
    const holderDid = holderDidInput();
    if (!holderDid) {
      Api.setStatus("Informe o DID holder para decriptar a oferta.");
      return;
    }

    const offerFilePath = toStringSafe($("#accept_offer_file_path").value).trim() || null;
    Api.setStatus("Importando oferta de credencial (envelope)...");
    const r = await Api.credAccept.importOfferEnvelope({
      holderDid,
      offerFilePath,
    });

    setOut({ where: "credentialAccept.importOfferEnvelope", input: { holderDid, offerFilePath }, resp: r });
    $("#accept_result").value = JSON.stringify(r, null, 2);

    if (!r?.ok) {
      Api.setStatus(`Erro importando oferta: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (r.data?.canceled) {
      Api.setStatus("Importação cancelada.");
      return;
    }

    const payload = unwrapPayload(r.data);
    lastImportedOffer = payload;
    updateImportedOfferFields(payload);
    Api.setStatus("Oferta importada e decriptada com sucesso.");
  }

  async function exportRequestEnvelope() {
    const holderDid = holderDidInput();
    const genesisPath = toStringSafe($("#accept_genesis_path").value).trim();
    const linkSecretId = toStringSafe($("#accept_link_secret_id").value).trim() || "default";
    const ensureLinkSecret = !!$("#accept_ensure_link_secret").checked;

    if (!holderDid) {
      Api.setStatus("Informe DID holder.");
      return;
    }
    if (!genesisPath) {
      Api.setStatus("Informe Genesis path.");
      return;
    }

    const offerFilePath = toStringSafe($("#accept_offer_file_path").value).trim() || null;
    const issuerVerkey = toStringSafe($("#accept_issuer_verkey").value).trim() || null;
    const kind = toStringSafe($("#accept_request_kind").value).trim() || "anoncreds/credential_request";
    const threadId = toStringSafe($("#accept_thread_id").value).trim() || null;

    const expiresRaw = toStringSafe($("#accept_expires_at").value).trim();
    let expiresAtMs = null;
    if (expiresRaw) {
      const parsed = Number(expiresRaw);
      if (!Number.isFinite(parsed) || parsed <= 0) {
        Api.setStatus("ExpiresAt inválido. Use epoch em milissegundos.");
        return;
      }
      expiresAtMs = Math.trunc(parsed);
    }

    const metaRaw = toStringSafe($("#accept_meta_json").value).trim();
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
      holderDid,
      genesisPath,
      linkSecretId,
      ensureLinkSecret,
      offerFilePath,
      issuerVerkey,
      kind,
      threadId,
      expiresAtMs,
      metaObj,
    };

    Api.setStatus("Gerando credential request e exportando envelope...");
    const r = await Api.credAccept.exportRequestEnvelope(input);
    setOut({ where: "credentialAccept.exportRequestEnvelope", input, resp: r, lastImportedOffer });
    $("#accept_result").value = JSON.stringify(r, null, 2);

    if (!r?.ok) {
      Api.setStatus(`Erro exportando request: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (r.data?.canceled) {
      Api.setStatus("Exportação cancelada.");
      return;
    }

    Api.setStatus(`Aceite exportado: ${r.data?.requestFilePath || "(sem caminho)"}`);
  }

  $("#btn_accept_refresh_dids").addEventListener("click", refreshDidOptions);
  $("#btn_accept_import_offer").addEventListener("click", importOfferEnvelope);
  $("#btn_accept_export_request").addEventListener("click", exportRequestEnvelope);
  $("#accept_holder_filter").addEventListener("input", applyOwnDidFilter);
  $("#accept_holder_filter").addEventListener("keyup", applyOwnDidFilter);
  $("#accept_holder_limit").addEventListener("input", applyOwnDidFilter);
  $("#accept_holder_limit").addEventListener("change", applyOwnDidFilter);
  $("#accept_genesis_path").addEventListener("change", () => {
    refreshImportedOfferAttributes().catch(() => {
      setOfferAttributes([], "Não foi possível atualizar a lista de atributos da credencial.");
    });
  });
  $("#accept_genesis_path").addEventListener("blur", () => {
    refreshImportedOfferAttributes().catch(() => {
      setOfferAttributes([], "Não foi possível atualizar a lista de atributos da credencial.");
    });
  });
  $("#btn_accept_holder_clear_filter").addEventListener("click", () => {
    $("#accept_holder_filter").value = "";
    applyOwnDidFilter();
  });

  $("#sel_accept_holder_did").addEventListener("change", () => {
    const did = toStringSafe($("#sel_accept_holder_did").value).trim();
    if (did) $("#accept_holder_did").value = did;
  });

  refreshDidOptions().catch(() => {});
  return {};
})();
