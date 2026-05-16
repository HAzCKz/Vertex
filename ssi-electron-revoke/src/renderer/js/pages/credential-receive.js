// src/renderer/js/pages/credential-receive.js
/* eslint-disable no-console */

const CredentialReceivePage = (() => {
  const root = document.getElementById("page-credential-receive");
  if (!root) return {};
  const DEFAULT_DID_LIMIT = 150;
  const MAX_DID_LIMIT = 1000;
  const CREDENTIAL_ID_TIMESTAMP_RE = /-\d{8}-\d{6}-\d{3}$/;
  const DEBUG_MAX_DEPTH = 5;
  const DEBUG_MAX_OBJECT_KEYS = 32;
  const DEBUG_MAX_ARRAY_ITEMS = 8;
  const DEBUG_MAX_STRING_LENGTH = 500;
  const DEBUG_HEAVY_KEYS = new Set([
    "credential",
    "credential_json",
    "credentialJson",
    "credentialPlain",
    "credentialJsonForStore",
    "holder_bundle",
    "holderBundle",
    "revocationBundleRecord",
    "proof",
    "proofs",
    "proof_sequence",
    "proofSequence",
    "values",
  ]);

  let ownDidOptions = [];
  let visibleOwnDidOptions = [];
  let importedCredentialPreview = null;

  root.innerHTML = `
    <div class="card">
      <h2>Receber Credencial</h2>
      <p class="small">
        Importa o envelope de credencial gerado em <code>Criar Credencial</code>,
        decripta para o Holder e salva a credencial na wallet.
      </p>

      <div class="row">
        <button class="secondary" id="btn_receive_refresh_dids">Atualizar DIDs own</button>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>1) Holder</h3>

      <div class="row">
        <div class="input" style="min-width:340px">
          <label>DID holder (lista own)</label>
          <select id="sel_receive_holder_did">
            <option value="">-- selecione um DID --</option>
          </select>
        </div>

        <div class="input" style="min-width:420px">
          <label>DID holder (manual)</label>
          <input id="receive_holder_did" placeholder="ex.: did do holder" />
        </div>
      </div>
      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de DIDs</label>
          <input id="receive_holder_filter" placeholder="Filtrar por DID, alias ou verkey..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="receive_holder_limit" type="number" min="1" max="${MAX_DID_LIMIT}" value="${DEFAULT_DID_LIMIT}" />
        </div>
        <button class="secondary" id="btn_receive_holder_clear_filter">Limpar filtro</button>
      </div>
      <p class="small" id="receive_holder_stats">DIDs holder: 0</p>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Genesis path</label>
          <input id="receive_genesis_path" placeholder="/caminho/para/genesis.txn" />
        </div>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>2) Importar e salvar</h3>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Arquivo da credencial (.env.json)</label>
          <input id="receive_credential_file_path" placeholder="vazio = escolher no diálogo" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Arquivo da oferta (opcional, para inferir nonce)</label>
          <input id="receive_offer_file_path" placeholder="ex.: /caminho/cred_offer.env.json" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:320px">
          <label>Request Metadata ID (nonce)</label>
          <input id="receive_request_metadata_id" placeholder="se vazio, tenta inferir do envelope" />
        </div>
        <div class="input" style="min-width:320px">
          <label>Credential ID (local)</label>
          <input id="receive_credential_id" placeholder="vazio = auto" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Atributos da credencial</label>
          <textarea id="receive_credential_attrs" rows="8" readonly placeholder="Importe a credencial para visualizar os atributos e valores antes de salvar."></textarea>
        </div>
      </div>

      <div class="row">
        <button class="secondary" id="btn_receive_import_preview">Importar Credencial</button>
        <button class="primary" id="btn_receive_store">Salvar Credencial</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:320px">
          <label>CredDef ID</label>
          <input id="receive_creddef_id" readonly />
        </div>
        <div class="input" style="min-width:260px">
          <label>Thread ID</label>
          <input id="receive_thread_id" readonly />
        </div>
        <div class="input" style="min-width:260px">
          <label>Kind</label>
          <input id="receive_kind" readonly />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Resultado</label>
          <textarea id="receive_result" rows="10" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="receive_out" class="debug-scroll" tabindex="0">{}</pre>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#receive_out");

  function summarizeHeavyDebugValue(key, value) {
    if (Array.isArray(value)) {
      return {
        omitted: true,
        reason: "debug_compact_heavy_array",
        key,
        length: value.length,
        sample: value.slice(0, DEBUG_MAX_ARRAY_ITEMS).map((item) => summarizeDebugValue(item, 1, key)),
      };
    }
    if (value && typeof value === "object") {
      const keys = Object.keys(value);
      return {
        omitted: true,
        reason: "debug_compact_heavy_object",
        key,
        keys: keys.slice(0, DEBUG_MAX_OBJECT_KEYS),
        omittedKeys: Math.max(0, keys.length - DEBUG_MAX_OBJECT_KEYS),
      };
    }
    if (typeof value === "string") {
      return {
        omitted: true,
        reason: "debug_compact_heavy_string",
        key,
        chars: value.length,
        preview: value.length > DEBUG_MAX_STRING_LENGTH
          ? `${value.slice(0, DEBUG_MAX_STRING_LENGTH)}...`
          : value,
      };
    }
    return value;
  }

  function summarizeDebugValue(value, depth = 0, key = "") {
    if (value === undefined) return undefined;
    if (value === null || typeof value === "number" || typeof value === "boolean") return value;

    if (typeof value === "string") {
      if (DEBUG_HEAVY_KEYS.has(key) || value.length > DEBUG_MAX_STRING_LENGTH) {
        return summarizeHeavyDebugValue(key || "string", value);
      }
      return value;
    }

    if (DEBUG_HEAVY_KEYS.has(key)) {
      return summarizeHeavyDebugValue(key, value);
    }

    if (depth >= DEBUG_MAX_DEPTH) {
      if (Array.isArray(value)) {
        return {
          omitted: true,
          reason: "debug_max_depth_array",
          length: value.length,
        };
      }
      if (value && typeof value === "object") {
        const keys = Object.keys(value);
        return {
          omitted: true,
          reason: "debug_max_depth_object",
          keys: keys.slice(0, DEBUG_MAX_OBJECT_KEYS),
          omittedKeys: Math.max(0, keys.length - DEBUG_MAX_OBJECT_KEYS),
        };
      }
    }

    if (Array.isArray(value)) {
      const sample = value
        .slice(0, DEBUG_MAX_ARRAY_ITEMS)
        .map((item) => summarizeDebugValue(item, depth + 1, key));
      if (value.length <= DEBUG_MAX_ARRAY_ITEMS) return sample;
      return {
        length: value.length,
        sample,
        omittedItems: value.length - DEBUG_MAX_ARRAY_ITEMS,
      };
    }

    if (value && typeof value === "object") {
      const outObj = {};
      const entries = Object.entries(value);
      entries.slice(0, DEBUG_MAX_OBJECT_KEYS).forEach(([childKey, childValue]) => {
        outObj[childKey] = summarizeDebugValue(childValue, depth + 1, childKey);
      });
      if (entries.length > DEBUG_MAX_OBJECT_KEYS) {
        outObj.__debug_omitted_keys = entries.length - DEBUG_MAX_OBJECT_KEYS;
      }
      return outObj;
    }

    return String(value);
  }

  function summarizeDebugPayload(obj) {
    try {
      return summarizeDebugValue(obj);
    } catch (e) {
      return {
        debugSummaryError: e?.message || String(e),
      };
    }
  }

  function setOut(obj) {
    out.textContent = JSON.stringify(summarizeDebugPayload(obj), null, 2);
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

  function normalizeText(v) {
    return toStringSafe(v).toLocaleLowerCase("pt-BR");
  }

  function formatCredentialIdTimestamp(date = new Date()) {
    const pad = (n, size = 2) => String(n).padStart(size, "0");
    return [
      date.getFullYear(),
      pad(date.getMonth() + 1),
      pad(date.getDate()),
    ].join("") + "-" + [
      pad(date.getHours()),
      pad(date.getMinutes()),
      pad(date.getSeconds()),
    ].join("") + "-" + pad(date.getMilliseconds(), 3);
  }

  function normalizeCredentialIdBase(value) {
    return toStringSafe(value)
      .trim()
      .replace(CREDENTIAL_ID_TIMESTAMP_RE, "")
      .replace(/\s+/g, "-")
      .replace(/[^\p{L}\p{N}._-]/gu, "_")
      .replace(/[-_]{2,}/g, "-")
      .replace(/^[-_.]+|[-_.]+$/g, "");
  }

  function buildFinalCredentialId(value) {
    const base = normalizeCredentialIdBase(value);
    if (!base) return "";
    return `${base}-${formatCredentialIdTimestamp()}`;
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
    const el = $("#sel_receive_holder_did");
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
    $("#receive_holder_stats").textContent =
      `DIDs holder: total ${total} | filtrados ${filtered} | exibidos ${shown} (máx ${limit})`;
  }

  function applyHolderDidFilter() {
    const filterText = normalizeText($("#receive_holder_filter").value).trim();
    const limit = parseDidLimit($("#receive_holder_limit").value);
    $("#receive_holder_limit").value = String(limit);

    const filtered = filterText
      ? ownDidOptions.filter((d) => didSearchBlob(d).includes(filterText))
      : ownDidOptions;

    visibleOwnDidOptions = filtered.slice(0, limit);
    renderOwnDidOptions(visibleOwnDidOptions);
    updateDidStats(ownDidOptions.length, filtered.length, visibleOwnDidOptions.length, limit);
  }

  async function refreshDidOptions() {
    Api.setStatus("Carregando DIDs own do holder...");
    const r = await Api.did.list("own");
    setOut({ where: "credentialReceive.refreshDidOptions", resp: r });
    if (!r?.ok) {
      Api.setStatus(`Erro listando DIDs own: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    ownDidOptions = parseDidList(r);
    applyHolderDidFilter();
    Api.setStatus(`DIDs own carregados: ${ownDidOptions.length} (${visibleOwnDidOptions.length} exibidos).`);
  }

  function updateFromReceiveResult(data) {
    $("#receive_credential_file_path").value = firstNonEmpty(data?.credentialFilePath, $("#receive_credential_file_path").value);
    $("#receive_offer_file_path").value = firstNonEmpty(data?.inferredOfferFilePath, $("#receive_offer_file_path").value);
    $("#receive_holder_did").value = firstNonEmpty(data?.holderDid, $("#receive_holder_did").value);
    $("#receive_request_metadata_id").value = firstNonEmpty(data?.requestMetadataId, $("#receive_request_metadata_id").value);
    $("#receive_credential_id").value = firstNonEmpty(data?.credentialId, $("#receive_credential_id").value);
    $("#receive_creddef_id").value = firstNonEmpty(data?.credDefId);
    $("#receive_thread_id").value = firstNonEmpty(data?.threadId);
    $("#receive_kind").value = firstNonEmpty(data?.kind);
  }

  function formatCredentialAttributes(data) {
    const attrs = Array.isArray(data?.credentialAttributes) ? data.credentialAttributes : [];
    if (attrs.length) {
      return attrs
        .map((attr) => `${toStringSafe(attr?.name) || "(sem nome)"}: ${toStringSafe(attr?.value)}`)
        .join("\n");
    }

    const valuesRaw = data?.credentialValuesRaw;
    if (valuesRaw && typeof valuesRaw === "object" && !Array.isArray(valuesRaw)) {
      const entries = Object.entries(valuesRaw);
      if (entries.length) {
        return entries
          .sort(([a], [b]) => String(a).localeCompare(String(b), "pt-BR"))
          .map(([name, value]) => `${name}: ${toStringSafe(value)}`)
          .join("\n");
      }
    }

    return "Nenhum atributo foi encontrado na credencial importada.";
  }

  function setCredentialAttributes(data) {
    $("#receive_credential_attrs").value = data ? formatCredentialAttributes(data) : "";
  }

  function currentImportKey() {
    return [
      toStringSafe($("#receive_credential_file_path").value).trim(),
      toStringSafe($("#receive_holder_did").value).trim(),
      toStringSafe($("#receive_offer_file_path").value).trim(),
    ].join("|");
  }

  function setImportedCredentialPreview(data) {
    importedCredentialPreview = data
      ? {
        ...data,
        importKey: currentImportKey(),
      }
      : null;
  }

  function hasCurrentImportedCredential() {
    return !!(
      importedCredentialPreview
      && importedCredentialPreview.importKey === currentImportKey()
    );
  }

  async function importCredentialPreview() {
    const holderDid = toStringSafe($("#receive_holder_did").value).trim() || null;
    const credentialFilePath = toStringSafe($("#receive_credential_file_path").value).trim() || null;
    const offerFilePath = toStringSafe($("#receive_offer_file_path").value).trim() || null;
    const requestMetadataId = toStringSafe($("#receive_request_metadata_id").value).trim() || null;

    const input = {
      holderDid,
      credentialFilePath,
      offerFilePath,
      requestMetadataId,
    };

    Api.setStatus("Importando credencial para pré-visualização...");
    const r = await Api.credReceive.previewEnvelope(input);
    setOut({ where: "credentialReceive.previewEnvelope", input, resp: r });
    $("#receive_result").value = JSON.stringify(r, null, 2);

    if (!r?.ok) {
      setImportedCredentialPreview(null);
      setCredentialAttributes(null);
      Api.setStatus(`Erro importando credencial: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (r.data?.canceled) {
      setImportedCredentialPreview(null);
      setCredentialAttributes(null);
      Api.setStatus("Importação cancelada.");
      return;
    }

    updateFromReceiveResult(r.data || {});
    setImportedCredentialPreview(r.data || {});
    setCredentialAttributes(r.data || {});
    Api.setStatus(`Credencial importada para revisão: ${r.data?.credentialId || "(sem id sugerido)"}`);
  }

  async function saveImportedCredential() {
    const holderDid = toStringSafe($("#receive_holder_did").value).trim() || null;
    const genesisPath = toStringSafe($("#receive_genesis_path").value).trim();
    const credentialFilePath = toStringSafe($("#receive_credential_file_path").value).trim() || null;
    const offerFilePath = toStringSafe($("#receive_offer_file_path").value).trim() || null;
    const requestMetadataId = toStringSafe($("#receive_request_metadata_id").value).trim() || null;
    const credentialId = buildFinalCredentialId($("#receive_credential_id").value);

    if (!genesisPath) {
      Api.setStatus("Informe o genesis path.");
      return;
    }
    if (!credentialId) {
      Api.setStatus("Informe o Credential ID (local) antes de salvar.");
      return;
    }
    if (!hasCurrentImportedCredential()) {
      Api.setStatus("Importe a credencial antes de salvar ou reimporte após alterar arquivo, Holder ou oferta.");
      return;
    }
    $("#receive_credential_id").value = credentialId;

    const input = {
      holderDid,
      genesisPath,
      credentialFilePath,
      offerFilePath,
      requestMetadataId,
      credentialId,
    };

    Api.setStatus("Salvando credencial na wallet do holder...");
    const r = await Api.credReceive.importAndStoreEnvelope(input);
    setOut({ where: "credentialReceive.importAndStoreEnvelope", input, resp: r });
    $("#receive_result").value = JSON.stringify(r, null, 2);

    if (!r?.ok) {
      Api.setStatus(`Erro recebendo credencial: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (r.data?.canceled) {
      Api.setStatus("Importação cancelada.");
      return;
    }

    updateFromReceiveResult(r.data || {});
    if (r.data?.alreadyStored) {
      Api.setStatus(`Credencial já estava armazenada na wallet: ${r.data?.credentialId || "(sem id)"}`);
    } else {
      Api.setStatus(`Credencial salva com sucesso: ${r.data?.credentialId || "(sem id)"}`);
    }
  }

  function invalidateImportedCredentialPreview() {
    setImportedCredentialPreview(null);
    setCredentialAttributes(null);
  }

  $("#btn_receive_refresh_dids").addEventListener("click", refreshDidOptions);
  $("#btn_receive_import_preview").addEventListener("click", importCredentialPreview);
  $("#btn_receive_store").addEventListener("click", saveImportedCredential);
  $("#receive_holder_filter").addEventListener("input", applyHolderDidFilter);
  $("#receive_holder_filter").addEventListener("keyup", applyHolderDidFilter);
  $("#receive_holder_limit").addEventListener("input", applyHolderDidFilter);
  $("#receive_holder_limit").addEventListener("change", applyHolderDidFilter);
  $("#receive_holder_did").addEventListener("input", invalidateImportedCredentialPreview);
  $("#receive_credential_file_path").addEventListener("input", invalidateImportedCredentialPreview);
  $("#receive_offer_file_path").addEventListener("input", invalidateImportedCredentialPreview);
  $("#btn_receive_holder_clear_filter").addEventListener("click", () => {
    $("#receive_holder_filter").value = "";
    applyHolderDidFilter();
  });
  $("#sel_receive_holder_did").addEventListener("change", () => {
    const did = toStringSafe($("#sel_receive_holder_did").value).trim();
    if (did) {
      $("#receive_holder_did").value = did;
      invalidateImportedCredentialPreview();
    }
  });

  refreshDidOptions().catch(() => {});
  return {};
})();
