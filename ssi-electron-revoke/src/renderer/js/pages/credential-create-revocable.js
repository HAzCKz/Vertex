// src/renderer/js/pages/credential-create-revocable.js
/* eslint-disable no-console */

const CredentialCreateRevocablePage = (() => {
  const root = document.getElementById("page-credential-create-revocable");
  if (!root) return {};

  const DEFAULT_DID_LIMIT = 150;
  const MAX_DID_LIMIT = 1000;
  const DEFAULT_EXTRA_WINDOWS_FOR_FP = 10;
  const DEFAULT_MANIFEST_URL = "http://127.0.0.1:8080/manifest";
  const CONTROL_ATTRIBUTE_CANONICAL_NAMES = [
    "root_merkle_L",
    "seed",
    "start_time",
    "time_window",
    "unit_of_time",
  ];
  const CONTROL_ATTRIBUTE_ALIASES = new Set([
    "root_merkle_l",
    ...CONTROL_ATTRIBUTE_CANONICAL_NAMES,
  ]);
  const CONTROL_ATTRIBUTE_KEYS = new Set(
    CONTROL_ATTRIBUTE_CANONICAL_NAMES.map((name) => normalizeControlAttributeKey(name))
  );

  let ownDidOptions = [];
  let visibleOwnDidOptions = [];
  let importedRequest = null;
  let revocableSchemaValidation = {
    genesisPath: "",
    credDefId: "",
    checked: false,
    ok: false,
    attrNames: [],
    missingAttrs: CONTROL_ATTRIBUTE_CANONICAL_NAMES.slice(),
  };
  let revocationSetupState = {
    issuerDid: "",
    kSetup: null,
    kWrite: null,
    ledgerSetup: null,
    manifestWrite: null,
  };

  root.innerHTML = `
    <div class="card">
      <h2>Criar Credencial Revogável</h2>
      <p class="small">
        Mantém o fluxo atual intacto e cria um envelope específico para credencial revogável,
        incluindo o bundle do holder com as janelas de revogação. O protocolo usa
        <strong>${DEFAULT_EXTRA_WINDOWS_FOR_FP} janelas extras fixas</strong> para descarte prático de falso positivo.
      </p>

      <div class="row">
        <button class="secondary" id="btn_create_rev_refresh_dids">Atualizar DIDs emissor</button>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>1) Emissor</h3>

      <div class="row">
        <div class="input" style="min-width:340px">
          <label>DID emissor (lista own)</label>
          <select id="sel_create_rev_issuer_did">
            <option value="">-- selecione um DID --</option>
          </select>
        </div>

        <div class="input" style="min-width:420px">
          <label>DID emissor (manual)</label>
          <input id="create_rev_issuer_did" placeholder="ex.: did do emissor" />
        </div>
      </div>
      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de DIDs</label>
          <input id="create_rev_issuer_filter" placeholder="Filtrar por DID, alias ou verkey..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="create_rev_issuer_limit" type="number" min="1" max="${MAX_DID_LIMIT}" value="${DEFAULT_DID_LIMIT}" />
        </div>
        <button class="secondary" id="btn_create_rev_issuer_clear_filter">Limpar filtro</button>
      </div>
      <p class="small" id="create_rev_issuer_stats">DIDs emissor: 0</p>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>2) Importar aceite (request)</h3>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Arquivo do request (.env.json)</label>
          <input id="create_rev_request_file_path" placeholder="vazio = escolher no diálogo" />
        </div>
        <button class="secondary" id="btn_create_rev_import_request">Importar aceite</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Arquivo da oferta (opcional, fallback)</label>
          <input id="create_rev_offer_file_path" placeholder="ex.: /caminho/cred_offer.env.json" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:320px">
          <label>CredDef ID</label>
          <input id="create_rev_creddef_id" />
        </div>
        <div class="input" style="min-width:320px">
          <label>Holder DID (hint)</label>
          <input id="create_rev_holder_did_hint" readonly />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Holder verkey (destino do envelope)</label>
          <input id="create_rev_holder_verkey" placeholder="se vazio, tenta inferir do request envelope" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:280px">
          <label>Thread ID</label>
          <input id="create_rev_thread_id" />
        </div>
        <div class="input" style="min-width:220px">
          <label>Nonce</label>
          <input id="create_rev_request_nonce" readonly />
        </div>
        <div class="input" style="min-width:280px">
          <label>Offer encontrada</label>
          <input id="create_rev_offer_matched" readonly />
        </div>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>3) Dados da credencial</h3>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Genesis path</label>
          <input id="create_rev_genesis_path" placeholder="/caminho/para/genesis.txn" />
        </div>
        <button class="secondary" id="btn_create_rev_load_schema">Carregar atributos do schema</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:420px">
          <label>ID local da credencial do emissor</label>
          <input id="create_rev_local_credential_id" placeholder="vazio = gerar automaticamente" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Valores editáveis da credencial (JSON objeto)</label>
          <textarea id="create_rev_values_json" rows="10" placeholder='{"nome":"Alice","cpf":"12345678900","idade":"29"}'></textarea>
        </div>
      </div>
      <p class="small">
        Os atributos de controle de revogação são preenchidos automaticamente pelo sistema e não aparecem neste JSON:
        <code>${CONTROL_ATTRIBUTE_CANONICAL_NAMES.join("</code>, <code>")}</code>.
      </p>
      <div
        id="create_rev_schema_warning"
        class="small"
        style="display:none; margin:10px 0 16px; padding:12px; border:1px solid #dc2626; border-radius:8px; background:#fef2f2; color:#991b1b; white-space:pre-wrap;"
      ></div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>4) Preparar revogação no ledger</h3>

      <p class="small">
        Antes de emitir, o emissor precisa publicar o vetor <code>K</code> e ancorar o manifesto
        no ledger. O <code>root_merkle_L</code> da credencial será derivado a partir desse setup.
      </p>

      <div class="row">
        <button class="secondary" id="btn_create_rev_load_ledger_setup">Ler setup atual do ledger</button>
        <button class="secondary" id="btn_create_rev_generate_k">Gerar vetor K</button>
        <button class="secondary" id="btn_create_rev_publish_k">Publicar K no ledger</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:280px">
          <label>K vector ID (automático)</label>
          <input id="create_rev_k_vector_id" readonly />
        </div>
        <div class="input" style="min-width:320px">
          <label>Hash do vetor K</label>
          <input id="create_rev_k_vector_hash" readonly />
        </div>
        <div class="input" style="min-width:260px">
          <label>Status do K</label>
          <input id="create_rev_k_status" readonly />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Manifest URL</label>
          <input id="create_rev_manifest_url" placeholder="${DEFAULT_MANIFEST_URL}" />
        </div>
        <div class="input" style="min-width:160px">
          <label>Manifest version</label>
          <input id="create_rev_manifest_version" value="1" />
        </div>
        <button class="secondary" id="btn_create_rev_anchor_manifest">Ancorar manifesto no ledger</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:420px">
          <label>Status do manifesto</label>
          <input id="create_rev_manifest_status" readonly />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Manifest anchor (gerado automaticamente)</label>
          <textarea id="create_rev_manifest_json" rows="4" readonly></textarea>
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Resumo do setup de revogação</label>
          <textarea id="create_rev_setup_json" rows="8" readonly></textarea>
        </div>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>5) Configuração da validade</h3>

      <div class="row">
        <div class="input" style="min-width:220px">
          <label>Início da validade (DD/MM/AAAA)</label>
          <input id="create_rev_start_date" placeholder="ex.: 01/04/2026" />
        </div>
        <div class="input" style="min-width:180px">
          <label>Hora inicial (HH:mm:ss)</label>
          <input id="create_rev_start_time_text" placeholder="ex.: 14:30:00" />
        </div>
        <div class="input" style="min-width:220px">
          <label>Fim da validade (calculado)</label>
          <input id="create_rev_validity_end_display" readonly />
        </div>
        <div class="input" style="min-width:220px">
          <label>Unidade de tempo</label>
          <select id="create_rev_unit_of_time">
            <option value="days" selected>days</option>
            <option value="weeks">weeks</option>
            <option value="months">months</option>
            <option value="years">years</option>
            <option value="hours">hours</option>
            <option value="minutes">minutes</option>
            <option value="seconds">seconds</option>
            <option value="decades">decades</option>
          </select>
        </div>
        <div class="input" style="min-width:220px">
          <label>Tamanho de cada janela</label>
          <input id="create_rev_time_window" type="number" min="1" value="1" />
        </div>
        <div class="input" style="min-width:220px">
          <label>Quantidade de janelas válidas</label>
          <input id="create_rev_valid_window_count" type="number" min="1" value="365" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:220px">
          <label>Janelas extras p/ FP</label>
          <input id="create_rev_extra_windows" value="${DEFAULT_EXTRA_WINDOWS_FOR_FP}" readonly />
        </div>
        <div class="input" style="min-width:460px">
          <label>Conversão interna</label>
          <input id="create_rev_internal_range" readonly />
        </div>
      </div>

      <p class="small">
        Exemplo: para uma credencial válida por 365 dias com verificação diária, use
        <code>Unidade de tempo = days</code>, <code>Tamanho de cada janela = 1</code> e
        <code>Quantidade de janelas válidas = 365</code>.
      </p>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>6) Exportar envelope revogável</h3>

      <div class="row">
        <div class="input" style="min-width:280px">
          <label>Kind</label>
          <input id="create_rev_credential_kind" value="anoncreds/revocable-credential-package-v2" />
        </div>
        <div class="input" style="min-width:220px">
          <label>ExpiresAt (epoch ms)</label>
          <input id="create_rev_expires_at" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Meta JSON (opcional)</label>
          <textarea id="create_rev_meta_json" rows="4" placeholder='{"kind":"cpf-revogavel"}'></textarea>
        </div>
      </div>

      <div class="row">
        <button class="primary" id="btn_create_rev_export_credential">Emitir e Exportar Credencial Revogável</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Resultado</label>
          <textarea id="create_rev_result" rows="12" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="create_rev_out">{}</pre>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#create_rev_out");

  function setOut(obj) {
    out.textContent = JSON.stringify(obj, null, 2);
  }

  function toStringSafe(v) {
    if (v === undefined || v === null) return "";
    return String(v);
  }

  function getGenesisPathValue() {
    return firstNonEmpty(
      toStringSafe($("#create_rev_genesis_path")?.value).trim(),
      window.AppState?.genesisPath
    );
  }

  function getIssuerDidValue() {
    return firstNonEmpty(
      toStringSafe($("#create_rev_issuer_did")?.value).trim(),
      toStringSafe($("#sel_create_rev_issuer_did")?.value).trim()
    );
  }

  function resetRevocationSetupState(nextIssuerDid = "") {
    revocationSetupState = {
      issuerDid: toStringSafe(nextIssuerDid).trim(),
      kSetup: null,
      kWrite: null,
      ledgerSetup: null,
      manifestWrite: null,
    };
    $("#create_rev_k_vector_id").value = "";
    $("#create_rev_k_vector_hash").value = "";
    $("#create_rev_k_status").value = "";
    $("#create_rev_manifest_status").value = "";
    $("#create_rev_manifest_json").value = "";
    $("#create_rev_setup_json").value = "";
  }

  function ensureSetupIssuerState() {
    const issuerDid = getIssuerDidValue();
    const currentIssuerDid = toStringSafe(revocationSetupState.issuerDid).trim();
    if (currentIssuerDid && issuerDid !== currentIssuerDid) {
      resetRevocationSetupState(issuerDid);
    } else if (!currentIssuerDid && issuerDid) {
      revocationSetupState.issuerDid = issuerDid;
    }
    return issuerDid;
  }

  function getResolvedKAnchor() {
    return (
      revocationSetupState.kWrite?.ledger_anchor
      || revocationSetupState.ledgerSetup?.activeKAnchor
      || null
    );
  }

  function getResolvedKVector() {
    return (
      revocationSetupState.kSetup?.k_vector
      || revocationSetupState.ledgerSetup?.activeKVector
      || null
    );
  }

  function getResolvedManifest() {
    return (
      revocationSetupState.manifestWrite?.manifest
      || revocationSetupState.ledgerSetup?.manifest
      || null
    );
  }

  function updateRevocationSetupPreview() {
    const issuerDid = ensureSetupIssuerState();
    const kAnchor = getResolvedKAnchor();
    const kVector = getResolvedKVector();
    const manifest = getResolvedManifest();
    const kVectorId = firstNonEmpty(kAnchor?.k_vector_id, kVector?.k_vector_id);
    const kHash = firstNonEmpty(kAnchor?.vector_hash, kVector?.vector_hash);
    const manifestUrl = firstNonEmpty(manifest?.manifest_url, $("#create_rev_manifest_url").value, DEFAULT_MANIFEST_URL);
    const manifestVersion = firstNonEmpty(manifest?.manifest_version, $("#create_rev_manifest_version").value, "1");

    $("#create_rev_k_vector_id").value = kVectorId;
    $("#create_rev_k_vector_hash").value = kHash;
    $("#create_rev_k_status").value = kVectorId
      ? (revocationSetupState.kWrite?.ledger_anchor || revocationSetupState.ledgerSetup?.activeKAnchor
        ? "Publicado no ledger"
        : "Gerado localmente")
      : "Pendente";
    $("#create_rev_manifest_status").value = manifest?.manifest_url
      ? `Ancorado no ledger (${manifest.manifest_version || "1"})`
      : "Pendente";
    $("#create_rev_manifest_url").value = manifestUrl;
    $("#create_rev_manifest_version").value = manifestVersion;
    $("#create_rev_manifest_json").value = manifest ? JSON.stringify(manifest, null, 2) : "";

    const summary = {
      issuerDid: issuerDid || null,
      ready: !!(kVectorId && manifest?.manifest_url),
      activeKAttrKey: "REVOCATION_K_ACTIVE",
      manifestAttrKey: "REVOCATION_MANIFEST",
      kVectorId: kVectorId || null,
      kVectorHash: kHash || null,
      chunkCount: kAnchor?.chunk_count ?? null,
      kWrittenOnLedger: !!(revocationSetupState.kWrite?.ledger_anchor || revocationSetupState.ledgerSetup?.activeKAnchor),
      manifestUrl: manifest?.manifest_url || null,
      manifestVersion: manifest?.manifest_version || null,
      manifestUpdatedAt: manifest?.updated_at || null,
    };
    $("#create_rev_setup_json").value = JSON.stringify(summary, null, 2);
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

  function firstNonEmpty(...values) {
    for (const v of values) {
      const s = toStringSafe(v).trim();
      if (s) return s;
    }
    return "";
  }

  function normalizeControlAttributeKey(name) {
    return toStringSafe(name).trim().toLocaleLowerCase("pt-BR");
  }

  function getMissingControlAttributes(attrNames) {
    const found = new Set(
      (Array.isArray(attrNames) ? attrNames : [])
        .map((name) => normalizeControlAttributeKey(name))
        .filter(Boolean)
    );
    return CONTROL_ATTRIBUTE_CANONICAL_NAMES.filter((name) => !found.has(normalizeControlAttributeKey(name)));
  }

  function hasAllControlAttributes(attrNames) {
    const found = new Set(
      (Array.isArray(attrNames) ? attrNames : [])
        .map((name) => normalizeControlAttributeKey(name))
        .filter(Boolean)
    );
    return Array.from(CONTROL_ATTRIBUTE_KEYS).every((name) => found.has(name));
  }

  function buildMissingControlAttributesWarning(missingAttrs) {
    const missing = Array.isArray(missingAttrs) && missingAttrs.length
      ? missingAttrs.join(", ")
      : CONTROL_ATTRIBUTE_CANONICAL_NAMES.join(", ");
    return [
      "Aviso: a estrutura desta credencial não contém todos os atributos de controle de uma credencial revogável.",
      `Atributos de controle não encontrados: ${missing}.`,
      "A emissão pelo menu \"Criar Credencial Revogável\" foi bloqueada. Use este menu apenas para credenciais com seed, start_time, time_window, unit_of_time e root_merkle_L.",
    ].join("\n");
  }

  function showMissingControlAttributesWarning(missingAttrs) {
    const message = buildMissingControlAttributesWarning(missingAttrs);
    const el = $("#create_rev_schema_warning");
    if (el) {
      el.textContent = message;
      el.style.display = "block";
    }
    Api.setStatus(message);
    return message;
  }

  function clearMissingControlAttributesWarning() {
    const el = $("#create_rev_schema_warning");
    if (el) {
      el.textContent = "";
      el.style.display = "none";
    }
  }

  function rememberRevocableSchemaValidation(genesisPath, credDefId, attrNames) {
    const safeAttrNames = Array.isArray(attrNames) ? attrNames.map(String) : [];
    const missingAttrs = getMissingControlAttributes(safeAttrNames);
    revocableSchemaValidation = {
      genesisPath: toStringSafe(genesisPath).trim(),
      credDefId: toStringSafe(credDefId).trim(),
      checked: true,
      ok: hasAllControlAttributes(safeAttrNames),
      attrNames: safeAttrNames,
      missingAttrs,
    };
    return revocableSchemaValidation;
  }

  function resetRevocableSchemaValidation() {
    revocableSchemaValidation = {
      genesisPath: "",
      credDefId: "",
      checked: false,
      ok: false,
      attrNames: [],
      missingAttrs: CONTROL_ATTRIBUTE_CANONICAL_NAMES.slice(),
    };
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

  function parsePositiveInteger(value, label) {
    const raw = toStringSafe(value).trim();
    if (!raw) return null;
    const parsed = Number(raw);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      throw new Error(`${label} inválido.`);
    }
    return Math.trunc(parsed);
  }

  function sanitizeCredentialValuesObj(valuesObj) {
    if (!valuesObj || typeof valuesObj !== "object" || Array.isArray(valuesObj)) {
      return { sanitized: {}, removedKeys: [] };
    }
    const sanitized = {};
    const removedKeys = new Set();
    Object.entries(valuesObj).forEach(([key, value]) => {
      if (CONTROL_ATTRIBUTE_ALIASES.has(String(key))) {
        removedKeys.add(String(key) === "root_merkle_l" ? "root_merkle_L" : String(key));
        return;
      }
      sanitized[key] = value;
    });
    return { sanitized, removedKeys: Array.from(removedKeys) };
  }

  function parsePtBrDateTimeToLocal(dateText, timeText) {
    const rawDate = toStringSafe(dateText).trim();
    const rawTime = toStringSafe(timeText).trim();
    const dateMatch = rawDate.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
    const timeMatch = rawTime.match(/^(\d{2}):(\d{2}):(\d{2})$/);
    if (!dateMatch) {
      throw new Error("Início da validade inválido. Use o formato DD/MM/AAAA.");
    }
    if (!timeMatch) {
      throw new Error("Hora inicial inválida. Use o formato HH:mm:ss.");
    }
    const day = Number(dateMatch[1]);
    const month = Number(dateMatch[2]);
    const year = Number(dateMatch[3]);
    const hours = Number(timeMatch[1]);
    const minutes = Number(timeMatch[2]);
    const seconds = Number(timeMatch[3]);
    if (
      !Number.isFinite(hours) || hours < 0 || hours > 23
      || !Number.isFinite(minutes) || minutes < 0 || minutes > 59
      || !Number.isFinite(seconds) || seconds < 0 || seconds > 59
    ) {
      throw new Error("Hora inicial inválida.");
    }
    const date = new Date(year, month - 1, day, hours, minutes, seconds, 0);
    if (
      date.getFullYear() !== year
      || date.getMonth() !== month - 1
      || date.getDate() !== day
      || date.getHours() !== hours
      || date.getMinutes() !== minutes
      || date.getSeconds() !== seconds
    ) {
      throw new Error("Data/hora de início inválida.");
    }
    return {
      date,
      epochSeconds: Math.trunc(date.getTime() / 1000),
    };
  }

  function formatLocalDate(date) {
    return `${pad2(date.getDate())}/${pad2(date.getMonth() + 1)}/${date.getFullYear()}`;
  }

  function formatLocalTime(date) {
    return `${pad2(date.getHours())}:${pad2(date.getMinutes())}:${pad2(date.getSeconds())}`;
  }

  function fillCurrentValidityStartDefaults() {
    const now = new Date();
    $("#create_rev_start_date").value = formatLocalDate(now);
    $("#create_rev_start_time_text").value = formatLocalTime(now);
  }

  function parsePtBrDateToUtc(dateText) {
    const raw = toStringSafe(dateText).trim();
    const match = raw.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
    if (!match) {
      throw new Error("Início da validade inválido. Use o formato DD/MM/AAAA.");
    }
    const day = Number(match[1]);
    const month = Number(match[2]);
    const year = Number(match[3]);
    const ms = Date.UTC(year, month - 1, day, 0, 0, 0, 0);
    const date = new Date(ms);
    if (
      date.getUTCFullYear() !== year
      || date.getUTCMonth() !== month - 1
      || date.getUTCDate() !== day
    ) {
      throw new Error("Data de início inválida.");
    }
    return {
      date,
      epochSeconds: Math.trunc(ms / 1000),
    };
  }

  function pad2(value) {
    return String(value).padStart(2, "0");
  }

  function formatUtcDate(date) {
    return `${pad2(date.getUTCDate())}/${pad2(date.getUTCMonth() + 1)}/${date.getUTCFullYear()}`;
  }

  function formatUtcDateTime(date) {
    return `${formatUtcDate(date)} ${pad2(date.getUTCHours())}:${pad2(date.getUTCMinutes())}:${pad2(date.getUTCSeconds())} UTC`;
  }

  function addUnitsUtc(baseDate, unitOfTime, amount) {
    const date = new Date(baseDate.getTime());
    switch (String(unitOfTime || "").trim().toLowerCase()) {
      case "second":
      case "seconds":
        date.setUTCSeconds(date.getUTCSeconds() + amount);
        return date;
      case "minute":
      case "minutes":
        date.setUTCMinutes(date.getUTCMinutes() + amount);
        return date;
      case "hour":
      case "hours":
        date.setUTCHours(date.getUTCHours() + amount);
        return date;
      case "day":
      case "days":
        date.setUTCDate(date.getUTCDate() + amount);
        return date;
      case "week":
      case "weeks":
        date.setUTCDate(date.getUTCDate() + (amount * 7));
        return date;
      case "month":
      case "months":
        date.setUTCMonth(date.getUTCMonth() + amount);
        return date;
      case "year":
      case "years":
        date.setUTCFullYear(date.getUTCFullYear() + amount);
        return date;
      case "decade":
      case "decades":
        date.setUTCFullYear(date.getUTCFullYear() + (amount * 10));
        return date;
      default:
        throw new Error("Unidade de tempo inválida.");
    }
  }

  function computeValidityRange() {
    const startDateRaw = toStringSafe($("#create_rev_start_date").value).trim();
    const startTimeRaw = toStringSafe($("#create_rev_start_time_text").value).trim();
    const unitOfTime = toStringSafe($("#create_rev_unit_of_time").value).trim();
    const timeWindow = parsePositiveInteger($("#create_rev_time_window").value, "Tamanho de cada janela");
    const validWindowCount = parsePositiveInteger(
      $("#create_rev_valid_window_count").value,
      "Quantidade de janelas válidas"
    );

    if (!startDateRaw || !startTimeRaw || !unitOfTime || !timeWindow || !validWindowCount) {
      $("#create_rev_validity_end_display").value = "";
      $("#create_rev_internal_range").value = "";
      return null;
    }

    const start = parsePtBrDateTimeToLocal(startDateRaw, startTimeRaw);
    const totalUnits = Math.trunc(timeWindow) * Math.trunc(validWindowCount);
    const nextBoundary = addUnitsUtc(start.date, unitOfTime, totalUnits);
    const nextBoundaryEpoch = Math.trunc(nextBoundary.getTime() / 1000);
    const validityEndEpoch = nextBoundaryEpoch - 1;
    if (!Number.isFinite(validityEndEpoch) || validityEndEpoch < start.epochSeconds) {
      throw new Error("Não foi possível calcular o fim da validade.");
    }
    const validityEndDate = new Date(validityEndEpoch * 1000);

    $("#create_rev_validity_end_display").value = formatUtcDateTime(validityEndDate);
    $("#create_rev_internal_range").value =
      `start_time=${start.epochSeconds} | validity_end=${validityEndEpoch} | base_window_count=${Math.trunc(validWindowCount)} | total_window_units=${totalUnits}`;

    return {
      startTime: start.epochSeconds,
      validityEnd: validityEndEpoch,
      validWindowCount: Math.trunc(validWindowCount),
    };
  }

  function refreshValidityPreview() {
    try {
      computeValidityRange();
    } catch (_) {
      $("#create_rev_validity_end_display").value = "";
      $("#create_rev_internal_range").value = "";
    }
  }

  function didSearchBlob(d) {
    return normalizeText([
      d.did,
      d.alias,
      d.verkey,
      d.verKey,
    ].filter(Boolean).join(" "));
  }

  function renderDidOptions(items) {
    const el = $("#sel_create_rev_issuer_did");
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
    $("#create_rev_issuer_stats").textContent =
      `DIDs emissor: total ${total} | filtrados ${filtered} | exibidos ${shown} (máx ${limit})`;
  }

  function applyIssuerDidFilter() {
    const filterText = normalizeText($("#create_rev_issuer_filter").value).trim();
    const limit = parseDidLimit($("#create_rev_issuer_limit").value);
    $("#create_rev_issuer_limit").value = String(limit);

    const filtered = filterText
      ? ownDidOptions.filter((d) => didSearchBlob(d).includes(filterText))
      : ownDidOptions;

    visibleOwnDidOptions = filtered.slice(0, limit);
    renderDidOptions(visibleOwnDidOptions);
    updateDidStats(ownDidOptions.length, filtered.length, visibleOwnDidOptions.length, limit);
  }

  async function refreshDids() {
    Api.setStatus("Carregando DIDs own do emissor para credencial revogável...");
    const r = await Api.did.list("own");
    setOut({ where: "credentialCreateRevocable.refreshDids", resp: r });
    if (!r?.ok) {
      Api.setStatus(`Erro listando DIDs: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }
    ownDidOptions = parseDidList(r);
    applyIssuerDidFilter();
    Api.setStatus(`DIDs emissor carregados: ${ownDidOptions.length} (${visibleOwnDidOptions.length} exibidos).`);
  }

  function updateFromImportedRequest(data) {
    $("#create_rev_request_file_path").value = firstNonEmpty(data?.requestFilePath, data?.filePath);
    const matchedOfferPath = firstNonEmpty(data?.offerFilePathMatched);
    if (matchedOfferPath) {
      $("#create_rev_offer_file_path").value = matchedOfferPath;
    } else if (Array.isArray(data?.offerCandidatesChecked) && data.offerCandidatesChecked.length > 0) {
      const candidate = firstNonEmpty(data.offerCandidatesChecked[0]);
      $("#create_rev_offer_file_path").value = candidate || "";
    } else {
      $("#create_rev_offer_file_path").value = "";
    }
    $("#create_rev_issuer_did").value = firstNonEmpty(data?.issuerDidResolved, $("#create_rev_issuer_did").value);
    $("#create_rev_creddef_id").value = firstNonEmpty(data?.credDefId, $("#create_rev_creddef_id").value);
    $("#create_rev_holder_did_hint").value = firstNonEmpty(data?.holderDidHint);
    $("#create_rev_holder_verkey").value = firstNonEmpty(data?.holderVerkeyHint, $("#create_rev_holder_verkey").value);
    $("#create_rev_thread_id").value = firstNonEmpty(data?.threadId, $("#create_rev_thread_id").value);
    $("#create_rev_request_nonce").value = firstNonEmpty(data?.requestNonce);
    const offerTxt = data?.offerMatched ? `sim (${firstNonEmpty(data?.offerMatchSource, "desconhecido")})` : "não";
    $("#create_rev_offer_matched").value = offerTxt;
    ensureSetupIssuerState();
    updateRevocationSetupPreview();
  }

  function getRevocationSetupBaseInput() {
    const genesisPath = getGenesisPathValue();
    const issuerDid = ensureSetupIssuerState();
    if (genesisPath && toStringSafe($("#create_rev_genesis_path").value).trim() !== genesisPath) {
      $("#create_rev_genesis_path").value = genesisPath;
    }
    if (!genesisPath) {
      Api.setStatus("Informe Genesis path.");
      return null;
    }
    if (!issuerDid) {
      Api.setStatus("Informe o DID emissor.");
      return null;
    }
    return { genesisPath, issuerDid };
  }

  async function generateKVector() {
    const base = getRevocationSetupBaseInput();
    if (!base) return;

    Api.setStatus("Gerando vetor K localmente...");
    const r = await Api.credCreateRevocable.setupKVector(base);
    setOut({ where: "credentialCreateRevocable.setupKVector", input: base, resp: r });
    $("#create_rev_result").value = JSON.stringify(r, null, 2);

    if (!r?.ok) {
      Api.setStatus(`Erro gerando vetor K: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    revocationSetupState.issuerDid = base.issuerDid;
    revocationSetupState.kSetup = r.data || null;
    if (r.data?.ledger_anchor || r.data?.k_vector) {
      revocationSetupState.ledgerSetup = {
        ...(revocationSetupState.ledgerSetup || {}),
        issuerDid: base.issuerDid,
        activeKAttrKey: "REVOCATION_K_ACTIVE",
        manifestAttrKey: "REVOCATION_MANIFEST",
        activeKAnchor: r.data?.ledger_anchor || revocationSetupState.ledgerSetup?.activeKAnchor || null,
        activeKVector: r.data?.k_vector || revocationSetupState.ledgerSetup?.activeKVector || null,
        manifest: r.data?.manifest || getResolvedManifest(),
        ready: !!(
          firstNonEmpty(
            r.data?.ledger_anchor?.k_vector_id,
            revocationSetupState.ledgerSetup?.activeKAnchor?.k_vector_id
          )
          && firstNonEmpty(
            r.data?.manifest?.manifest_url,
            getResolvedManifest()?.manifest_url
          )
        ),
      };
    }
    updateRevocationSetupPreview();
    if (r.data?.reusedFromLedger) {
      Api.setStatus(`Vetor K já existente no ledger reutilizado: ${firstNonEmpty(r.data?.k_vector?.k_vector_id, "sem id")}.`);
      return;
    }
    Api.setStatus(`Vetor K gerado: ${firstNonEmpty(r.data?.k_vector?.k_vector_id, "sem id")}.`);
  }

  async function publishKVectorOnLedger() {
    const base = getRevocationSetupBaseInput();
    if (!base) return;

    const kVectorObj = revocationSetupState.kSetup?.k_vector || revocationSetupState.ledgerSetup?.activeKVector;
    if (!kVectorObj) {
      Api.setStatus("Gere ou carregue o vetor K antes de publicar no ledger.");
      return;
    }

    Api.setStatus("Publicando vetor K no ledger...");
    const r = await Api.credCreateRevocable.writeKVectorOnLedger({
      genesisPath: base.genesisPath,
      issuerDid: base.issuerDid,
      kVectorObj,
    });
    setOut({
      where: "credentialCreateRevocable.writeKVectorOnLedger",
      input: { ...base, kVectorId: kVectorObj.k_vector_id || null },
      resp: r,
    });
    $("#create_rev_result").value = JSON.stringify(r, null, 2);

    if (!r?.ok) {
      Api.setStatus(`Erro publicando vetor K: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    revocationSetupState.issuerDid = base.issuerDid;
    revocationSetupState.kWrite = r.data || null;
    revocationSetupState.ledgerSetup = {
      ...(revocationSetupState.ledgerSetup || {}),
      issuerDid: base.issuerDid,
      activeKAttrKey: "REVOCATION_K_ACTIVE",
      manifestAttrKey: "REVOCATION_MANIFEST",
      activeKAnchor: r.data?.ledger_anchor || null,
      activeKVector: kVectorObj,
      manifest: getResolvedManifest(),
      ready: !!(r.data?.ledger_anchor?.k_vector_id && getResolvedManifest()?.manifest_url),
    };
    updateRevocationSetupPreview();
    if (r.data?.reusedExisting) {
      Api.setStatus(`Vetor K já estava publicado no ledger: ${firstNonEmpty(r.data?.ledger_anchor?.k_vector_id, "sem id")}.`);
      return;
    }
    Api.setStatus(`Vetor K publicado no ledger: ${firstNonEmpty(r.data?.ledger_anchor?.k_vector_id, "sem id")}.`);
  }

  async function anchorManifestOnLedger() {
    const base = getRevocationSetupBaseInput();
    if (!base) return;

    const manifestUrl = firstNonEmpty(
      toStringSafe($("#create_rev_manifest_url").value).trim(),
      DEFAULT_MANIFEST_URL
    );
    const manifestVersion = firstNonEmpty(
      toStringSafe($("#create_rev_manifest_version").value).trim(),
      "1"
    );

    Api.setStatus("Lendo manifesto e ancorando no ledger...");
    const r = await Api.credCreateRevocable.anchorManifestOnLedger({
      genesisPath: base.genesisPath,
      issuerDid: base.issuerDid,
      manifestUrl,
      manifestVersion,
    });
    setOut({
      where: "credentialCreateRevocable.anchorManifestOnLedger",
      input: { ...base, manifestUrl, manifestVersion },
      resp: r,
    });
    $("#create_rev_result").value = JSON.stringify(r, null, 2);

    if (!r?.ok) {
      Api.setStatus(`Erro ancorando manifesto: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    revocationSetupState.issuerDid = base.issuerDid;
    revocationSetupState.manifestWrite = r.data || null;
    revocationSetupState.ledgerSetup = {
      ...(revocationSetupState.ledgerSetup || {}),
      issuerDid: base.issuerDid,
      activeKAttrKey: "REVOCATION_K_ACTIVE",
      manifestAttrKey: "REVOCATION_MANIFEST",
      activeKAnchor: getResolvedKAnchor(),
      activeKVector: getResolvedKVector(),
      manifest: r.data?.manifest || null,
      ready: !!(getResolvedKAnchor()?.k_vector_id && r.data?.manifest?.manifest_url),
    };
    updateRevocationSetupPreview();
    Api.setStatus(`Manifesto ancorado no ledger: ${firstNonEmpty(r.data?.manifest?.manifest_url, manifestUrl)}.`);
  }

  async function loadLedgerSetup() {
    const base = getRevocationSetupBaseInput();
    if (!base) return;

    Api.setStatus("Lendo setup de revogação atual do ledger...");
    const r = await Api.credCreateRevocable.readLedgerSetup(base);
    setOut({ where: "credentialCreateRevocable.readLedgerSetup", input: base, resp: r });
    $("#create_rev_result").value = JSON.stringify(r, null, 2);

    if (!r?.ok) {
      Api.setStatus(`Erro lendo setup do ledger: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    revocationSetupState.issuerDid = base.issuerDid;
    revocationSetupState.ledgerSetup = r.data || null;
    updateRevocationSetupPreview();
    if (r.data?.ready) {
      Api.setStatus("Setup de revogação carregado do ledger.");
    } else {
      Api.setStatus("Setup lido do ledger, mas ainda está incompleto.");
    }
  }

  async function ensureRevocationSetupReadyForExport() {
    const manifest = getResolvedManifest();
    const kAnchor = getResolvedKAnchor();
    if (manifest?.manifest_url && kAnchor?.k_vector_id) {
      return {
        manifest,
        kVectorId: kAnchor.k_vector_id,
        kLedgerAnchorObj: kAnchor,
      };
    }

    const base = getRevocationSetupBaseInput();
    if (!base) return null;

    const r = await Api.credCreateRevocable.readLedgerSetup(base);
    setOut({ where: "credentialCreateRevocable.ensureRevocationSetupReadyForExport", input: base, resp: r });
    if (!r?.ok) {
      Api.setStatus(`Erro lendo setup do ledger: ${r?.error?.message || "erro desconhecido"}`);
      return null;
    }
    revocationSetupState.issuerDid = base.issuerDid;
    revocationSetupState.ledgerSetup = r.data || null;
    updateRevocationSetupPreview();

    const resolvedManifest = getResolvedManifest();
    const resolvedKAnchor = getResolvedKAnchor();
    if (!resolvedManifest?.manifest_url || !resolvedKAnchor?.k_vector_id) {
      Api.setStatus("Publique o vetor K e ancore o manifesto no ledger antes de emitir.");
      return null;
    }
    return {
      manifest: resolvedManifest,
      kVectorId: resolvedKAnchor.k_vector_id,
      kLedgerAnchorObj: resolvedKAnchor,
    };
  }

  function getSchemaTemplateAttrNames(data, valuesTemplate) {
    return Array.isArray(data?.attrNames) && data.attrNames.length
      ? data.attrNames
      : Object.keys(valuesTemplate || {});
  }

  async function validateRevocableCredentialStructure(genesisPath, credDefId, opts = {}) {
    const normalizedGenesisPath = toStringSafe(genesisPath).trim();
    const normalizedCredDefId = toStringSafe(credDefId).trim();
    const where = opts.where || "credentialCreateRevocable.validateRevocableCredentialStructure";

    if (!normalizedGenesisPath || !normalizedCredDefId) {
      resetRevocableSchemaValidation();
      return {
        ok: false,
        skipped: true,
        missingInput: {
          genesisPath: !normalizedGenesisPath,
          credDefId: !normalizedCredDefId,
        },
      };
    }

    if (
      !opts.fillTemplate
      && revocableSchemaValidation.checked
      && revocableSchemaValidation.genesisPath === normalizedGenesisPath
      && revocableSchemaValidation.credDefId === normalizedCredDefId
    ) {
      if (revocableSchemaValidation.ok) clearMissingControlAttributesWarning();
      else showMissingControlAttributesWarning(revocableSchemaValidation.missingAttrs);
      return {
        ok: revocableSchemaValidation.ok,
        cached: true,
        validation: revocableSchemaValidation,
        attrNames: revocableSchemaValidation.attrNames,
      };
    }

    const r = await Api.credCreate.loadSchemaTemplate({
      genesisPath: normalizedGenesisPath,
      credDefId: normalizedCredDefId,
    });
    setOut({
      where,
      input: { genesisPath: normalizedGenesisPath, credDefId: normalizedCredDefId },
      resp: r,
    });
    $("#create_rev_result").value = JSON.stringify(r, null, 2);

    if (!r?.ok) {
      resetRevocableSchemaValidation();
      Api.setStatus(`Erro carregando schema: ${r?.error?.message || "erro desconhecido"}`);
      return { ok: false, apiError: true, resp: r };
    }

    const tpl = r.data?.valuesTemplate || {};
    const attrNames = getSchemaTemplateAttrNames(r.data, tpl);
    const validation = rememberRevocableSchemaValidation(normalizedGenesisPath, normalizedCredDefId, attrNames);

    if (!validation.ok) {
      showMissingControlAttributesWarning(validation.missingAttrs);
      return { ok: false, resp: r, tpl, attrNames, validation };
    }

    clearMissingControlAttributesWarning();
    if (opts.fillTemplate) {
      const sanitizedTemplate = sanitizeCredentialValuesObj(tpl);
      $("#create_rev_values_json").value = JSON.stringify(sanitizedTemplate.sanitized, null, 2);
    }
    return { ok: true, resp: r, tpl, attrNames, validation };
  }

  async function importRequestEnvelope() {
    const issuerDid = toStringSafe($("#create_rev_issuer_did").value).trim() || null;
    const requestFilePath = toStringSafe($("#create_rev_request_file_path").value).trim() || null;

    $("#create_rev_request_file_path").value = "";
    $("#create_rev_offer_file_path").value = "";
    importedRequest = null;
    resetRevocableSchemaValidation();
    clearMissingControlAttributesWarning();

    Api.setStatus("Importando request envelope para emissão revogável...");
    const r = await Api.credCreate.importRequestEnvelope({ issuerDid, requestFilePath });
    setOut({ where: "credentialCreateRevocable.importRequestEnvelope", input: { issuerDid, requestFilePath }, resp: r });
    $("#create_rev_result").value = JSON.stringify(r, null, 2);

    if (!r?.ok) {
      Api.setStatus(`Erro importando request: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (r.data?.canceled) {
      Api.setStatus("Importação cancelada.");
      return;
    }

    importedRequest = r.data;
    updateFromImportedRequest(r.data);

    const genesisPath = getGenesisPathValue();
    const credDefId = toStringSafe($("#create_rev_creddef_id").value).trim();
    if (genesisPath && credDefId) {
      const validation = await validateRevocableCredentialStructure(genesisPath, credDefId, {
        where: "credentialCreateRevocable.importRequestEnvelope.validateStructure",
      });
      if (!validation.ok) return;
      Api.setStatus("Request importado com sucesso. Estrutura de credencial revogável confirmada.");
      return;
    }

    Api.setStatus("Request importado com sucesso. Informe o Genesis path para validar os atributos de controle antes da emissão.");
  }

  async function loadSchemaTemplate() {
    const genesisPath = getGenesisPathValue();
    const credDefId = toStringSafe($("#create_rev_creddef_id").value).trim();
    if (genesisPath && toStringSafe($("#create_rev_genesis_path").value).trim() !== genesisPath) {
      $("#create_rev_genesis_path").value = genesisPath;
    }
    if (!genesisPath) {
      Api.setStatus("Informe Genesis path.");
      return;
    }
    if (!credDefId) {
      Api.setStatus("Informe CredDef ID.");
      return;
    }

    Api.setStatus("Carregando schema/atributos da credencial revogável...");
    const validation = await validateRevocableCredentialStructure(genesisPath, credDefId, {
      where: "credentialCreateRevocable.loadSchemaTemplate",
      fillTemplate: true,
    });
    if (!validation.ok) {
      return;
    }

    Api.setStatus(`Atributos carregados (${validation.attrNames.length}). Preencha os valores.`);
  }

  async function exportCredentialEnvelope() {
    const genesisPath = getGenesisPathValue();
    const issuerDid = toStringSafe($("#create_rev_issuer_did").value).trim() || null;
    const requestFilePath = toStringSafe($("#create_rev_request_file_path").value).trim() || null;
    const offerFilePath = toStringSafe($("#create_rev_offer_file_path").value).trim() || null;
    const credDefId = toStringSafe($("#create_rev_creddef_id").value).trim() || null;
    const holderVerkey = toStringSafe($("#create_rev_holder_verkey").value).trim() || null;
    const issuerLocalCredentialId = toStringSafe($("#create_rev_local_credential_id").value).trim() || null;
    const kind = toStringSafe($("#create_rev_credential_kind").value).trim() || "anoncreds/revocable-credential-package-v2";
    const threadId = toStringSafe($("#create_rev_thread_id").value).trim() || null;
    const unitOfTime = toStringSafe($("#create_rev_unit_of_time").value).trim() || null;
    const holderDidHint = toStringSafe($("#create_rev_holder_did_hint").value).trim() || null;

    const valuesRaw = toStringSafe($("#create_rev_values_json").value).trim();
    if (!valuesRaw) {
      Api.setStatus("Preencha os valores da credencial em JSON.");
      return;
    }

    let valuesObj = null;
    try {
      valuesObj = JSON.parse(valuesRaw);
    } catch (_) {
      Api.setStatus("Valores da credencial: JSON inválido.");
      return;
    }

    let timeWindow = null;
    let expiresAtMs = null;
    let computedRange = null;
    let sanitizedValues = null;
    let removedControlKeys = [];

    try {
      timeWindow = parsePositiveInteger($("#create_rev_time_window").value, "Tamanho de cada janela");
      computedRange = computeValidityRange();
      const sanitized = sanitizeCredentialValuesObj(valuesObj);
      sanitizedValues = sanitized.sanitized;
      removedControlKeys = sanitized.removedKeys;
    } catch (err) {
      Api.setStatus(err?.message || "Parâmetros de revogação inválidos.");
      return;
    }

    if (!computedRange) {
      Api.setStatus("Informe a data inicial, a unidade de tempo, o tamanho de cada janela e a quantidade de janelas válidas.");
      return;
    }
    if (!genesisPath) {
      Api.setStatus("Informe Genesis path.");
      return;
    }
    if (toStringSafe($("#create_rev_genesis_path").value).trim() !== genesisPath) {
      $("#create_rev_genesis_path").value = genesisPath;
    }
    if (!credDefId) {
      Api.setStatus("Informe CredDef ID.");
      return;
    }
    const structureValidation = await validateRevocableCredentialStructure(genesisPath, credDefId, {
      where: "credentialCreateRevocable.exportCredentialEnvelope.validateStructure",
    });
    if (!structureValidation.ok) {
      return;
    }
    if (!unitOfTime) {
      Api.setStatus("Informe a unidade de tempo.");
      return;
    }
    if (!timeWindow) {
      Api.setStatus("Informe o tamanho de cada janela.");
      return;
    }

    const expiresRaw = toStringSafe($("#create_rev_expires_at").value).trim();
    if (expiresRaw) {
      const n = Number(expiresRaw);
      if (!Number.isFinite(n) || n <= 0) {
        Api.setStatus("ExpiresAt inválido. Use epoch em milissegundos.");
        return;
      }
      expiresAtMs = Math.trunc(n);
    }

    const metaRaw = toStringSafe($("#create_rev_meta_json").value).trim();
    let metaObj = null;
    if (metaRaw) {
      try {
        metaObj = JSON.parse(metaRaw);
      } catch (_) {
        Api.setStatus("Meta JSON inválido.");
        return;
      }
    }

    const setupReady = await ensureRevocationSetupReadyForExport();
    if (!setupReady) return;

    const input = {
      genesisPath,
      issuerDid,
      requestFilePath,
      offerFilePath,
      credDefId,
      holderVerkey,
      holderDidHint,
      issuerLocalCredentialId,
      kind,
      threadId,
      expiresAtMs,
      metaObj,
      valuesObj: sanitizedValues,
      startDate: toStringSafe($("#create_rev_start_date").value).trim(),
      startTimeText: toStringSafe($("#create_rev_start_time_text").value).trim(),
      startTime: computedRange.startTime,
      validityEnd: computedRange.validityEnd,
      unitOfTime,
      timeWindow,
      manifestObj: setupReady.manifest,
      kVectorId: setupReady.kVectorId,
      kLedgerAnchorObj: setupReady.kLedgerAnchorObj,
    };

    $("#create_rev_values_json").value = JSON.stringify(sanitizedValues, null, 2);
    Api.setStatus("Emitindo credencial revogável e exportando envelope...");
    const r = await Api.credCreateRevocable.exportCredentialEnvelope(input);
    setOut({
      where: "credentialCreateRevocable.exportCredentialEnvelope",
      input,
      resp: r,
      importedRequest,
      revocationSetupState,
      removedControlKeys,
    });
    $("#create_rev_result").value = JSON.stringify(r, null, 2);

    if (!r?.ok) {
      Api.setStatus(`Erro emitindo/exportando credencial revogável: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (r.data?.canceled) {
      Api.setStatus("Exportação cancelada.");
      return;
    }

    const issuerRecordId = firstNonEmpty(
      r.data?.issuerRecordSummary?.issuerLocalCredentialId,
      r.data?.issuerRecord?.issuer_local_credential_id,
      r.data?.issuerLocalCredentialId
    );
    if (issuerRecordId) {
      Api.setStatus(
        `Credencial revogável exportada: ${r.data?.credentialFilePath || "(sem caminho)"} | salva no wallet do emissor como ${issuerRecordId}.`
      );
      return;
    }
    Api.setStatus(`Credencial revogável exportada: ${r.data?.credentialFilePath || "(sem caminho)"}`);
  }

  $("#btn_create_rev_refresh_dids").addEventListener("click", refreshDids);
  $("#btn_create_rev_import_request").addEventListener("click", importRequestEnvelope);
  $("#btn_create_rev_load_schema").addEventListener("click", loadSchemaTemplate);
  $("#btn_create_rev_load_ledger_setup").addEventListener("click", loadLedgerSetup);
  $("#btn_create_rev_generate_k").addEventListener("click", generateKVector);
  $("#btn_create_rev_publish_k").addEventListener("click", publishKVectorOnLedger);
  $("#btn_create_rev_anchor_manifest").addEventListener("click", anchorManifestOnLedger);
  $("#btn_create_rev_export_credential").addEventListener("click", exportCredentialEnvelope);
  $("#create_rev_issuer_filter").addEventListener("input", applyIssuerDidFilter);
  $("#create_rev_issuer_filter").addEventListener("keyup", applyIssuerDidFilter);
  $("#create_rev_issuer_limit").addEventListener("input", applyIssuerDidFilter);
  $("#create_rev_issuer_limit").addEventListener("change", applyIssuerDidFilter);
  $("#btn_create_rev_issuer_clear_filter").addEventListener("click", () => {
    $("#create_rev_issuer_filter").value = "";
    applyIssuerDidFilter();
  });
  $("#create_rev_start_date").addEventListener("input", refreshValidityPreview);
  $("#create_rev_start_time_text").addEventListener("input", refreshValidityPreview);
  $("#create_rev_unit_of_time").addEventListener("change", refreshValidityPreview);
  $("#create_rev_time_window").addEventListener("input", refreshValidityPreview);
  $("#create_rev_time_window").addEventListener("change", refreshValidityPreview);
  $("#create_rev_valid_window_count").addEventListener("input", refreshValidityPreview);
  $("#create_rev_valid_window_count").addEventListener("change", refreshValidityPreview);

  $("#sel_create_rev_issuer_did").addEventListener("change", () => {
    const did = toStringSafe($("#sel_create_rev_issuer_did").value).trim();
    if (did) $("#create_rev_issuer_did").value = did;
    ensureSetupIssuerState();
    updateRevocationSetupPreview();
  });
  $("#create_rev_issuer_did").addEventListener("input", () => {
    ensureSetupIssuerState();
    updateRevocationSetupPreview();
  });

  fillCurrentValidityStartDefaults();
  refreshValidityPreview();
  $("#create_rev_manifest_url").value = DEFAULT_MANIFEST_URL;
  updateRevocationSetupPreview();
  refreshDids().catch(() => {});
  return {};
})();
