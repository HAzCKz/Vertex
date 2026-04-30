// src/renderer/js/pages/presentation-create.js
/* eslint-disable no-console */

const PresentationCreatePage = (() => {
  const root = document.getElementById("page-presentation-create");
  if (!root) return {};
  const DEFAULT_DID_LIMIT = 150;
  const MAX_DID_LIMIT = 1000;
  const REVOCATION_CONTROL_ATTRS = [
    "root_merkle_L",
    "seed",
    "start_time",
    "time_window",
    "unit_of_time",
  ];
  const REVOCATION_CONTROL_ATTR_SET = new Set([
    "root_merkle_l",
    ...REVOCATION_CONTROL_ATTRS,
  ]);
  const DEFAULT_REVOCATION_ADDITIONAL_WINDOWS = 10;

  let ownDidOptions = [];
  let visibleOwnDidOptions = [];
  let recipientOptions = [];
  let visibleRecipientOptions = [];
  let allCredentials = [];
  let filteredCredentials = [];
  let credentialsPageIndex = 1;
  let credentialsPageSize = 30;
  const selectedCredentialIds = new Set();
  const selectionConfig = new Map();
  const revocationBundleCache = new Map();
  let activeCredentialId = "";

  root.innerHTML = `
    <div class="card">
      <h2>Criar Apresentações</h2>
      <p class="small">
        Selecione uma ou mais credenciais da wallet, escolha atributos revelados e/ou predicados ZKP,
        gere a apresentação e exporte em envelope cifrado para um DID de destino.
      </p>

      <div class="row">
        <button class="secondary" id="btn_pres_refresh_all">Atualizar DIDs/Credenciais</button>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>1) Contexto e Destino</h3>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Genesis path</label>
          <input id="pres_genesis_path" placeholder="/caminho/para/genesis.txn" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:340px">
          <label>Holder DID (lista own)</label>
          <select id="sel_pres_holder_did">
            <option value="">-- selecione um DID --</option>
          </select>
        </div>

        <div class="input" style="min-width:420px">
          <label>Holder DID (manual)</label>
          <input id="pres_holder_did" placeholder="ex.: DID do holder" />
        </div>
      </div>
      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de DIDs (holder)</label>
          <input id="pres_holder_filter" placeholder="Filtrar por DID, alias ou verkey..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="pres_holder_limit" type="number" min="1" max="${MAX_DID_LIMIT}" value="${DEFAULT_DID_LIMIT}" />
        </div>
        <button class="secondary" id="btn_pres_holder_clear_filter">Limpar filtro</button>
      </div>
      <p class="small" id="pres_holder_stats">DIDs holder: 0</p>

      <div class="row">
        <div class="input" style="min-width:420px">
          <label>Destinatário (DID + verkey)</label>
          <select id="sel_pres_recipient">
            <option value="">-- selecione um destinatário --</option>
          </select>
        </div>

        <div class="input" style="min-width:320px">
          <label>DID destino (manual)</label>
          <input id="pres_recipient_did" placeholder="opcional (se verkey for manual)" />
        </div>

        <div class="input" style="min-width:420px">
          <label>Verkey destino (manual)</label>
          <input id="pres_recipient_verkey" placeholder="se vazio, tenta resolver via DID destino" />
        </div>
      </div>
      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de destinatários</label>
          <input id="pres_recipient_filter" placeholder="Filtrar por DID, verkey, alias ou origem..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="pres_recipient_limit" type="number" min="1" max="${MAX_DID_LIMIT}" value="${DEFAULT_DID_LIMIT}" />
        </div>
        <button class="secondary" id="btn_pres_recipient_clear_filter">Limpar filtro</button>
      </div>
      <p class="small" id="pres_recipient_stats">Destinatários: 0</p>

      <div class="row">
        <div class="input" style="min-width:260px">
          <label>Kind</label>
          <input id="pres_kind" value="ssi/proof/presentation" />
        </div>

        <div class="input" style="min-width:300px">
          <label>Thread ID (opcional)</label>
          <input id="pres_thread_id" placeholder="vazio = auto" />
        </div>

        <div class="input" style="min-width:220px">
          <label>ExpiresAt (epoch ms)</label>
          <input id="pres_expires_at" placeholder="opcional" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:280px">
          <label>Proof Name</label>
          <input id="pres_name" value="proof-from-wallet" />
        </div>

        <div class="input" style="min-width:180px">
          <label>Proof Version</label>
          <input id="pres_version" value="1.0" />
        </div>

        <div class="input" style="min-width:260px">
          <label>Proof Nonce (opcional)</label>
          <input id="pres_nonce" placeholder="vazio = auto" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Meta JSON (opcional)</label>
          <textarea id="pres_meta_json" rows="4" placeholder='{"flow":"presentation"}'></textarea>
        </div>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>2) Credenciais disponíveis</h3>

      <div class="row">
        <div class="input" style="min-width:340px">
          <label>Schema ID (filtro exato opcional)</label>
          <input id="pres_filter_schema" placeholder="ex.: V4SG...:2:nome:1.0" />
        </div>

        <div class="input" style="min-width:340px">
          <label>CredDef ID (filtro exato opcional)</label>
          <input id="pres_filter_creddef" placeholder="ex.: V4SG...:3:CL:...:TAG" />
        </div>

        <div class="input" style="min-width:300px">
          <label>Busca livre</label>
          <input id="pres_filter_text" placeholder="id, schema, creddef, atributo..." />
        </div>

        <button class="secondary" id="btn_pres_search">Buscar</button>
        <button class="secondary" id="btn_pres_clear_filter">Limpar</button>
      </div>

      <div class="row" style="align-items:flex-end">
        <div class="input" style="min-width:180px">
          <label>Itens por página</label>
          <select id="pres_cred_page_size">
            <option value="20">20</option>
            <option value="30" selected>30</option>
            <option value="50">50</option>
            <option value="100">100</option>
            <option value="200">200</option>
          </select>
        </div>
        <button class="secondary" id="btn_pres_cred_first">⏮ Primeiro</button>
        <button class="secondary" id="btn_pres_cred_prev">◀ Prev</button>
        <div class="input" style="min-width:120px">
          <label>Página</label>
          <input id="pres_cred_page_index" value="1" />
        </div>
        <button class="secondary" id="btn_pres_cred_next">Next ▶</button>
        <button class="secondary" id="btn_pres_cred_last">Último ⏭</button>
        <div class="small" id="pres_cred_page_meta"></div>
      </div>

      <div class="tableWrap">
        <table class="table" id="tbl_pres_credentials">
          <thead>
            <tr>
              <th>Usar</th>
              <th>ID local</th>
              <th>Schema ID</th>
              <th>CredDef ID</th>
              <th>Atributos</th>
              <th>Ações</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <p class="small" id="pres_selected_summary">0 credenciais selecionadas.</p>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>3) Configurar atributos das credenciais selecionadas</h3>

      <div class="row">
        <button class="secondary" id="btn_pres_mark_all_revealed">Marcar todos como revelado</button>
        <button class="secondary" id="btn_pres_clear_modes">Limpar seleção de atributos</button>
      </div>

      <div class="tableWrap">
        <table class="table" id="tbl_pres_attrs">
          <thead>
            <tr>
              <th>Credencial</th>
              <th>Atributo</th>
              <th>Valor atual</th>
              <th>Modo</th>
              <th>Operador ZKP</th>
              <th>Valor ZKP (inteiro)</th>
              <th>Info</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>4) Janelas de revogação</h3>
      <p class="small">
        Para cada credencial revogável selecionada, escolha a janela inicial e quantas janelas
        subsequentes serão entregues ao verificador. Credenciais não revogáveis não exigem esta etapa.
      </p>

      <div class="tableWrap">
        <table class="table" id="tbl_pres_revocation_windows">
          <thead>
            <tr>
              <th>Credencial</th>
              <th>Janela inicial</th>
              <th>Data da janela</th>
              <th>Janela final</th>
              <th>Faixa válida</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>5) Gerar e exportar</h3>

      <div class="row">
        <button class="primary" id="btn_pres_export">Gerar apresentação e exportar envelope</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Resultado</label>
          <textarea id="pres_result" rows="10" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="pres_out">{}</pre>
    </div>

    <div id="pres_revocation_warning_modal" style="display:none; position:fixed; inset:0; z-index:9999; background:rgba(15,23,42,.45); align-items:center; justify-content:center; padding:24px;">
      <div style="background:#fff; border-radius:14px; max-width:560px; width:min(560px, 100%); box-shadow:0 18px 60px rgba(15,23,42,.28); padding:20px;">
        <h3 style="margin-top:0;">Atenção</h3>
        <p id="pres_revocation_warning_message" style="white-space:pre-wrap; line-height:1.45;"></p>
        <div class="row" style="justify-content:flex-end; margin-bottom:0;">
          <button class="secondary" id="btn_pres_revocation_warning_close" type="button">Voltar</button>
        </div>
      </div>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#pres_out");

  function setOut(obj) {
    out.textContent = JSON.stringify(obj, null, 2);
  }

  function toStringSafe(v) {
    if (v === undefined || v === null) return "";
    return String(v);
  }

  function firstNonEmpty(...values) {
    for (const v of values) {
      const txt = toStringSafe(v).trim();
      if (txt) return txt;
    }
    return "";
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

  function normalizeValuesRaw(rec) {
    if (!rec || typeof rec !== "object") return {};

    if (rec.values_raw && typeof rec.values_raw === "object" && !Array.isArray(rec.values_raw)) {
      return rec.values_raw;
    }

    const values = rec.values;
    if (!values || typeof values !== "object" || Array.isArray(values)) return {};

    const map = {};
    Object.entries(values).forEach(([k, v]) => {
      if (v && typeof v === "object" && !Array.isArray(v)) {
        const raw = toStringSafe(v.raw).trim();
        if (raw) map[k] = raw;
      }
    });
    return map;
  }

  function parseCredentialsData(rawData) {
    const parsed = parseMaybeJson(rawData);
    let arr = [];

    if (Array.isArray(parsed)) {
      arr = parsed;
    } else if (parsed && typeof parsed === "object") {
      if (Array.isArray(parsed.items)) arr = parsed.items;
      else if (Array.isArray(parsed.data)) arr = parsed.data;
      else if (Array.isArray(parsed.records)) arr = parsed.records;
    }

    return arr
      .map((it) => parseMaybeJson(it))
      .filter((it) => it && typeof it === "object")
      .map((rec) => ({
        ...rec,
        id_local: firstNonEmpty(rec.id_local, rec.id),
        schema_id: firstNonEmpty(rec.schema_id, rec.schemaId),
        cred_def_id: firstNonEmpty(rec.cred_def_id, rec.credDefId),
        values_raw: normalizeValuesRaw(rec),
      }))
      .filter((rec) => rec.id_local && rec.schema_id && rec.cred_def_id);
  }

  function looksIntegerString(txt) {
    return /^-?\d+$/.test(toStringSafe(txt).trim());
  }

  function shortText(txt, max = 38) {
    const s = toStringSafe(txt).trim();
    if (s.length <= max) return s;
    return `${s.slice(0, max)}...`;
  }

  function getCredentialById(credId) {
    return allCredentials.find((c) => c.id_local === credId) || null;
  }

  function ensureCredentialConfig(credId) {
    if (!selectionConfig.has(credId)) {
      selectionConfig.set(credId, { attrs: {}, revocation: {} });
    }
    const cfg = selectionConfig.get(credId);
    if (!cfg.attrs || typeof cfg.attrs !== "object") cfg.attrs = {};
    if (!cfg.revocation || typeof cfg.revocation !== "object") cfg.revocation = {};
    return cfg;
  }

  function ensureAttrConfig(credId, attrName, rawValue) {
    const cfg = ensureCredentialConfig(credId);
    if (!cfg.attrs[attrName]) {
      const raw = toStringSafe(rawValue).trim();
      cfg.attrs[attrName] = {
        mode: "",
        pType: ">=",
        pValue: looksIntegerString(raw) ? raw : "",
      };
    }
    if (isRequiredControlAttrForCredential(credId, attrName)) {
      cfg.attrs[attrName].mode = "revealed";
      cfg.attrs[attrName].pType = ">=";
      cfg.attrs[attrName].pValue = looksIntegerString(toStringSafe(rawValue).trim())
        ? toStringSafe(rawValue).trim()
        : "";
    }
    return cfg.attrs[attrName];
  }

  function normalizeControlAttrName(attrName) {
    const raw = toStringSafe(attrName).trim();
    if (raw === "root_merkle_l") return "root_merkle_L";
    return raw;
  }

  function getCredentialControlAttrNames(rec) {
    const attrsMap = rec?.values_raw && typeof rec.values_raw === "object" ? rec.values_raw : {};
    const present = new Set();
    Object.keys(attrsMap).forEach((attrName) => {
      const normalized = normalizeControlAttrName(attrName);
      if (REVOCATION_CONTROL_ATTR_SET.has(attrName) || REVOCATION_CONTROL_ATTRS.includes(normalized)) {
        present.add(normalized);
      }
    });
    return REVOCATION_CONTROL_ATTRS.filter((attrName) => present.has(attrName));
  }

  function isRevocableCredential(rec) {
    return getCredentialControlAttrNames(rec).length > 0;
  }

  function isRequiredControlAttrForCredential(credId, attrName) {
    const rec = getCredentialById(credId);
    if (!rec || !isRevocableCredential(rec)) return false;
    return REVOCATION_CONTROL_ATTRS.includes(normalizeControlAttrName(attrName));
  }

  function getBundleIdForCredential(credId) {
    const id = toStringSafe(credId).trim();
    return id ? `revocation-bundle-${id}` : "";
  }

  function normalizeBundleControl(bundle, rec) {
    const fromBundle = bundle?.control && typeof bundle.control === "object" ? bundle.control : {};
    const attrsMap = rec?.values_raw && typeof rec.values_raw === "object" ? rec.values_raw : {};
    return {
      ...fromBundle,
      root_merkle_l: firstNonEmpty(fromBundle.root_merkle_l, fromBundle.root_merkle_L, attrsMap.root_merkle_l, attrsMap.root_merkle_L),
      seed: firstNonEmpty(fromBundle.seed, attrsMap.seed),
      start_time: firstNonEmpty(fromBundle.start_time, attrsMap.start_time),
      time_window: firstNonEmpty(fromBundle.time_window, attrsMap.time_window),
      unit_of_time: firstNonEmpty(fromBundle.unit_of_time, attrsMap.unit_of_time),
      validity_end: firstNonEmpty(fromBundle.validity_end, attrsMap.validity_end),
      base_window_count: firstNonEmpty(fromBundle.base_window_count, attrsMap.base_window_count),
      confirmation_window_count: firstNonEmpty(fromBundle.confirmation_window_count, attrsMap.confirmation_window_count),
      last_valid_window_index: firstNonEmpty(fromBundle.last_valid_window_index, attrsMap.last_valid_window_index),
      last_confirmation_window_index: firstNonEmpty(fromBundle.last_confirmation_window_index, attrsMap.last_confirmation_window_index),
      window_count: firstNonEmpty(fromBundle.window_count, attrsMap.window_count),
      extra_windows_for_fp: firstNonEmpty(fromBundle.extra_windows_for_fp, attrsMap.extra_windows_for_fp),
    };
  }

  function addUnitsUtc(baseDate, unitOfTime, amount) {
    const date = new Date(baseDate.getTime());
    switch (toStringSafe(unitOfTime).trim().toLowerCase()) {
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
        return null;
    }
  }

  function computeBaseWindowCountFromControl(control) {
    const startTime = Number(control?.start_time);
    const validityEnd = Number(control?.validity_end);
    const timeWindow = Number(control?.time_window);
    const unitOfTime = toStringSafe(control?.unit_of_time).trim();
    if (!Number.isFinite(startTime) || !Number.isFinite(validityEnd) || validityEnd < startTime) return null;
    if (!Number.isFinite(timeWindow) || timeWindow <= 0 || !unitOfTime) return null;

    const startDate = new Date(Math.trunc(startTime) * 1000);
    let index = 0;
    let cursor = startDate;
    while (index < 100000) {
      if (Math.trunc(cursor.getTime() / 1000) > validityEnd) break;
      const next = addUnitsUtc(cursor, unitOfTime, Math.trunc(timeWindow));
      if (!next) return null;
      cursor = next;
      index += 1;
    }
    return index > 0 ? index : null;
  }

  function deriveRevocationWindowLayout(control) {
    const extraWindowsForFp = Math.max(0, Math.trunc(Number(control?.extra_windows_for_fp) || 0));
    const totalWindowCountRaw = Number(control?.window_count);
    const fallbackBaseWindowCount = Number.isFinite(totalWindowCountRaw) && totalWindowCountRaw > 0
      ? Math.max(1, Math.trunc(totalWindowCountRaw) - extraWindowsForFp)
      : null;
    const computedBaseWindowCount = computeBaseWindowCountFromControl(control);
    const baseWindowCount = Math.max(
      1,
      Math.trunc(
        Number(control?.base_window_count) > 0
          ? Number(control?.base_window_count)
          : (computedBaseWindowCount || fallbackBaseWindowCount || 1)
      )
    );
    const confirmationWindowCount = Math.max(
      0,
      Math.trunc(
        Number(control?.confirmation_window_count) > 0
          ? Number(control?.confirmation_window_count)
          : extraWindowsForFp
      )
    );
    const totalWindowCount = Math.max(
      baseWindowCount,
      Math.trunc(
        Number(control?.window_count) > 0
          ? Number(control?.window_count)
          : (baseWindowCount + confirmationWindowCount)
      )
    );
    const lastValidWindowIndex =
      Number(control?.last_valid_window_index) > 0 || baseWindowCount === 1
        ? Math.trunc(Number(control?.last_valid_window_index) || 0)
        : Math.max(0, baseWindowCount - 1);
    const lastConfirmationWindowIndex =
      Number(control?.last_confirmation_window_index) > 0 || totalWindowCount === 1
        ? Math.trunc(Number(control?.last_confirmation_window_index) || 0)
        : Math.max(0, totalWindowCount - 1);

    return {
      baseWindowCount,
      confirmationWindowCount,
      totalWindowCount,
      lastValidWindowIndex,
      lastConfirmationWindowIndex,
    };
  }

  function computeWindowStartTimestamp(control, windowIndex) {
    const startTime = Number(control?.start_time);
    const timeWindow = Number(control?.time_window);
    const unitOfTime = toStringSafe(control?.unit_of_time).trim();
    const idx = Number(windowIndex);
    if (!Number.isFinite(startTime) || startTime < 0 || !Number.isFinite(timeWindow) || timeWindow <= 0 || !unitOfTime) {
      return null;
    }
    if (!Number.isFinite(idx) || idx < 0) return null;

    let cursor = new Date(Math.trunc(startTime) * 1000);
    for (let i = 0; i < Math.trunc(idx); i += 1) {
      const next = addUnitsUtc(cursor, unitOfTime, Math.trunc(timeWindow));
      if (!next) return null;
      cursor = next;
    }
    return Math.trunc(cursor.getTime() / 1000);
  }

  function formatWindowTimestamp(ts) {
    const n = Number(ts);
    if (!Number.isFinite(n) || n < 0) return "";
    try {
      return new Date(Math.trunc(n) * 1000).toLocaleString();
    } catch (_) {
      return "";
    }
  }

  function inferCurrentWindowIndexFromControl(control, layout) {
    const startTime = Number(control?.start_time);
    const timeWindow = Number(control?.time_window);
    const unitOfTime = toStringSafe(control?.unit_of_time).trim();
    if (!Number.isFinite(startTime) || startTime < 0 || !Number.isFinite(timeWindow) || timeWindow <= 0 || !unitOfTime) {
      return 0;
    }

    const startDate = new Date(Math.trunc(startTime) * 1000);
    const now = new Date();
    if (now < startDate) return 0;

    let index = 0;
    let cursor = startDate;
    const max = Math.max(0, Number(layout?.lastValidWindowIndex ?? 0));
    while (index < max) {
      const next = addUnitsUtc(cursor, unitOfTime, Math.trunc(timeWindow));
      if (!next || now < next) break;
      cursor = next;
      index += 1;
    }
    return Math.max(0, Math.min(max, index));
  }

  function parseMaybeJsonObject(raw) {
    const parsed = parseMaybeJson(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  }

  function getRevocationBundleState(credId) {
    return revocationBundleCache.get(credId) || null;
  }

  function ensureRevocationBundleLoaded(credId) {
    const id = toStringSafe(credId).trim();
    if (!id || revocationBundleCache.has(id)) return;
    const bundleIdLocal = getBundleIdForCredential(id);
    revocationBundleCache.set(id, { loading: true, bundleIdLocal, bundle: null, error: "" });
    Api.revocationVerify.getHolderBundle({ bundleIdLocal })
      .then((resp) => {
        if (!resp?.ok) {
          revocationBundleCache.set(id, {
            loading: false,
            bundleIdLocal,
            bundle: null,
            error: resp?.error?.message || "bundle de revogação não encontrado",
          });
          return;
        }
        revocationBundleCache.set(id, {
          loading: false,
          bundleIdLocal,
          bundle: parseMaybeJsonObject(resp.data),
          error: "",
        });
      })
      .catch((err) => {
        revocationBundleCache.set(id, {
          loading: false,
          bundleIdLocal,
          bundle: null,
          error: err?.message || String(err),
        });
      })
      .finally(() => renderRevocationWindowTable());
  }

  function renderOwnDidOptions(items) {
    const el = $("#sel_pres_holder_did");
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
    const el = $("#sel_pres_recipient");
    const currentVerkey = toStringSafe(el.value).trim();
    el.innerHTML = `<option value="">-- selecione um destinatário --</option>`;

    const fragment = document.createDocumentFragment();
    (items || []).forEach((item) => {
      const did = toStringSafe(item.did).trim();
      const verkey = toStringSafe(item.verkey).trim();
      if (!did || !verkey) return;
      const opt = document.createElement("option");
      opt.value = verkey;
      opt.dataset.did = did;
      opt.textContent = `${did} | ${verkey.slice(0, 20)}... (${item.source})`;
      fragment.appendChild(opt);
    });
    el.appendChild(fragment);

    if (currentVerkey && (items || []).some((item) => toStringSafe(item.verkey).trim() === currentVerkey)) {
      el.value = currentVerkey;
    }
  }

  function holderDidSearchBlob(d) {
    return normalizeText([
      d.did,
      d.alias,
      d.verkey,
      d.verKey,
    ].filter(Boolean).join(" "));
  }

  function recipientDidSearchBlob(item) {
    return normalizeText([
      item.did,
      item.alias,
      item.verkey,
      item.verKey,
      item.source,
    ].filter(Boolean).join(" "));
  }

  function updateHolderStats(total, filtered, shown, limit) {
    $("#pres_holder_stats").textContent =
      `DIDs holder: total ${total} | filtrados ${filtered} | exibidos ${shown} (máx ${limit})`;
  }

  function updateRecipientStats(total, filtered, shown, limit) {
    $("#pres_recipient_stats").textContent =
      `Destinatários: total ${total} | filtrados ${filtered} | exibidos ${shown} (máx ${limit})`;
  }

  function applyHolderDidFilter() {
    const filterText = normalizeText($("#pres_holder_filter").value).trim();
    const limit = parseDidLimit($("#pres_holder_limit").value);
    $("#pres_holder_limit").value = String(limit);

    const filtered = filterText
      ? ownDidOptions.filter((d) => holderDidSearchBlob(d).includes(filterText))
      : ownDidOptions;

    visibleOwnDidOptions = filtered.slice(0, limit);
    renderOwnDidOptions(visibleOwnDidOptions);
    updateHolderStats(ownDidOptions.length, filtered.length, visibleOwnDidOptions.length, limit);
  }

  function applyRecipientDidFilter() {
    const filterText = normalizeText($("#pres_recipient_filter").value).trim();
    const limit = parseDidLimit($("#pres_recipient_limit").value);
    $("#pres_recipient_limit").value = String(limit);

    const filtered = filterText
      ? recipientOptions.filter((item) => recipientDidSearchBlob(item).includes(filterText))
      : recipientOptions;

    visibleRecipientOptions = filtered.slice(0, limit);
    renderRecipientOptions(visibleRecipientOptions);
    updateRecipientStats(recipientOptions.length, filtered.length, visibleRecipientOptions.length, limit);
  }

  function buildSearchBlob(rec) {
    const attrs = rec.values_raw && typeof rec.values_raw === "object"
      ? Object.entries(rec.values_raw).map(([k, v]) => `${k}:${toStringSafe(v)}`).join(" ")
      : "";

    return [rec.id_local, rec.schema_id, rec.cred_def_id, attrs]
      .map((v) => toStringSafe(v).toLowerCase())
      .join(" | ");
  }

  function applyFilterClientSide(items) {
    const q = normalizeText($("#pres_filter_text").value).trim();
    if (!q) return items;
    return items.filter((rec) => buildSearchBlob(rec).includes(q));
  }

  function getCredentialPagination() {
    credentialsPageSize = Number($("#pres_cred_page_size").value || 30);
    if (!Number.isFinite(credentialsPageSize) || credentialsPageSize < 1) credentialsPageSize = 30;

    const total = filteredCredentials.length;
    const totalPages = Math.max(1, Math.ceil(total / credentialsPageSize));
    if (credentialsPageIndex > totalPages) credentialsPageIndex = totalPages;
    if (credentialsPageIndex < 1) credentialsPageIndex = 1;
    $("#pres_cred_page_index").value = String(credentialsPageIndex);

    const start = (credentialsPageIndex - 1) * credentialsPageSize;
    const end = start + credentialsPageSize;
    const slice = filteredCredentials.slice(start, end);
    return { total, totalPages, start, end: Math.min(end, total), slice };
  }

  function updateSelectedSummary() {
    const total = selectedCredentialIds.size;
    let configuredAttrs = 0;
    let configuredCreds = 0;
    selectedCredentialIds.forEach((credId) => {
      const cfg = selectionConfig.get(credId);
      if (!cfg || !cfg.attrs || typeof cfg.attrs !== "object") return;
      const count = Object.values(cfg.attrs).filter((a) => {
        const mode = toStringSafe(a?.mode).trim();
        return mode === "revealed" || mode === "zkp";
      }).length;
      if (count > 0) {
        configuredCreds += 1;
        configuredAttrs += count;
      }
    });
    const active = activeCredentialId ? ` | editando: ${activeCredentialId}` : "";
    $("#pres_selected_summary").textContent = `${total} credenciais selecionadas | ${configuredAttrs} atributo(s) configurado(s) em ${configuredCreds} credencial(is)${active}.`;
  }

  function renderCredentialTable() {
    const tbody = $("#tbl_pres_credentials tbody");
    tbody.innerHTML = "";
    const { total, totalPages, start, end, slice } = getCredentialPagination();

    slice.forEach((rec, idx) => {
      const attrKeys = rec.values_raw && typeof rec.values_raw === "object"
        ? Object.keys(rec.values_raw)
        : [];
      const checked = selectedCredentialIds.has(rec.id_local) ? "checked" : "";
      const selectedClass = rec.id_local === activeCredentialId ? "selectedRow" : "";

      const tr = document.createElement("tr");
      tr.dataset.idx = String(start + idx);
      tr.className = selectedClass;
      tr.innerHTML = `
        <td><input type="checkbox" data-act="toggle" data-id="${rec.id_local}" ${checked} /></td>
        <td class="mono">${rec.id_local}</td>
        <td class="mono" title="${toStringSafe(rec.schema_id)}">${shortText(rec.schema_id, 34)}</td>
        <td class="mono" title="${toStringSafe(rec.cred_def_id)}">${shortText(rec.cred_def_id, 34)}</td>
        <td title="${attrKeys.join(", ")}">${shortText(attrKeys.join(", "), 34)}</td>
        <td>
          <div class="actions">
            <button data-act="config" data-id="${rec.id_local}">Atributos</button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });

    if (total > 0) {
      $("#pres_cred_page_meta").textContent =
        `Total: ${total} | Página ${credentialsPageIndex}/${totalPages} | Itens ${start + 1}-${end}`;
    } else {
      $("#pres_cred_page_meta").textContent = "Total: 0 | Página 1/1";
    }

    updateSelectedSummary();
    renderRevocationWindowTable();
  }

  function renderAttrTable() {
    const tbody = $("#tbl_pres_attrs tbody");
    tbody.innerHTML = "";

    const selectedIds = Array.from(selectedCredentialIds)
      .map((id) => toStringSafe(id).trim())
      .filter((id) => !!id)
      .filter((id, idx, arr) => arr.indexOf(id) === idx);

    if (!selectedIds.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="7" class="small">Selecione uma ou mais credenciais (checkbox "Usar" ou botão "Atributos").</td>`;
      tbody.appendChild(tr);
      updateSelectedSummary();
      renderRevocationWindowTable();
      return;
    }

    let renderedRows = 0;
    selectedIds.forEach((credId) => {
      const rec = getCredentialById(credId);
      if (!rec) return;

      const attrsMap = rec.values_raw && typeof rec.values_raw === "object" ? rec.values_raw : {};
      const attrEntries = Object.entries(attrsMap);
      if (!attrEntries.length) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td class="mono" title="${credId}">${shortText(credId, 28)}</td>
          <td colspan="6" class="small">Credencial sem atributos em values_raw.</td>
        `;
        tbody.appendChild(tr);
        renderedRows += 1;
        return;
      }

      attrEntries.forEach(([attrName, rawValue]) => {
        const cfg = ensureAttrConfig(credId, attrName, rawValue);
        const raw = toStringSafe(rawValue).trim();
        const isInteger = looksIntegerString(raw);
        const zkpDisabled = isInteger ? "" : "disabled";
        const mode = toStringSafe(cfg.mode).trim();
        const pType = toStringSafe(cfg.pType).trim() || ">=";
        const pValue = toStringSafe(cfg.pValue).trim();
        const disabledControls = mode === "zkp" ? "" : "disabled";
        const isActive = credId === activeCredentialId;
        const isRequiredControl = isRequiredControlAttrForCredential(credId, attrName);
        const requiredModeOptions = isRequiredControl
          ? `<option value="revealed" selected>Revelado obrigatório</option>`
          : `
              <option value="" ${mode === "" ? "selected" : ""}>Não incluir</option>
              <option value="revealed" ${mode === "revealed" ? "selected" : ""}>Revelado</option>
              <option value="zkp" ${mode === "zkp" ? "selected" : ""} ${zkpDisabled}>ZKP</option>
            `;
        const infoText = isRequiredControl
          ? "obrigatório para checagem de validade/revogação"
          : (isInteger ? "numérico (ZKP habilitado)" : "não numérico (apenas revelado)");
        const pTypeControl = isRequiredControl
          ? `<input value="-" disabled style="width:80px" />`
          : `
              <select data-act="ptype" data-cred-id="${credId}" data-attr="${attrName}" ${disabledControls}>
                <option value=">=" ${pType === ">=" ? "selected" : ""}>>=</option>
                <option value=">" ${pType === ">" ? "selected" : ""}>></option>
                <option value="<=" ${pType === "<=" ? "selected" : ""}><=</option>
                <option value="<" ${pType === "<" ? "selected" : ""}><</option>
              </select>
            `;
        const pValueControl = isRequiredControl
          ? `<input value="-" disabled style="width:120px" />`
          : `<input data-act="pvalue" data-cred-id="${credId}" data-attr="${attrName}" value="${pValue}" ${disabledControls} style="width:120px" />`;

        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td class="mono" title="${credId}">${shortText(credId, 28)}${isActive ? " *" : ""}</td>
          <td class="mono">${attrName}</td>
          <td class="mono" title="${raw}">${shortText(raw, 28)}</td>
          <td>
            <select data-act="mode" data-cred-id="${credId}" data-attr="${attrName}">
              ${requiredModeOptions}
            </select>
          </td>
          <td>${pTypeControl}</td>
          <td>${pValueControl}</td>
          <td class="small">${infoText}</td>
        `;
        tbody.appendChild(tr);
        renderedRows += 1;
      });
    });

    if (!renderedRows) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="7" class="small">Nenhum atributo disponível nas credenciais selecionadas.</td>`;
      tbody.appendChild(tr);
    }

    updateSelectedSummary();
    renderRevocationWindowTable();
  }

  function getRevocationWindowView(credId) {
    const rec = getCredentialById(credId);
    if (!rec || !isRevocableCredential(rec)) return null;

    ensureRevocationBundleLoaded(credId);
    const state = getRevocationBundleState(credId);
    const bundle = state?.bundle || null;
    const control = normalizeBundleControl(bundle, rec);
    const layout = deriveRevocationWindowLayout(control);
    const cfg = ensureCredentialConfig(credId);
    const revCfg = cfg.revocation;

    if (revCfg.primaryWindowIndex === undefined || revCfg.primaryWindowIndex === null || revCfg.primaryWindowIndex === "") {
      revCfg.primaryWindowIndex = inferCurrentWindowIndexFromControl(control, layout);
    }

    const primaryRaw = Number(revCfg.primaryWindowIndex);
    const primaryWindowIndex = Number.isFinite(primaryRaw)
      ? Math.max(0, Math.trunc(primaryRaw))
      : 0;
    if (String(revCfg.primaryWindowIndex) !== String(primaryWindowIndex)) {
      revCfg.primaryWindowIndex = primaryWindowIndex;
    }

    if (revCfg.finalWindowIndex === undefined || revCfg.finalWindowIndex === null || revCfg.finalWindowIndex === "") {
      const previousAdditional = Number(revCfg.additionalWindowCount);
      const defaultAdditional = Number.isFinite(previousAdditional)
        ? Math.max(0, Math.trunc(previousAdditional))
        : DEFAULT_REVOCATION_ADDITIONAL_WINDOWS;
      revCfg.finalWindowIndex = Math.min(
        layout.lastConfirmationWindowIndex,
        primaryWindowIndex + defaultAdditional
      );
    }

    const finalRaw = Number(revCfg.finalWindowIndex);
    const finalWindowIndex = Number.isFinite(finalRaw)
      ? Math.max(0, Math.trunc(finalRaw))
      : primaryWindowIndex;
    const additionalWindowCount = Math.max(0, finalWindowIndex - primaryWindowIndex);

    return {
      rec,
      state,
      control,
      layout,
      primaryWindowIndex,
      finalWindowIndex,
      additionalWindowCount,
      windowStart: computeWindowStartTimestamp(control, primaryWindowIndex),
    };
  }

  function renderRevocationWindowTable() {
    const tbody = $("#tbl_pres_revocation_windows tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    const selectedRevocableIds = Array.from(selectedCredentialIds)
      .filter((credId) => {
        const rec = getCredentialById(credId);
        return rec && isRevocableCredential(rec);
      });

    if (!selectedRevocableIds.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="6" class="small">Nenhuma credencial revogável selecionada. Para credenciais não revogáveis, nenhuma janela precisa ser enviada.</td>`;
      tbody.appendChild(tr);
      return;
    }

    selectedRevocableIds.forEach((credId) => {
      const view = getRevocationWindowView(credId);
      const tr = document.createElement("tr");
      if (!view) {
        tr.innerHTML = `<td class="mono">${credId}</td><td colspan="5" class="small">Não foi possível preparar as janelas desta credencial.</td>`;
        tbody.appendChild(tr);
        return;
      }

      const { state, layout, primaryWindowIndex, finalWindowIndex, windowStart } = view;
      const loading = state?.loading ? "Carregando bundle de revogação..." : "";
      const error = state?.error ? `Erro: ${state.error}` : "";
      const status = error || loading || `Bundle ${state?.bundleIdLocal || getBundleIdForCredential(credId)} pronto.`;
      const disabled = state?.error || state?.loading ? "disabled" : "";
      const numericAttrs = `inputmode="numeric" pattern="[0-9]*" autocomplete="off"`;

      tr.innerHTML = `
        <td class="mono" title="${credId}">${shortText(credId, 34)}</td>
        <td>
          <input data-act="rev-primary" data-cred-id="${credId}" type="text" ${numericAttrs} value="${primaryWindowIndex}" ${disabled} style="width:120px" />
        </td>
        <td>${formatWindowTimestamp(windowStart) || "-"}</td>
        <td>
          <input data-act="rev-final" data-cred-id="${credId}" type="text" ${numericAttrs} value="${finalWindowIndex}" ${disabled} style="width:120px" />
        </td>
        <td class="small">válidas: 0-${layout.lastValidWindowIndex}; extras: ${layout.lastValidWindowIndex + 1}-${layout.lastConfirmationWindowIndex}</td>
        <td class="small">${status}</td>
      `;
      tbody.appendChild(tr);
    });
  }

  async function refreshDidOptions() {
    Api.setStatus("Carregando DIDs para criação de apresentação...");

    const [ownResp, extResp] = await Promise.all([
      Api.did.list("own"),
      Api.did.list("external"),
    ]);

    if (!ownResp?.ok) {
      setOut({ where: "presentationCreate.refreshDidOptions", ownResp, extResp });
      Api.setStatus(`Erro listando DIDs own: ${ownResp?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (!extResp?.ok) {
      setOut({ where: "presentationCreate.refreshDidOptions", ownResp, extResp });
      Api.setStatus(`Erro listando DIDs external: ${extResp?.error?.message || "erro desconhecido"}`);
      return;
    }

    ownDidOptions = parseDidList(ownResp);
    applyHolderDidFilter();

    const own = parseDidList(ownResp).map((d) => ({ ...d, source: "own" }));
    const ext = parseDidList(extResp).map((d) => ({ ...d, source: "external" }));
    const seen = new Set();
    recipientOptions = own.concat(ext).filter((d) => {
      const did = toStringSafe(d.did).trim();
      const verkey = toStringSafe(d.verkey).trim();
      const key = `${did}|${verkey}`;
      if (!did || !verkey || seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    applyRecipientDidFilter();
  }

  async function refreshCredentials() {
    const schemaIdEq = toStringSafe($("#pres_filter_schema").value).trim() || null;
    const credDefIdEq = toStringSafe($("#pres_filter_creddef").value).trim() || null;

    Api.setStatus("Listando credenciais para apresentação...");
    const resp = await Api.credential.list(schemaIdEq, credDefIdEq);
    setOut({ where: "presentationCreate.refreshCredentials", input: { schemaIdEq, credDefIdEq }, resp });

    if (!resp?.ok) {
      Api.setStatus(`Erro listando credenciais: ${resp?.error?.message || "erro desconhecido"}`);
      allCredentials = [];
      filteredCredentials = [];
      credentialsPageIndex = 1;
      renderCredentialTable();
      renderAttrTable();
      return;
    }

    allCredentials = parseCredentialsData(resp.data);
    filteredCredentials = applyFilterClientSide(allCredentials);
    credentialsPageIndex = 1;

    // Remove seleção inválida após refresh
    Array.from(selectedCredentialIds).forEach((id) => {
      if (!allCredentials.find((it) => it.id_local === id)) {
        selectedCredentialIds.delete(id);
      }
    });
    if (activeCredentialId && !allCredentials.find((it) => it.id_local === activeCredentialId)) {
      activeCredentialId = "";
    }

    renderCredentialTable();
    renderAttrTable();
    Api.setStatus(`Credenciais carregadas: ${filteredCredentials.length}.`);
  }

  async function refreshAll() {
    await refreshDidOptions();
    await refreshCredentials();
  }

  function toggleCredentialSelection(credId, checked) {
    if (checked) selectedCredentialIds.add(credId);
    else selectedCredentialIds.delete(credId);

    if (checked && !activeCredentialId) {
      activeCredentialId = credId;
    }
    if (!checked && activeCredentialId === credId) {
      activeCredentialId = selectedCredentialIds.values().next().value || "";
    }

    renderCredentialTable();
    renderAttrTable();
  }

  function openCredentialConfig(credId) {
    if (!credId) return;
    selectedCredentialIds.add(credId);
    activeCredentialId = credId;
    renderCredentialTable();
    renderAttrTable();
    Api.setStatus(`Configurando atributos da credencial ${credId}.`);
  }

  function markAllRevealedForActive() {
    const targetIds = Array.from(selectedCredentialIds)
      .map((id) => toStringSafe(id).trim())
      .filter((id) => !!id && !!getCredentialById(id));
    if (!targetIds.length) {
      Api.setStatus("Selecione ao menos uma credencial para configurar atributos.");
      return;
    }

    targetIds.forEach((credId) => {
      const rec = getCredentialById(credId);
      if (!rec) return;
      const attrsMap = rec.values_raw && typeof rec.values_raw === "object" ? rec.values_raw : {};
      Object.entries(attrsMap).forEach(([attrName, rawValue]) => {
        const cfg = ensureAttrConfig(credId, attrName, rawValue);
        cfg.mode = "revealed";
      });
    });

    renderAttrTable();
    renderCredentialTable();
    Api.setStatus(`Todos os atributos foram marcados como revelados em ${targetIds.length} credencial(is) selecionada(s).`);
  }

  function clearModesForActive() {
    const targetIds = Array.from(selectedCredentialIds)
      .map((id) => toStringSafe(id).trim())
      .filter((id) => !!id && !!getCredentialById(id));
    if (!targetIds.length) {
      Api.setStatus("Selecione ao menos uma credencial para limpar a configuração.");
      return;
    }

    targetIds.forEach((credId) => {
      const rec = getCredentialById(credId);
      if (!rec) return;
      const attrsMap = rec.values_raw && typeof rec.values_raw === "object" ? rec.values_raw : {};
      Object.entries(attrsMap).forEach(([attrName, rawValue]) => {
        const cfg = ensureAttrConfig(credId, attrName, rawValue);
        if (isRequiredControlAttrForCredential(credId, attrName)) {
          cfg.mode = "revealed";
          cfg.pType = ">=";
          cfg.pValue = looksIntegerString(toStringSafe(rawValue).trim()) ? toStringSafe(rawValue).trim() : "";
        } else {
          cfg.mode = "";
          cfg.pType = ">=";
          cfg.pValue = looksIntegerString(toStringSafe(rawValue).trim()) ? toStringSafe(rawValue).trim() : "";
        }
      });
    });

    renderAttrTable();
    Api.setStatus(`Configuração de atributos limpa em ${targetIds.length} credencial(is) selecionada(s).`);
  }

  function updateAttributeConfigFromEvent(target) {
    const act = toStringSafe(target.dataset.act).trim();
    const credId = toStringSafe(target.dataset.credId).trim();
    const attrName = toStringSafe(target.dataset.attr).trim();
    if (!act || !credId || !attrName) return;

    const rec = getCredentialById(credId);
    if (!rec) return;

    const rawValue = rec.values_raw ? rec.values_raw[attrName] : "";
    const cfg = ensureAttrConfig(credId, attrName, rawValue);
    if (isRequiredControlAttrForCredential(credId, attrName)) {
      cfg.mode = "revealed";
      renderAttrTable();
      renderCredentialTable();
      return;
    }

    if (act === "mode") {
      const mode = toStringSafe(target.value).trim();
      if (mode !== "" && mode !== "revealed" && mode !== "zkp") return;
      if (mode === "zkp" && !looksIntegerString(toStringSafe(rawValue).trim())) {
        cfg.mode = "revealed";
      } else {
        cfg.mode = mode;
      }
      selectedCredentialIds.add(credId);
      renderAttrTable();
      renderCredentialTable();
      return;
    }

    if (act === "ptype") {
      const pType = toStringSafe(target.value).trim();
      if ([">=", ">", "<=", "<"].includes(pType)) {
        cfg.pType = pType;
      }
      return;
    }

    if (act === "pvalue") {
      cfg.pValue = toStringSafe(target.value).trim();
    }
  }

  let revocationWarningReturnFocus = null;

  function closeRevocationWindowWarning() {
    const modal = $("#pres_revocation_warning_modal");
    if (modal) modal.style.display = "none";
    const focusTarget = revocationWarningReturnFocus;
    revocationWarningReturnFocus = null;
    if (focusTarget && typeof focusTarget.focus === "function") {
      setTimeout(() => {
        focusTarget.focus();
        if (typeof focusTarget.select === "function") focusTarget.select();
      }, 0);
    }
  }

  function showRevocationWindowWarning(message, focusTarget = null) {
    revocationWarningReturnFocus = focusTarget;
    const modal = $("#pres_revocation_warning_modal");
    const msg = $("#pres_revocation_warning_message");
    if (!modal || !msg) {
      Api.setStatus(message);
      return;
    }
    msg.textContent = message;
    modal.style.display = "flex";
    const closeBtn = $("#btn_pres_revocation_warning_close");
    if (closeBtn) setTimeout(() => closeBtn.focus(), 0);
  }

  function sanitizeWindowInput(target) {
    const cleanValue = toStringSafe(target.value).replace(/\D+/g, "");
    if (target.value !== cleanValue) target.value = cleanValue;
    return cleanValue;
  }

  function validateRevocationWindowConfig(credId, options = {}) {
    const view = getRevocationWindowView(credId);
    if (!view) return { ok: false, message: `Não foi possível calcular as janelas da credencial ${credId}.` };

    const cfg = ensureCredentialConfig(credId);
    const startRaw = toStringSafe(cfg.revocation.primaryWindowIndex).trim();
    const finalRaw = toStringSafe(cfg.revocation.finalWindowIndex).trim();
    const lastValid = view.layout.lastValidWindowIndex;
    const lastConfirmation = view.layout.lastConfirmationWindowIndex;

    if (!/^\d+$/.test(startRaw)) {
      return { ok: false, message: `Informe uma janela inicial válida para ${credId}.` };
    }
    if (!/^\d+$/.test(finalRaw)) {
      return { ok: false, message: `Informe uma janela final válida para ${credId}.` };
    }

    const startWindowIndex = Number(startRaw);
    const finalWindowIndex = Number(finalRaw);
    if (startWindowIndex > lastValid) {
      return {
        ok: false,
        message: `Janela inicial inválida para ${credId}. Use um valor entre 0 e ${lastValid}.`,
      };
    }
    if (finalWindowIndex > lastConfirmation) {
      return {
        ok: false,
        message: `Janela final inválida para ${credId}. Use um valor entre 0 e ${lastConfirmation}. Neste campo você pode incluir também as janelas extras de confirmação.`,
      };
    }
    if (finalWindowIndex < startWindowIndex) {
      return {
        ok: false,
        message: `Janela final inválida para ${credId}. Ela deve ser igual ou superior à janela inicial.`,
      };
    }

    const result = {
      ok: true,
      startWindowIndex,
      finalWindowIndex,
      additionalWindowCount: finalWindowIndex - startWindowIndex,
    };
    if (options.persist) {
      cfg.revocation.primaryWindowIndex = result.startWindowIndex;
      cfg.revocation.finalWindowIndex = result.finalWindowIndex;
      cfg.revocation.additionalWindowCount = result.additionalWindowCount;
    }
    return result;
  }

  function updateRevocationConfigFromEvent(target, eventType = "change") {
    const act = toStringSafe(target.dataset.act).trim();
    const credId = toStringSafe(target.dataset.credId).trim();
    if (!credId || !selectedCredentialIds.has(credId)) return;

    const view = getRevocationWindowView(credId);
    if (!view) return;
    const cfg = ensureCredentialConfig(credId);
    const value = sanitizeWindowInput(target);

    if (act === "rev-primary") {
      cfg.revocation.primaryWindowIndex = value;
      if (cfg.revocation.finalWindowIndex === undefined || cfg.revocation.finalWindowIndex === null || cfg.revocation.finalWindowIndex === "") {
        cfg.revocation.finalWindowIndex = value;
      }
      if (eventType !== "input") {
        const validation = validateRevocationWindowConfig(credId, { persist: true });
        if (!validation.ok) showRevocationWindowWarning(validation.message, target);
        renderRevocationWindowTable();
      }
      return;
    }

    if (act === "rev-final") {
      cfg.revocation.finalWindowIndex = value;
      if (eventType !== "input") {
        const validation = validateRevocationWindowConfig(credId, { persist: true });
        if (!validation.ok) showRevocationWindowWarning(validation.message, target);
        renderRevocationWindowTable();
      }
    }
  }

  function buildRevocationSequencesPayload() {
    const sequences = [];
    const errors = [];

    Array.from(selectedCredentialIds).forEach((credId) => {
      const rec = getCredentialById(credId);
      if (!rec || !isRevocableCredential(rec)) return;

      const state = getRevocationBundleState(credId);
      if (!state || state.loading) {
        errors.push(`Aguarde o carregamento do bundle de revogação da credencial ${credId}.`);
        return;
      }
      if (state.error || !state.bundle) {
        errors.push(`Bundle de revogação indisponível para ${credId}: ${state?.error || "não encontrado"}.`);
        return;
      }

      const view = getRevocationWindowView(credId);
      if (!view) {
        errors.push(`Não foi possível calcular as janelas da credencial revogável ${credId}.`);
        return;
      }

      const validation = validateRevocationWindowConfig(credId, { persist: true });
      if (!validation.ok) {
        errors.push(validation.message);
        return;
      }

      sequences.push({
        credential_id_local: credId,
        primary_window_index: validation.startWindowIndex,
        additional_window_count: validation.additionalWindowCount,
      });
    });

    return { sequences, errors };
  }

  function buildSelectionPayload() {
    const payload = [];

    selectedCredentialIds.forEach((credId) => {
      const rec = getCredentialById(credId);
      if (!rec) return;
      const cfg = ensureCredentialConfig(credId);
      const attrsCfg = cfg.attrs || {};
      const attrsMap = rec.values_raw && typeof rec.values_raw === "object" ? rec.values_raw : {};
      const mandatoryAttrNames = getCredentialControlAttrNames(rec);

      const attrs = [];
      Object.entries(attrsCfg).forEach(([attrName, attrCfgRaw]) => {
        const attrCfg = attrCfgRaw && typeof attrCfgRaw === "object" ? attrCfgRaw : {};
        const mode = toStringSafe(attrCfg.mode).trim();
        if (mode === "revealed") {
          attrs.push({ name: attrName, mode: "revealed" });
          return;
        }
        if (mode === "zkp") {
          attrs.push({
            name: attrName,
            mode: "zkp",
            pType: toStringSafe(attrCfg.pType).trim() || ">=",
            pValue: toStringSafe(attrCfg.pValue).trim(),
          });
        }
      });

      mandatoryAttrNames.forEach((attrName) => {
        if (attrs.some((item) => normalizeControlAttrName(item.name) === attrName)) return;
        if (!Object.prototype.hasOwnProperty.call(attrsMap, attrName) && !Object.prototype.hasOwnProperty.call(attrsMap, "root_merkle_l")) return;
        attrs.push({ name: attrName, mode: "revealed" });
      });

      if (!attrs.length) return;

      payload.push({
        credentialId: rec.id_local,
        schemaId: rec.schema_id,
        credDefId: rec.cred_def_id,
        attributes: attrs,
      });
    });

    return payload;
  }

  async function exportPresentationEnvelope() {
    const genesisPath = toStringSafe($("#pres_genesis_path").value).trim();
    const holderDid = toStringSafe($("#pres_holder_did").value).trim();
    const recipientDid = toStringSafe($("#pres_recipient_did").value).trim() || null;
    const recipientVerkey = toStringSafe($("#pres_recipient_verkey").value).trim() || null;
    const kind = toStringSafe($("#pres_kind").value).trim() || "ssi/proof/presentation";
    const threadId = toStringSafe($("#pres_thread_id").value).trim() || null;
    const proofName = toStringSafe($("#pres_name").value).trim() || "proof-from-wallet";
    const proofVersion = toStringSafe($("#pres_version").value).trim() || "1.0";
    const proofNonce = toStringSafe($("#pres_nonce").value).trim() || null;

    if (!genesisPath) {
      Api.setStatus("Informe o Genesis path.");
      return;
    }
    if (!holderDid) {
      Api.setStatus("Informe o DID holder.");
      return;
    }

    const selection = buildSelectionPayload();
    if (!selection.length) {
      Api.setStatus("Selecione ao menos um atributo (revelado ou ZKP) em alguma credencial.");
      return;
    }

    const revocationSequencesResult = buildRevocationSequencesPayload();
    if (revocationSequencesResult.errors.length) {
      Api.setStatus(revocationSequencesResult.errors[0]);
      showRevocationWindowWarning(revocationSequencesResult.errors[0]);
      setOut({
        where: "presentationCreate.revocationWindows.validation",
        errors: revocationSequencesResult.errors,
      });
      return;
    }

    const expiresRaw = toStringSafe($("#pres_expires_at").value).trim();
    let expiresAtMs = null;
    if (expiresRaw) {
      const n = Number(expiresRaw);
      if (!Number.isFinite(n) || n <= 0) {
        Api.setStatus("ExpiresAt inválido. Use epoch em milissegundos.");
        return;
      }
      expiresAtMs = Math.trunc(n);
    }

    const metaRaw = toStringSafe($("#pres_meta_json").value).trim();
    let metaObj = null;
    if (metaRaw) {
      try {
        metaObj = JSON.parse(metaRaw);
      } catch (_) {
        Api.setStatus("Meta JSON inválido.");
        return;
      }
      if (!metaObj || typeof metaObj !== "object" || Array.isArray(metaObj)) {
        Api.setStatus("Meta JSON deve ser um objeto.");
        return;
      }
    }

    const input = {
      genesisPath,
      holderDid,
      recipientDid,
      recipientVerkey,
      kind,
      threadId,
      expiresAtMs,
      proofName,
      proofVersion,
      proofNonce,
      metaObj,
      selection,
      revocationSequences: revocationSequencesResult.sequences,
    };

    Api.setStatus("Gerando apresentação e exportando envelope...");
    const resp = await Api.presentation.createExportEnvelope(input);
    setOut({ where: "presentationCreate.export", input, resp });
    $("#pres_result").value = JSON.stringify(resp, null, 2);

    if (!resp?.ok) {
      Api.setStatus(`Erro gerando apresentação: ${resp?.error?.message || "erro desconhecido"}`);
      return;
    }
    if (resp.data?.canceled) {
      Api.setStatus("Exportação cancelada.");
      return;
    }

    Api.setStatus(`Apresentação exportada: ${resp.data?.filePath || "(sem caminho)"}`);
  }

  function clearFilters() {
    $("#pres_filter_schema").value = "";
    $("#pres_filter_creddef").value = "";
    $("#pres_filter_text").value = "";
    refreshCredentials().catch(() => {});
  }

  $("#btn_pres_refresh_all").addEventListener("click", () => {
    refreshAll().catch(() => {});
  });
  $("#btn_pres_search").addEventListener("click", () => {
    refreshCredentials().catch(() => {});
  });
  $("#btn_pres_clear_filter").addEventListener("click", clearFilters);
  $("#btn_pres_mark_all_revealed").addEventListener("click", markAllRevealedForActive);
  $("#btn_pres_clear_modes").addEventListener("click", clearModesForActive);
  $("#btn_pres_export").addEventListener("click", exportPresentationEnvelope);
  $("#btn_pres_revocation_warning_close").addEventListener("click", closeRevocationWindowWarning);
  $("#pres_revocation_warning_modal").addEventListener("click", (ev) => {
    if (ev.target && ev.target.id === "pres_revocation_warning_modal") {
      closeRevocationWindowWarning();
    }
  });
  root.addEventListener("keydown", (ev) => {
    if (ev.key !== "Escape") return;
    const modal = $("#pres_revocation_warning_modal");
    if (modal && modal.style.display !== "none") {
      closeRevocationWindowWarning();
    }
  });
  $("#pres_holder_filter").addEventListener("input", applyHolderDidFilter);
  $("#pres_holder_filter").addEventListener("keyup", applyHolderDidFilter);
  $("#pres_holder_limit").addEventListener("input", applyHolderDidFilter);
  $("#pres_holder_limit").addEventListener("change", applyHolderDidFilter);
  $("#btn_pres_holder_clear_filter").addEventListener("click", () => {
    $("#pres_holder_filter").value = "";
    applyHolderDidFilter();
  });
  $("#pres_recipient_filter").addEventListener("input", applyRecipientDidFilter);
  $("#pres_recipient_filter").addEventListener("keyup", applyRecipientDidFilter);
  $("#pres_recipient_limit").addEventListener("input", applyRecipientDidFilter);
  $("#pres_recipient_limit").addEventListener("change", applyRecipientDidFilter);
  $("#btn_pres_recipient_clear_filter").addEventListener("click", () => {
    $("#pres_recipient_filter").value = "";
    applyRecipientDidFilter();
  });
  $("#pres_cred_page_size").addEventListener("change", () => {
    credentialsPageIndex = 1;
    renderCredentialTable();
  });
  $("#btn_pres_cred_first").addEventListener("click", () => {
    credentialsPageIndex = 1;
    renderCredentialTable();
  });
  $("#btn_pres_cred_prev").addEventListener("click", () => {
    credentialsPageIndex -= 1;
    renderCredentialTable();
  });
  $("#btn_pres_cred_next").addEventListener("click", () => {
    credentialsPageIndex += 1;
    renderCredentialTable();
  });
  $("#btn_pres_cred_last").addEventListener("click", () => {
    credentialsPageSize = Number($("#pres_cred_page_size").value || 30);
    if (!Number.isFinite(credentialsPageSize) || credentialsPageSize < 1) credentialsPageSize = 30;
    const totalPages = Math.max(1, Math.ceil(filteredCredentials.length / credentialsPageSize));
    credentialsPageIndex = totalPages;
    renderCredentialTable();
  });
  $("#pres_cred_page_index").addEventListener("change", () => {
    const n = Number($("#pres_cred_page_index").value);
    if (Number.isFinite(n)) credentialsPageIndex = Math.trunc(n);
    renderCredentialTable();
  });
  $("#pres_cred_page_index").addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter") return;
    const n = Number($("#pres_cred_page_index").value);
    if (Number.isFinite(n)) credentialsPageIndex = Math.trunc(n);
    renderCredentialTable();
  });

  $("#sel_pres_holder_did").addEventListener("change", () => {
    const did = toStringSafe($("#sel_pres_holder_did").value).trim();
    if (did) $("#pres_holder_did").value = did;
  });

  $("#sel_pres_recipient").addEventListener("change", () => {
    const sel = $("#sel_pres_recipient");
    const opt = sel.options[sel.selectedIndex];
    const did = opt ? toStringSafe(opt.dataset.did).trim() : "";
    const verkey = toStringSafe(sel.value).trim();
    if (did) $("#pres_recipient_did").value = did;
    if (verkey) $("#pres_recipient_verkey").value = verkey;
  });

  $("#tbl_pres_credentials").addEventListener("click", (ev) => {
    const btn = ev.target.closest("button[data-act]");
    if (!btn) return;
    const act = toStringSafe(btn.dataset.act).trim();
    const credId = toStringSafe(btn.dataset.id).trim();
    if (act === "config") openCredentialConfig(credId);
  });

  $("#tbl_pres_credentials").addEventListener("change", (ev) => {
    const cb = ev.target.closest("input[data-act='toggle']");
    if (!cb) return;
    const credId = toStringSafe(cb.dataset.id).trim();
    toggleCredentialSelection(credId, !!cb.checked);
  });

  $("#tbl_pres_attrs").addEventListener("change", (ev) => {
    const target = ev.target.closest("select[data-act], input[data-act]");
    if (!target) return;
    updateAttributeConfigFromEvent(target);
  });

  $("#tbl_pres_attrs").addEventListener("input", (ev) => {
    const target = ev.target.closest("input[data-act='pvalue']");
    if (!target) return;
    updateAttributeConfigFromEvent(target);
  });
  $("#tbl_pres_revocation_windows").addEventListener("change", (ev) => {
    const target = ev.target.closest("input[data-act]");
    if (!target) return;
    updateRevocationConfigFromEvent(target, ev.type);
  });
  $("#tbl_pres_revocation_windows").addEventListener("input", (ev) => {
    const target = ev.target.closest("input[data-act]");
    if (!target) return;
    updateRevocationConfigFromEvent(target, ev.type);
  });

  refreshAll().catch(() => {});

  return {};
})();
