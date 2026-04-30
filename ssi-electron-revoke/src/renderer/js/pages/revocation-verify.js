// src/renderer/js/pages/revocation-verify.js
/* eslint-disable no-console */

const RevocationVerifyPage = (() => {
  const root = document.getElementById("page-revocation-verify");
  if (!root) return {};

  const DEFAULT_ADDITIONAL_WINDOWS = 10;
  const EXTRA_REVOCATION_TAIL_WINDOWS = 11;
  const VERIFY_SCAN_CONCURRENCY = 8;
  const VERIFY_BINARY_SEARCH_THRESHOLD = 50;
  const CREDENTIALS_PAGE_SIZE_DEFAULT = 30;
  const DEBUG_MAX_DEPTH = 5;
  const DEBUG_MAX_OBJECT_KEYS = 40;
  const DEBUG_MAX_ARRAY_ITEMS = 12;
  const DEBUG_MAX_STRING_LENGTH = 700;
  const DEBUG_HEAVY_KEYS = new Set([
    "bitmap",
    "bitmaps",
    "bloom",
    "bundle",
    "credential",
    "credential_json",
    "credentialJson",
    "holder_bundle",
    "holderBundle",
    "proof",
    "proof_sequence",
    "proofSequence",
    "proofSequenceJson",
    "primary_proof",
    "primaryProof",
    "confirmation_proofs",
    "confirmationProofs",
    "revocation_proof_sequences",
    "revocationProofSequences",
    "scanRuns",
  ]);
  const CONTROL_ATTRIBUTE_NAMES = new Set([
    "seed",
    "start_time",
    "unit_of_time",
    "time_window",
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
  let loadedBundle = null;
  let lastCredentials = [];
  let filteredCredentialsView = [];
  let filteredCredentialsCacheKey = "";
  let credentialsPageIndex = 1;
  let credentialsPageSize = CREDENTIALS_PAGE_SIZE_DEFAULT;
  let credentialListLoaded = false;

  root.innerHTML = `
    <div class="card">
      <h2>Verificar Revogação</h2>
      <p class="small">
        Permite ao Holder ou ao Emissor verificar o status de revogação de uma credencial de duas formas:
        selecionando uma credencial já salva na wallet ou importando o envelope da credencial
        para salvá-la localmente. A ação final de <code>Verificar revogação</code> usa uma busca otimizada
        para credenciais com muitas janelas e mantém a verificação completa como fallback seguro, para
        garantir se ela está ou não revogada em qualquer janela de tempo. A montagem manual de
        <code>proof_sequence</code> continua disponível
        apenas para inspeção e debug.
      </p>

      <h3>1) Selecionar credencial da wallet</h3>

      <div class="row">
        <button class="secondary" id="btn_rev_verify_list_refresh">Atualizar lista</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:420px">
          <label>Busca livre</label>
          <input id="rev_verify_cred_filter" placeholder="Buscar por id/schema/creddef/atributos..." />
        </div>
        <button class="secondary" id="btn_rev_verify_list_search">Buscar</button>
        <button class="secondary" id="btn_rev_verify_list_clear">Limpar filtro</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:220px">
          <label>Atributo da credencial</label>
          <input id="rev_verify_attr_name_filter" placeholder="ex.: nome" />
        </div>
        <div class="input" style="min-width:420px">
          <label>Conteúdo do atributo</label>
          <input id="rev_verify_attr_value_filter" placeholder="ex.: Mariana Dias" />
        </div>
      </div>

      <div class="row" style="align-items:flex-end">
        <div class="input" style="min-width:160px">
          <label>Tamanho da página</label>
          <select id="rev_verify_cred_page_size">
            <option value="20">20</option>
            <option value="30" selected>30</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
        </div>
        <button class="secondary" id="btn_rev_verify_cred_first">⏮ Ir para o primeiro</button>
        <button class="secondary" id="btn_rev_verify_cred_prev">◀ Prev</button>
        <div class="input" style="min-width:120px">
          <label>Página</label>
          <input id="rev_verify_cred_page_index" value="1" />
        </div>
        <button class="secondary" id="btn_rev_verify_cred_next">Next ▶</button>
        <button class="secondary" id="btn_rev_verify_cred_last">Ir para o último</button>
        <div class="small" id="rev_verify_cred_page_meta"></div>
      </div>

      <div class="tableWrap">
        <table class="table" id="tbl_rev_verify_credentials">
          <thead>
            <tr>
              <th>ID local</th>
              <th>Schema ID</th>
              <th>CredDef ID</th>
              <th>Atributos</th>
              <th>Armazenada em</th>
              <th>Ações</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Credencial selecionada</label>
          <textarea id="rev_verify_selected_credential" rows="8" readonly></textarea>
        </div>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>2) Importar credencial (arquivo)</h3>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Caminho do Genesis</label>
          <input id="rev_verify_import_genesis_path" placeholder="/caminho/para/genesis.txn" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:420px">
          <label>DID do Holder (opcional)</label>
          <input id="rev_verify_import_holder_did" placeholder="vazio = tentar inferir da wallet" />
        </div>
        <div class="input" style="min-width:520px">
          <label>Arquivo da credencial (.env.json)</label>
          <input id="rev_verify_import_credential_file_path" placeholder="vazio = escolher no diálogo" />
        </div>
      </div>

      <div class="row">
        <button class="secondary" id="btn_rev_verify_import_credential">Importar credencial para verificar</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Resultado da importação</label>
          <textarea id="rev_verify_import_result" rows="8" readonly></textarea>
        </div>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>3) A partir do bundle salvo na wallet</h3>

      <div class="row">
        <div class="input" style="min-width:420px">
          <label>Bundle ID local</label>
          <input id="rev_verify_bundle_id" placeholder="ex.: revocation-bundle-credential-123" />
        </div>
        <div class="input" style="min-width:420px">
          <label>ID local da credencial (opcional)</label>
          <input id="rev_verify_credential_id" placeholder="vazio = usa o credential_id salvo no bundle" />
        </div>
      </div>

      <div class="row">
        <button class="secondary" id="btn_rev_verify_load_bundle">Carregar bundle</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:220px">
          <label>Janelas válidas</label>
          <input id="rev_verify_valid_windows" readonly />
        </div>
        <div class="input" style="min-width:220px">
          <label>Janelas extras de confirmação</label>
          <input id="rev_verify_confirmation_windows" readonly />
        </div>
        <div class="input" style="min-width:220px">
          <label>Total de janelas</label>
          <input id="rev_verify_total_windows" readonly />
        </div>
      </div>

      <p class="small">
        Ao clicar em <code>Verificar revogação</code>, o app usa busca otimizada em credenciais com muitas
        janelas e mantém a confirmação pelas janelas extras obrigatórias para descartar falso positivo.
      </p>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Bundle carregado</label>
          <textarea id="rev_verify_bundle_out" rows="8" readonly></textarea>
        </div>
      </div>

      <hr style="border-color:#e5e7eb; margin:16px 0;" />

      <h3>4) Prova de revogação</h3>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Sequência de prova JSON</label>
          <textarea id="rev_verify_proof_json" rows="12" placeholder='{"primary_proof":{...},"confirmation_proofs":[...]}'></textarea>
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Root Merkle L esperado (opcional)</label>
          <input id="rev_verify_expected_root" placeholder="se vazio, usa o root da própria prova" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Policy JSON (opcional)</label>
          <textarea id="rev_verify_policy_json" rows="4" placeholder='{"max_consecutive_hits_for_revoke":10,"max_windows_to_request":10}'></textarea>
        </div>
      </div>

      <div class="row">
        <button class="primary" id="btn_rev_verify_execute">Verificar revogação</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:220px">
          <label>Prova verificada</label>
          <input id="rev_verify_verified" readonly />
        </div>
        <div class="input" style="min-width:220px">
          <label>Aceita</label>
          <input id="rev_verify_accepted" readonly />
        </div>
        <div class="input" style="min-width:220px">
          <label>Revogada</label>
          <input id="rev_verify_revoked" readonly />
        </div>
        <div class="input" style="min-width:260px">
          <label>Decisão</label>
          <input id="rev_verify_decision" readonly />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:220px">
          <label>Requer mais janelas</label>
          <input id="rev_verify_requires_more" readonly />
        </div>
        <div class="input" style="min-width:220px">
          <label>Próxima janela exigida</label>
          <input id="rev_verify_next_window" readonly />
        </div>
        <div class="input" style="min-width:260px">
          <label>Ocorrências consecutivas</label>
          <input id="rev_verify_consecutive_hits" readonly />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:220px">
          <label>Janela de revogação</label>
          <input id="rev_verify_revoked_window" readonly />
        </div>
        <div class="input" style="min-width:320px">
          <label>Data inicial da credencial</label>
          <input id="rev_verify_credential_start_date" readonly />
        </div>
        <div class="input" style="min-width:320px">
          <label>Data da janela de revogação</label>
          <input id="rev_verify_revoked_window_date" readonly />
        </div>
        <div class="input" style="min-width:220px">
          <label>Janelas verificadas</label>
          <input id="rev_verify_scanned_windows" readonly />
        </div>
        <div class="input" style="min-width:220px">
          <label>Tempo de verificação</label>
          <input id="rev_verify_elapsed_time" readonly />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Resumo simples</label>
          <textarea id="rev_verify_status_summary" rows="6" readonly></textarea>
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:620px">
          <label>Resultado</label>
          <textarea id="rev_verify_result_out" rows="10" readonly></textarea>
        </div>
      </div>

      <h3>Debug</h3>
      <pre id="rev_verify_out" style="max-height:320px; overflow:auto; white-space:pre-wrap; word-break:break-word;">{}</pre>
    </div>

    <div id="rev_verify_warning_modal" style="display:none; position:fixed; inset:0; z-index:9999; background:rgba(15,23,42,.45); align-items:center; justify-content:center; padding:24px;">
      <div style="background:#fff; border-radius:14px; max-width:560px; width:min(560px, 100%); box-shadow:0 18px 60px rgba(15,23,42,.28); padding:20px;">
        <h3 style="margin-top:0;">Aviso</h3>
        <p id="rev_verify_warning_message" style="white-space:pre-wrap; line-height:1.45;"></p>
        <div class="row" style="justify-content:flex-end; margin-bottom:0;">
          <button class="secondary" id="btn_rev_verify_warning_close" type="button">Voltar</button>
        </div>
      </div>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#rev_verify_out");

  function summarizeHeavyDebugValue(key, value) {
    if (Array.isArray(value)) {
      return {
        omitted: true,
        reason: "debug_compact_heavy_array",
        key,
        length: value.length,
      };
    }
    if (value && typeof value === "object") {
      const keys = Object.keys(value);
      return {
        omitted: true,
        reason: "debug_compact_heavy_object",
        key,
        keys: keys.slice(0, 20),
        omittedKeys: Math.max(0, keys.length - 20),
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
      if (Array.isArray(value)) return { omitted: true, reason: "debug_max_depth_array", length: value.length };
      if (value && typeof value === "object") {
        const keys = Object.keys(value);
        return {
          omitted: true,
          reason: "debug_max_depth_object",
          keys: keys.slice(0, 20),
          omittedKeys: Math.max(0, keys.length - 20),
        };
      }
    }

    if (Array.isArray(value)) {
      const head = value.slice(0, DEBUG_MAX_ARRAY_ITEMS).map((item) => summarizeDebugValue(item, depth + 1, key));
      if (value.length <= DEBUG_MAX_ARRAY_ITEMS) return head;
      return {
        length: value.length,
        sample: head,
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
    return raw;
  }

  function firstNonEmpty(...values) {
    for (const v of values) {
      const txt = toStringSafe(v).trim();
      if (txt) return txt;
    }
    return "";
  }

  function getGenesisPathValue() {
    return firstNonEmpty(
      toStringSafe($("#rev_verify_import_genesis_path")?.value).trim(),
      window.AppState?.genesisPath
    );
  }

  function syncGenesisPathInput() {
    const genesisPath = firstNonEmpty(window.AppState?.genesisPath);
    if (!genesisPath) return "";
    if (toStringSafe($("#rev_verify_import_genesis_path")?.value).trim() !== genesisPath) {
      $("#rev_verify_import_genesis_path").value = genesisPath;
    }
    return genesisPath;
  }

  function showResult(obj) {
    $("#rev_verify_result_out").value = JSON.stringify(obj || {}, null, 2);
  }

  function showImportResult(obj) {
    $("#rev_verify_import_result").value = JSON.stringify(obj || {}, null, 2);
  }

  function showWarning(message) {
    const modal = $("#rev_verify_warning_modal");
    const msg = $("#rev_verify_warning_message");
    if (!modal || !msg) {
      Api.setStatus(message);
      return;
    }
    msg.textContent = message;
    modal.style.display = "flex";
    const closeBtn = $("#btn_rev_verify_warning_close");
    if (closeBtn) setTimeout(() => closeBtn.focus(), 0);
  }

  function closeWarning() {
    const modal = $("#rev_verify_warning_modal");
    if (modal) modal.style.display = "none";
  }

  function getSelectedCredentialRecord() {
    const raw = toStringSafe($("#rev_verify_selected_credential")?.value).trim();
    if (!raw) return null;
    const parsed = parseMaybeJson(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  }

  function clearVerifyStatus() {
    $("#rev_verify_verified").value = "";
    $("#rev_verify_accepted").value = "";
    $("#rev_verify_revoked").value = "";
    $("#rev_verify_decision").value = "";
    $("#rev_verify_requires_more").value = "";
    $("#rev_verify_next_window").value = "";
    $("#rev_verify_consecutive_hits").value = "";
    $("#rev_verify_revoked_window").value = "";
    $("#rev_verify_credential_start_date").value = "";
    $("#rev_verify_revoked_window_date").value = "";
    $("#rev_verify_scanned_windows").value = "";
    $("#rev_verify_elapsed_time").value = "";
    $("#rev_verify_status_summary").value = "";
  }

  function buildSimpleStatusSummary(status) {
    const decision = firstNonEmpty(status?.decision);
    const nextWindow = status?.next_required_window_index;
    const consecutiveHits = Number(status?.consecutive_hits ?? 0);
    const scannedWindows = Number(status?.scanned_windows ?? 0);
    const decisiveWindow = status?.decisive_window_index;
    const tailConfirmationOutcome = firstNonEmpty(status?.tail_confirmation?.outcome);

    if (!status?.verified) {
      const details = firstNonEmpty(status?.details);
      return details
        ? `A prova de revogação não foi validada. Não é seguro confiar neste resultado. Detalhe: ${details}`
        : "A prova de revogação não foi validada. Não é seguro confiar neste resultado.";
    }

    if (
      (tailConfirmationOutcome === "clean" || tailConfirmationOutcome === "needs_more_windows")
      && firstNonEmpty(status?.details)
    ) {
      return firstNonEmpty(status?.details);
    }

    switch (decision) {
      case "globally_not_revoked":
        if (status?.false_positive_confirmed) {
          const fpWindow = status?.false_positive_window_index;
          const hits = Number(status?.false_positive_consecutive_hits ?? 0);
          const breakWindow = status?.false_positive_break_window_index;
          const hitText = hits > 0 ? ` após ${hits} hit(s) consecutivo(s)` : "";
          const breakText = breakWindow === undefined || breakWindow === null || breakWindow === ""
            ? ""
            : ` A sequência foi quebrada na janela ${breakWindow}.`;
          return fpWindow === undefined || fpWindow === null || fpWindow === ""
            ? `A credencial está válida e não revogada: houve falso positivo confirmado no Bloom Filter${hitText}.${breakText}`
            : `A credencial está válida e não revogada: houve falso positivo confirmado a partir da janela ${fpWindow}${hitText}.${breakText}`;
        }
        if (status?.search_mode === "binary_window_search") {
          return scannedWindows > 0
            ? `A credencial não foi encontrada como revogada. A busca binária confirmada consultou ${scannedWindows} janela(s) estratégica(s) sem encontrar um ponto real de revogação.`
            : "A credencial não foi encontrada como revogada pela busca binária confirmada.";
        }
        return scannedWindows > 0
          ? `A credencial não foi encontrada como revogada em nenhuma das ${scannedWindows} janela(s) válida(s) verificadas.`
          : "A credencial não foi encontrada como revogada em nenhuma janela válida da credencial.";
      case "globally_revoked":
        if (decisiveWindow === undefined || decisiveWindow === null || decisiveWindow === "") {
          return "A credencial foi confirmada como revogada ao longo da verificação completa de todas as janelas possíveis.";
        }
        {
          const confirmationCount = Number(status?.confirmation_windows_checked ?? 0);
          const confirmationText = confirmationCount > 0
            ? ` Foram verificadas também ${confirmationCount} janela(s) subsequente(s) para descartar falso positivo.`
            : "";
          const modeText = status?.search_mode === "binary_window_search"
            ? " A localização do ponto de revogação foi otimizada com busca binária confirmada."
            : "";
          return status?.decisive_window_start
            ? `A credencial foi confirmada como revogada na janela ${decisiveWindow}, correspondente a ${formatWindowTimestamp(status?.decisive_window_start)}.${confirmationText}${modeText}`
            : `A credencial foi confirmada como revogada na janela ${decisiveWindow} durante a verificação completa das janelas possíveis.${confirmationText}${modeText}`;
        }
      case "global_inconclusive":
        return "A verificação completa não conseguiu concluir o status da credencial em todas as janelas. Revise o resultado detalhado.";
      case "valid_not_revoked":
        return "A credencial está válida e não foi encontrada como revogada.";
      case "false_positive_confirmed":
        return consecutiveHits > 0
          ? `A credencial continua válida. Houve ${consecutiveHits} hit(s) no Bloom Filter, mas a verificação confirmou que era falso positivo.`
          : "A credencial continua válida. O indício anterior de revogação era um falso positivo.";
      case "needs_next_window":
        if (nextWindow === undefined || nextWindow === null || nextWindow === "") {
          return "Ainda não foi possível concluir a verificação. É necessário consultar mais janelas.";
        }
        return `Ainda não foi possível concluir a verificação. É necessário consultar a próxima janela ${nextWindow}.`;
      case "revoked_by_policy":
        return consecutiveHits > 0
          ? `A credencial foi considerada revogada pela política de verificação após ${consecutiveHits} hit(s) consecutivo(s) no Bloom Filter.`
          : "A credencial foi considerada revogada pela política de verificação.";
      case "invalid_proof":
        return "A prova apresentada é inválida, então o status de revogação não pode ser aceito.";
      default:
        if (status?.accepted) {
          return "A verificação terminou com sucesso e a credencial pode ser aceita.";
        }
        if (status?.revoked) {
          return "A verificação indica que a credencial está revogada.";
        }
        return "A verificação foi concluída, mas o resultado precisa ser analisado em detalhes.";
    }
  }

  function resetLoadedBundleState() {
    loadedBundle = null;
    $("#rev_verify_bundle_id").value = "";
    $("#rev_verify_credential_id").value = "";
    resetBundleDerivedState();
    $("#rev_verify_selected_credential").value = "";
  }

  function resetBundleDerivedState() {
    loadedBundle = null;
    $("#rev_verify_bundle_out").value = "";
    $("#rev_verify_valid_windows").value = "";
    $("#rev_verify_confirmation_windows").value = "";
    $("#rev_verify_total_windows").value = "";
    $("#rev_verify_proof_json").value = "";
    $("#rev_verify_expected_root").value = "";
    $("#rev_verify_result_out").value = "";
    clearVerifyStatus();
  }

  function shortText(txt, max = 42) {
    const s = toStringSafe(txt).trim();
    if (s.length <= max) return s;
    return `${s.slice(0, max)}...`;
  }

  function formatStoredAt(storedAtRaw) {
    const txt = toStringSafe(storedAtRaw).trim();
    if (!txt) return "";
    const n = Number(txt);
    if (!Number.isFinite(n) || n <= 0) return txt;
    const ms = n > 1_000_000_000_000 ? n : n * 1000;
    try {
      return new Date(ms).toLocaleString();
    } catch (_) {
      return txt;
    }
  }

  function normalizeValuesRaw(rec) {
    if (!rec || typeof rec !== "object") return {};

    const direct = rec.values_raw;
    if (direct && typeof direct === "object" && !Array.isArray(direct)) return direct;

    const values = rec.values;
    if (!values || typeof values !== "object" || Array.isArray(values)) return {};

    const outMap = {};
    Object.entries(values).forEach(([k, v]) => {
      if (v && typeof v === "object" && !Array.isArray(v)) {
        const raw = toStringSafe(v.raw).trim();
        if (raw) outMap[k] = raw;
      }
    });
    return outMap;
  }

  function filterBusinessAttributes(attributes) {
    const outMap = {};
    Object.entries(attributes || {}).forEach(([key, value]) => {
      if (CONTROL_ATTRIBUTE_NAMES.has(String(key))) return;
      outMap[key] = value;
    });
    return outMap;
  }

  function parseCredentialsList(rawData) {
    const parsed = parseMaybeJson(rawData);

    let arr = [];
    if (Array.isArray(parsed)) arr = parsed;
    else if (parsed && typeof parsed === "object") {
      if (Array.isArray(parsed.items)) arr = parsed.items;
      else if (Array.isArray(parsed.data)) arr = parsed.data;
      else if (Array.isArray(parsed.records)) arr = parsed.records;
    }

    return arr
      .map((it) => parseMaybeJson(it))
      .filter((it) => it && typeof it === "object")
      .map((rec) => ({
        ...rec,
        id_local: toStringSafe(rec.id_local || rec.id).trim(),
        schema_id: toStringSafe(rec.schema_id || rec.schemaId).trim(),
        cred_def_id: toStringSafe(rec.cred_def_id || rec.credDefId).trim(),
        stored_at: toStringSafe(rec.stored_at || rec.storedAt).trim(),
        values_raw: normalizeValuesRaw(rec),
      }));
  }

  function buildCredentialSearchBlob(rec) {
    const attrs = rec.values_raw && typeof rec.values_raw === "object"
      ? Object.entries(rec.values_raw).map(([k, v]) => `${k}:${toStringSafe(v)}`).join(" ")
      : "";

    return [
      rec.id_local,
      rec.schema_id,
      rec.cred_def_id,
      attrs,
      toStringSafe(rec.stored_at),
    ]
      .map((v) => toStringSafe(v).toLowerCase())
      .join(" | ");
  }

  function getAttributeFilterQuery() {
    return {
      attrName: toStringSafe($("#rev_verify_attr_name_filter").value).trim().toLowerCase(),
      attrValue: toStringSafe($("#rev_verify_attr_value_filter").value).trim().toLowerCase(),
    };
  }

  function hasAttributeFilter() {
    const { attrName, attrValue } = getAttributeFilterQuery();
    return !!attrName || !!attrValue;
  }

  function matchesCredentialAttributeFilter(rec, attrNameQuery, attrValueQuery) {
    const values = filterBusinessAttributes(normalizeValuesRaw(rec));
    const entries = Object.entries(values);
    if (!entries.length) return false;

    return entries.some(([key, value]) => {
      const normalizedKey = toStringSafe(key).trim().toLowerCase();
      const normalizedValue = toStringSafe(value).trim().toLowerCase();
      if (attrNameQuery && !normalizedKey.includes(attrNameQuery)) return false;
      if (attrValueQuery && !normalizedValue.includes(attrValueQuery)) return false;
      return true;
    });
  }

  function getVisibleCredentials() {
    const query = toStringSafe($("#rev_verify_cred_filter").value).trim().toLowerCase();
    const { attrName, attrValue } = getAttributeFilterQuery();
    const baseItems = !query
      ? lastCredentials.slice()
      : lastCredentials.filter((rec) => buildCredentialSearchBlob(rec).includes(query));

    if (!attrName && !attrValue) return baseItems;
    return baseItems.filter((rec) => matchesCredentialAttributeFilter(rec, attrName, attrValue));
  }

  function buildCurrentCredentialFilterCacheKey() {
    return JSON.stringify({
      text: toStringSafe($("#rev_verify_cred_filter").value).trim().toLowerCase(),
      attr: getAttributeFilterQuery(),
      totalItems: lastCredentials.length,
      firstId: firstNonEmpty(lastCredentials[0]?.id_local),
      lastId: firstNonEmpty(lastCredentials[lastCredentials.length - 1]?.id_local),
    });
  }

  function getCredentialPagination(items) {
    credentialsPageSize = Number($("#rev_verify_cred_page_size").value || CREDENTIALS_PAGE_SIZE_DEFAULT);
    if (!Number.isFinite(credentialsPageSize) || credentialsPageSize < 1) {
      credentialsPageSize = CREDENTIALS_PAGE_SIZE_DEFAULT;
    }

    const total = Array.isArray(items) ? items.length : 0;
    const totalPages = Math.max(1, Math.ceil(total / credentialsPageSize));
    if (credentialsPageIndex > totalPages) credentialsPageIndex = totalPages;
    if (credentialsPageIndex < 1) credentialsPageIndex = 1;
    $("#rev_verify_cred_page_index").value = String(credentialsPageIndex);

    const start = (credentialsPageIndex - 1) * credentialsPageSize;
    const end = start + credentialsPageSize;
    const slice = Array.isArray(items) ? items.slice(start, end) : [];
    return {
      total,
      totalPages,
      start,
      end: Math.min(end, total),
      slice,
    };
  }

  function renderCredentialTable(options = {}) {
    const tbody = $("#tbl_rev_verify_credentials tbody");
    tbody.innerHTML = "";

    if (!credentialListLoaded) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="6" class="small">Clique em Atualizar lista para carregar as credenciais da wallet.</td>`;
      tbody.appendChild(tr);
      $("#rev_verify_cred_page_meta").textContent = "Lista ainda não carregada.";
      return;
    }

    const reuseFiltered = options?.reuseFiltered === true;
    const cacheKey = buildCurrentCredentialFilterCacheKey();
    const items = reuseFiltered && filteredCredentialsCacheKey === cacheKey
      ? filteredCredentialsView.slice()
      : getVisibleCredentials();

    filteredCredentialsView = items.slice();
    filteredCredentialsCacheKey = cacheKey;
    const { total, totalPages, start, end, slice } = getCredentialPagination(filteredCredentialsView);

    if (!slice.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="6" class="small">Nenhuma credencial encontrada.</td>`;
      tbody.appendChild(tr);
      $("#rev_verify_cred_page_meta").textContent = total > 0
        ? `Total: ${total} | Página ${credentialsPageIndex}/${totalPages}`
        : "Total: 0 | Página 1/1";
      return;
    }

    slice.forEach((rec) => {
      const attrKeys = rec.values_raw && typeof rec.values_raw === "object"
        ? Object.keys(rec.values_raw)
        : [];

      const tr = document.createElement("tr");
      tr.dataset.credId = toStringSafe(rec.id_local);
      tr.innerHTML = `
        <td class="mono">${toStringSafe(rec.id_local)}</td>
        <td class="mono" title="${toStringSafe(rec.schema_id)}">${shortText(rec.schema_id, 36)}</td>
        <td class="mono" title="${toStringSafe(rec.cred_def_id)}">${shortText(rec.cred_def_id, 36)}</td>
        <td title="${attrKeys.join(", ")}">${shortText(attrKeys.join(", "), 34)}</td>
        <td>${formatStoredAt(rec.stored_at)}</td>
        <td>
          <div class="actions">
            <button data-act="use">Usar</button>
            <button data-act="view">Ver</button>
          </div>
        </td>
      `;
      tbody.appendChild(tr);
    });

    $("#rev_verify_cred_page_meta").textContent = `Total: ${total} | Página ${credentialsPageIndex}/${totalPages} | Itens ${start + 1}-${end}`;
  }

  function showSelectedCredential(rec) {
    $("#rev_verify_selected_credential").value = JSON.stringify(rec || {}, null, 2);
  }

  function isTrueLike(value) {
    if (value === true) return true;
    const txt = toStringSafe(value).trim().toLowerCase();
    return txt === "true" || txt === "1" || txt === "sim" || txt === "yes";
  }

  function credentialHasRevocationControls(rec) {
    if (!rec || typeof rec !== "object") return false;
    const values = normalizeValuesRaw(rec);
    const hasValue = (name) => firstNonEmpty(values?.[name], rec?.[name]);
    return !!(
      hasValue("seed")
      && hasValue("start_time")
      && hasValue("unit_of_time")
      && hasValue("time_window")
      && firstNonEmpty(
        values?.root_merkle_L,
        values?.root_merkle_l,
        rec?.root_merkle_L,
        rec?.root_merkle_l
      )
    );
  }

  function isCredentialRevocable(rec) {
    if (!rec || typeof rec !== "object") return false;
    if (isTrueLike(rec.revocable) || isTrueLike(rec.is_revocable) || isTrueLike(rec.isRevocable)) return true;
    if (firstNonEmpty(rec.bundle_id_local, rec.bundleIdLocal, rec.revocation_bundle_id_local, rec.revocationBundleIdLocal)) {
      return true;
    }
    return credentialHasRevocationControls(rec);
  }

  function buildNonRevocableWarning(rec) {
    const credentialId = firstNonEmpty(rec?.credential_id, rec?.credentialId, rec?.id_local, rec?.id, "credencial selecionada");
    return `A credencial "${credentialId}" não é revogável.\n\nEla não possui atributos de controle de revogação nem bundle de revogação na wallet local. Portanto, não há revogação a verificar: este tipo de credencial foi emitido para validação sem consulta ao Bloom Filter.`;
  }

  function deriveBundleIdFromCredential(rec) {
    const credentialId = firstNonEmpty(rec?.credential_id, rec?.credentialId, rec?.id_local, rec?.id);
    if (!credentialId) return "";
    return `revocation-bundle-${credentialId}`;
  }

  function applyCredentialSelection(rec) {
    const credentialId = firstNonEmpty(rec?.credential_id, rec?.credentialId, rec?.id_local, rec?.id);
    const revocable = isCredentialRevocable(rec);
    const bundleId = firstNonEmpty(
      rec?.bundle_id_local,
      rec?.bundleIdLocal,
      revocable ? deriveBundleIdFromCredential(rec) : ""
    );

    resetBundleDerivedState();
    $("#rev_verify_credential_id").value = credentialId;
    $("#rev_verify_bundle_id").value = bundleId;
    showSelectedCredential(rec);
  }

  function findCredentialById(credentialId) {
    const wanted = toStringSafe(credentialId).trim();
    if (!wanted) return null;
    return lastCredentials.find((rec) => {
      const recId = firstNonEmpty(rec?.credential_id, rec?.credentialId, rec?.id_local, rec?.id);
      return toStringSafe(recId).trim() === wanted;
    }) || null;
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

  function deriveBundleWindowLayout(bundle) {
    const control = bundle?.control || {};
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

  function computeWindowStartTimestamp(bundle, windowIndex) {
    const control = bundle?.control || {};
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

  function getCredentialStartTimestamp(bundle) {
    const startTime = Number(bundle?.control?.start_time);
    return Number.isFinite(startTime) && startTime >= 0 ? Math.trunc(startTime) : null;
  }

  function formatCredentialStartTimestamp(bundle) {
    const startTime = getCredentialStartTimestamp(bundle);
    return startTime === null ? "" : formatWindowTimestamp(startTime);
  }

  function formatElapsedMs(ms) {
    const n = Number(ms);
    if (!Number.isFinite(n) || n < 0) return "";
    if (n < 1000) return `${Math.round(n)} ms`;
    return `${(n / 1000).toFixed(2)} s`;
  }

  function buildProcessingTime(startedAtMs) {
    const now = typeof performance !== "undefined" && typeof performance.now === "function"
      ? performance.now()
      : Date.now();
    const elapsedMs = Math.max(0, now - Number(startedAtMs || now));
    return {
      elapsed_ms: Math.round(elapsedMs),
      elapsed_time_human: formatElapsedMs(elapsedMs),
    };
  }

  function inferCurrentWindowIndex(bundle) {
    const control = bundle?.control || {};
    const startTime = Number(control?.start_time);
    const timeWindow = Number(control?.time_window);
    const unitOfTime = toStringSafe(control?.unit_of_time).trim();
    if (!Number.isFinite(startTime) || startTime < 0 || !Number.isFinite(timeWindow) || timeWindow <= 0 || !unitOfTime) {
      return null;
    }

    const startDate = new Date(Math.trunc(startTime) * 1000);
    const now = new Date();
    if (now < startDate) return 0;

    let index = 0;
    let cursor = startDate;
    while (index < 10000) {
      const next = addUnitsUtc(cursor, unitOfTime, Math.trunc(timeWindow));
      if (!next) return null;
      if (now < next) return index;
      cursor = next;
      index += 1;
    }
    return null;
  }

  function getBundleWindowLayout(bundle) {
    return deriveBundleWindowLayout(bundle);
  }

  function inferLatestAvailableWindowIndex(bundle) {
    const control = bundle?.control || {};
    const layout = getBundleWindowLayout(bundle);
    const startTime = Number(control?.start_time);
    const timeWindow = Number(control?.time_window);
    const unitOfTime = toStringSafe(control?.unit_of_time).trim();
    if (!layout) return null;
    if (!Number.isFinite(startTime) || startTime < 0 || !Number.isFinite(timeWindow) || timeWindow <= 0 || !unitOfTime) {
      return null;
    }

    const startDate = new Date(Math.trunc(startTime) * 1000);
    const now = new Date();
    if (now <= startDate) return 0;

    let index = 0;
    let cursor = startDate;
    while (index < layout.lastConfirmationWindowIndex) {
      const next = addUnitsUtc(cursor, unitOfTime, Math.trunc(timeWindow));
      if (!next) return null;
      if (now < next) break;
      cursor = next;
      index += 1;
    }
    return Math.min(index, layout.lastConfirmationWindowIndex);
  }

  function buildAutomaticProofWindowPlan(bundle, requestedPrimaryWindowIndex) {
    const layout = getBundleWindowLayout(bundle);
    const latestAvailableWindowIndex = inferLatestAvailableWindowIndex(bundle);
    if (!layout || latestAvailableWindowIndex === null) return null;

    let primaryWindowIndex = Number(requestedPrimaryWindowIndex);
    if (!Number.isFinite(primaryWindowIndex) || primaryWindowIndex < 0) {
      primaryWindowIndex = 0;
    }
    primaryWindowIndex = Math.trunc(primaryWindowIndex);

    const maxAllowedPrimary = Math.min(latestAvailableWindowIndex, layout.lastValidWindowIndex);
    if (primaryWindowIndex > maxAllowedPrimary) {
      primaryWindowIndex = maxAllowedPrimary;
    }

    return {
      primaryWindowIndex,
      additionalWindowCount: Math.max(0, latestAvailableWindowIndex - primaryWindowIndex),
      latestAvailableWindowIndex,
      lastValidWindowIndex: layout.lastValidWindowIndex,
      lastConfirmationWindowIndex: layout.lastConfirmationWindowIndex,
    };
  }

  function buildExhaustiveWindowScanPlan(bundle) {
    const layout = getBundleWindowLayout(bundle);
    if (!layout) return null;

    const plan = [];
    for (let primaryWindowIndex = 0; primaryWindowIndex <= layout.lastValidWindowIndex; primaryWindowIndex += 1) {
      const additionalWindowCount = Math.max(
        0,
        Math.min(DEFAULT_ADDITIONAL_WINDOWS, layout.lastConfirmationWindowIndex - primaryWindowIndex)
      );
      plan.push({
        primaryWindowIndex,
        additionalWindowCount,
        lastConfirmationWindowIndex: layout.lastConfirmationWindowIndex,
      });
    }
    return {
      lastValidWindowIndex: layout.lastValidWindowIndex,
      lastConfirmationWindowIndex: layout.lastConfirmationWindowIndex,
      steps: plan,
    };
  }

  function buildWindowScanStep(scanPlan, primaryWindowIndex) {
    const idx = Math.max(0, Math.trunc(Number(primaryWindowIndex) || 0));
    return {
      primaryWindowIndex: idx,
      additionalWindowCount: Math.max(
        0,
        Math.min(DEFAULT_ADDITIONAL_WINDOWS, scanPlan.lastConfirmationWindowIndex - idx)
      ),
      lastConfirmationWindowIndex: scanPlan.lastConfirmationWindowIndex,
    };
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
      return `Confirmação extra: todas as ${checkedWindows} janela(s) disponíveis nesta consulta${rangeText} foram verificadas individualmente.`;
    }
    return `Confirmação extra: as últimas ${checkedWindows} janela(s) disponíveis nesta consulta${rangeText} foram verificadas individualmente.`;
  }

  function summarizeTailVerificationResult(result) {
    const base = createTailConfirmationSummary(result);
    if (result?.outcome === "clean") {
      return `${base} Nenhuma delas indicou revogação, então a credencial permanece aceita como não revogada dentro do intervalo atualmente disponível.`;
    }
    if (result?.outcome === "needs_more_windows") {
      const suspiciousWindow = result?.suspiciousWindowIndex;
      const nextWindow = result?.nextRequiredWindowIndex;
      if (suspiciousWindow === undefined || suspiciousWindow === null || suspiciousWindow === "") {
        return nextWindow === undefined || nextWindow === null || nextWindow === ""
          ? `${base} Foi encontrado um indício de revogação em uma dessas janelas finais, então será necessário consultar janelas extras para confirmar se era falso positivo ou revogação real.`
          : `${base} Foi encontrado um indício de revogação em uma dessas janelas finais, então será necessário consultar janelas extras a partir da janela ${nextWindow} para confirmar se era falso positivo ou revogação real.`;
      }
      return nextWindow === undefined || nextWindow === null || nextWindow === ""
        ? `${base} A janela ${suspiciousWindow} apresentou indício de revogação, então será necessário consultar janelas extras para confirmar se era falso positivo ou revogação real.`
        : `${base} A janela ${suspiciousWindow} apresentou indício de revogação, então será necessário consultar janelas extras a partir da janela ${nextWindow} para confirmar se era falso positivo ou revogação real.`;
    }
    return `${base} A proteção extra ficou inconclusiva e o resultado precisa de revisão adicional.`;
  }

  function mergeTailConfirmationIntoStatus(baseStatus, result) {
    const base = baseStatus && typeof baseStatus === "object" ? baseStatus : {};
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
        ...base,
        verified: true,
        accepted: true,
        revoked: false,
        decision: "globally_not_revoked",
        requires_more_windows: false,
        next_required_window_index: null,
        consecutive_hits: 0,
        details: appendDetailText(base?.details, detailText),
        tail_confirmation: tailConfirmation,
      };
    }

    return {
      ...base,
      ...verifiedStatus,
      verified: true,
      accepted: false,
      revoked: false,
      decision: "needs_next_window",
      requires_more_windows: true,
      next_required_window_index: result?.nextRequiredWindowIndex ?? base?.next_required_window_index ?? null,
      decisive_window_index: null,
      decisive_window_start: null,
      decisive_window_start_human: "",
      details: appendDetailText(base?.details, detailText),
      tail_confirmation: tailConfirmation,
    };
  }

  async function runTailConfirmationCheck({ scanPlan, getProbeResult }) {
    const lastWindowRaw = Number(scanPlan?.lastConfirmationWindowIndex);
    if (!Number.isFinite(lastWindowRaw) || lastWindowRaw < 0) return null;

    const endWindowIndex = Math.trunc(lastWindowRaw);
    const checkedWindows = Math.min(EXTRA_REVOCATION_TAIL_WINDOWS, endWindowIndex + 1);
    const startWindowIndex = Math.max(0, endWindowIndex - checkedWindows + 1);
    let invalidResult = null;
    let suspiciousResult = null;
    let suspiciousWindowIndex = null;
    let verifiedRuns = 0;

    Api.setStatus(
      checkedWindows < EXTRA_REVOCATION_TAIL_WINDOWS
        ? `Executando confirmação extra: verificando todas as ${checkedWindows} janela(s) disponíveis nesta consulta (${startWindowIndex}-${endWindowIndex})...`
        : `Executando confirmação extra: verificando as últimas ${checkedWindows} janela(s) disponíveis nesta consulta (${startWindowIndex}-${endWindowIndex})...`
    );

    for (let windowIndex = startWindowIndex; windowIndex <= endWindowIndex; windowIndex += 1) {
      const entry = await getProbeResult(windowIndex);
      const status = entry?.result?.status || null;

      if (!entry?.result?.ok || !status?.verified) {
        if (!invalidResult) invalidResult = entry?.result;
        await yieldToUi();
        continue;
      }

      verifiedRuns += 1;
      if (
        status?.revoked
        || status?.requires_more_windows
        || Number(status?.consecutive_hits ?? 0) > 0
      ) {
        suspiciousResult = entry?.result;
        suspiciousWindowIndex = windowIndex;
        break;
      }

      await yieldToUi();
    }

    const commonResult = {
      checkedWindows,
      startWindowIndex,
      endWindowIndex,
      verifiedRuns,
      fallbackUsed: !!invalidResult,
      error: invalidResult?.error || invalidResult?.status?.details || null,
    };

    if (suspiciousResult) {
      return {
        ...commonResult,
        outcome: "needs_more_windows",
        status: suspiciousResult.status || null,
        suspiciousWindowIndex,
        nextRequiredWindowIndex: endWindowIndex + 1,
      };
    }

    return {
      ...commonResult,
      outcome: "clean",
      status: null,
    };
  }

  function buildBinarySearchGlobalStatus(bundle, scanPlan, scanRuns, candidateRun) {
    const credentialStartTime = getCredentialStartTimestamp(bundle);
    const credentialStartTimeHuman = credentialStartTime === null
      ? ""
      : formatWindowTimestamp(credentialStartTime);
    const orderedRuns = (Array.isArray(scanRuns) ? scanRuns.slice() : [])
      .sort((a, b) => Number(a?.primaryWindowIndex ?? 0) - Number(b?.primaryWindowIndex ?? 0));

    if (!candidateRun) {
      return {
        verified: true,
        accepted: true,
        revoked: false,
        decision: "globally_not_revoked",
        requires_more_windows: false,
        next_required_window_index: null,
        consecutive_hits: 0,
        credential_start_time: credentialStartTime,
        credential_start_time_human: credentialStartTimeHuman,
        decisive_window_index: null,
        decisive_window_start: null,
        decisive_window_start_human: "",
        scanned_windows: orderedRuns.length,
        search_mode: "binary_window_search",
        details: `A busca binária confirmada não encontrou uma janela de revogação após consultar ${orderedRuns.length} janela(s) estratégicas da credencial.`,
      };
    }

    const layout = getBundleWindowLayout(bundle);
    const decisiveWindowIndexRaw = Number(candidateRun?.primaryWindowIndex);
    const decisiveWindowIndex = Number.isFinite(decisiveWindowIndexRaw)
      ? Math.trunc(decisiveWindowIndexRaw)
      : null;
    const decisiveWindowStart = computeWindowStartTimestamp(bundle, decisiveWindowIndex);
    const consecutiveHitsRaw = Number(candidateRun?.status?.consecutive_hits);
    const traceLenRaw = Number(candidateRun?.status?.trace_len ?? candidateRun?.verify?.scanned_trace_len);
    const checkedSequenceWindowCount = Math.max(
      1,
      Number.isFinite(consecutiveHitsRaw) && consecutiveHitsRaw > 0
        ? Math.trunc(consecutiveHitsRaw)
        : (Number.isFinite(traceLenRaw) && traceLenRaw > 0 ? Math.trunc(traceLenRaw) : 1)
    );
    const confirmationWindowsChecked = Math.max(0, checkedSequenceWindowCount - 1);
    const lastCheckedWindowIndex = decisiveWindowIndex !== null
      ? Math.min(
        layout?.lastConfirmationWindowIndex ?? decisiveWindowIndex + checkedSequenceWindowCount - 1,
        decisiveWindowIndex + checkedSequenceWindowCount - 1
      )
      : null;

    return {
      verified: true,
      accepted: false,
      revoked: true,
      decision: "globally_revoked",
      requires_more_windows: false,
      next_required_window_index: null,
      consecutive_hits: candidateRun?.status?.consecutive_hits ?? "",
      credential_start_time: credentialStartTime,
      credential_start_time_human: credentialStartTimeHuman,
      decisive_window_index: decisiveWindowIndex,
      decisive_window_start: decisiveWindowStart,
      decisive_window_start_human: formatWindowTimestamp(decisiveWindowStart),
      confirmation_windows_checked: confirmationWindowsChecked,
      last_checked_window_index: lastCheckedWindowIndex,
      scanned_windows: orderedRuns.length,
      search_mode: "binary_window_search",
      details: decisiveWindowStart
        ? `Revogação confirmada com busca binária na janela ${decisiveWindowIndex}, iniciada em ${formatWindowTimestamp(decisiveWindowStart)}. A confirmação cobriu ${confirmationWindowsChecked} janela(s) subsequente(s).`
        : `Revogação confirmada com busca binária na janela ${decisiveWindowIndex}. A confirmação cobriu ${confirmationWindowsChecked} janela(s) subsequente(s).`,
    };
  }

  function buildGlobalRevocationStatus(bundle, scanPlan, scanRuns) {
    const runs = Array.isArray(scanRuns) ? scanRuns : [];
    const successfulRuns = runs.filter((item) => item?.status && item.status.verified);
    const revokedRun = successfulRuns.find((item) => item?.status?.revoked);
    const invalidRun = runs.find((item) => item?.status && !item.status.verified);
    const falsePositiveRun = successfulRuns
      .filter((item) => item?.status?.decision === "false_positive_confirmed")
      .sort((a, b) => Number(a?.primaryWindowIndex ?? 0) - Number(b?.primaryWindowIndex ?? 0))[0];
    const credentialStartTime = getCredentialStartTimestamp(bundle);
    const credentialStartTimeHuman = credentialStartTime === null
      ? ""
      : formatWindowTimestamp(credentialStartTime);
    if (revokedRun) {
      const layout = getBundleWindowLayout(bundle);
      const decisiveWindowIndexRaw = Number(revokedRun?.primaryWindowIndex);
      const decisiveWindowIndex = Number.isFinite(decisiveWindowIndexRaw)
        ? Math.trunc(decisiveWindowIndexRaw)
        : null;
      const decisiveWindowStart = computeWindowStartTimestamp(bundle, decisiveWindowIndex);
      const consecutiveHitsRaw = Number(revokedRun?.status?.consecutive_hits);
      const traceLenRaw = Number(revokedRun?.status?.trace_len ?? revokedRun?.verify?.scanned_trace_len);
      const checkedSequenceWindowCount = Math.max(
        1,
        Number.isFinite(consecutiveHitsRaw) && consecutiveHitsRaw > 0
          ? Math.trunc(consecutiveHitsRaw)
          : (Number.isFinite(traceLenRaw) && traceLenRaw > 0 ? Math.trunc(traceLenRaw) : 1)
      );
      const confirmationWindowsChecked = Math.max(0, checkedSequenceWindowCount - 1);
      const lastCheckedWindowIndex = decisiveWindowIndex !== null
        ? Math.min(
          layout?.lastConfirmationWindowIndex ?? decisiveWindowIndex + checkedSequenceWindowCount - 1,
          decisiveWindowIndex + checkedSequenceWindowCount - 1
        )
        : null;
      const scannedWindowsThroughDecision = lastCheckedWindowIndex === null
        ? successfulRuns.length
        : Math.max(0, lastCheckedWindowIndex + 1);
      return {
        verified: true,
        accepted: false,
        revoked: true,
        decision: "globally_revoked",
        requires_more_windows: false,
        next_required_window_index: null,
        consecutive_hits: revokedRun?.status?.consecutive_hits ?? "",
        credential_start_time: credentialStartTime,
        credential_start_time_human: credentialStartTimeHuman,
        decisive_window_index: decisiveWindowIndex,
        decisive_window_start: decisiveWindowStart,
        decisive_window_start_human: formatWindowTimestamp(decisiveWindowStart),
        confirmation_windows_checked: confirmationWindowsChecked,
        last_checked_window_index: lastCheckedWindowIndex,
        scanned_windows: scannedWindowsThroughDecision,
        details: decisiveWindowStart
          ? `Revogação confirmada ao verificar a janela ${decisiveWindowIndex}, iniciada em ${formatWindowTimestamp(decisiveWindowStart)}. A sequência de confirmação cobriu até a janela ${lastCheckedWindowIndex}.`
          : `Revogação confirmada ao verificar a janela ${decisiveWindowIndex}. A sequência de confirmação cobriu até a janela ${lastCheckedWindowIndex}.`,
      };
    }

    if (invalidRun) {
      return {
        verified: false,
        accepted: false,
        revoked: false,
        decision: "invalid_proof",
        requires_more_windows: false,
        next_required_window_index: null,
        consecutive_hits: invalidRun?.status?.consecutive_hits ?? "",
        credential_start_time: credentialStartTime,
        credential_start_time_human: credentialStartTimeHuman,
        decisive_window_index: null,
        decisive_window_start: null,
        decisive_window_start_human: "",
        scanned_windows: runs.length,
        failure_window_index: invalidRun?.primaryWindowIndex ?? invalidRun?.status?.primary_window_index ?? null,
        details: firstNonEmpty(
          invalidRun?.status?.details,
          invalidRun?.verify?.details,
          "A prova de revogação não foi validada em uma das janelas verificadas."
        ),
      };
    }

    const allRunsSucceeded = scanPlan && successfulRuns.length === scanPlan.steps.length;
    if (allRunsSucceeded) {
      const falsePositiveHits = Number(falsePositiveRun?.status?.consecutive_hits ?? 0);
      const falsePositiveWindow = falsePositiveRun?.primaryWindowIndex ?? null;
      const falsePositiveBreakWindow =
        falsePositiveWindow === null || !Number.isFinite(falsePositiveHits) || falsePositiveHits <= 0
          ? null
          : falsePositiveWindow + Math.trunc(falsePositiveHits);
      return {
        verified: true,
        accepted: true,
        revoked: false,
        decision: "globally_not_revoked",
        requires_more_windows: false,
        next_required_window_index: null,
        consecutive_hits: 0,
        credential_start_time: credentialStartTime,
        credential_start_time_human: credentialStartTimeHuman,
        decisive_window_index: null,
        decisive_window_start: null,
        decisive_window_start_human: "",
        scanned_windows: successfulRuns.length,
        false_positive_confirmed: !!falsePositiveRun,
        false_positive_window_index: falsePositiveWindow,
        false_positive_consecutive_hits: falsePositiveRun ? falsePositiveHits : 0,
        false_positive_break_window_index: falsePositiveBreakWindow,
        details: falsePositiveRun
          ? `Falso positivo confirmado: a janela ${falsePositiveWindow} teve hit no Bloom, mas a sequência de 10 janelas subsequentes não permaneceu positiva. A credencial deve ser considerada válida e não revogada.`
          : `Nenhuma janela válida da credencial indicou revogação após a verificação completa de ${successfulRuns.length} janela(s).`,
      };
    }

    return {
      verified: false,
      accepted: false,
      revoked: false,
      decision: "global_inconclusive",
      requires_more_windows: false,
      next_required_window_index: null,
      consecutive_hits: "",
      credential_start_time: credentialStartTime,
      credential_start_time_human: credentialStartTimeHuman,
      decisive_window_index: null,
      decisive_window_start: null,
      decisive_window_start_human: "",
      scanned_windows: successfulRuns.length,
      details: "Não foi possível concluir a verificação completa em todas as janelas da credencial.",
    };
  }

  function summarizeBuildStep(buildResp, proofSequence) {
    const primaryProof = proofSequence?.primary_proof || {};
    const confirmationProofs = Array.isArray(proofSequence?.confirmation_proofs)
      ? proofSequence.confirmation_proofs
      : [];
    return {
      ok: !!buildResp?.ok,
      primary_window_index: primaryProof?.window_index ?? null,
      confirmation_count: confirmationProofs.length,
      expected_last_window_index: confirmationProofs.length > 0
        ? confirmationProofs[confirmationProofs.length - 1]?.window_index ?? null
        : primaryProof?.window_index ?? null,
      root_merkle_l: firstNonEmpty(
        primaryProof?.control?.root_merkle_l,
        primaryProof?.control?.root_merkle_L
      ) || null,
      error: buildResp?.ok ? null : (buildResp?.error?.message || "Erro montando proof_sequence."),
    };
  }

  function summarizeVerifyStep(verifyResp, verifyData, status) {
    const manifestRefresh = verifyData?.manifestRefresh || null;
    return {
      ok: !!verifyResp?.ok,
      verified: !!status?.verified,
      accepted: !!status?.accepted,
      revoked: !!status?.revoked,
      decision: firstNonEmpty(status?.decision) || null,
      requires_more_windows: !!status?.requires_more_windows,
      next_required_window_index: status?.next_required_window_index ?? null,
      consecutive_hits: status?.consecutive_hits ?? null,
      primary_window_index: status?.primary_window_index ?? null,
      details: firstNonEmpty(status?.details) || null,
      scanned_trace_len: Array.isArray(status?.trace) ? status.trace.length : null,
      manifest_refresh_source: manifestRefresh?.source || null,
      manifest_refresh_hash: manifestRefresh?.effectiveManifestHash || null,
      error: verifyResp?.ok ? null : (verifyResp?.error?.message || "Erro verificando janela."),
    };
  }

  function compactWindowStatus(status) {
    return {
      verified: !!status?.verified,
      accepted: !!status?.accepted,
      revoked: !!status?.revoked,
      decision: firstNonEmpty(status?.decision) || null,
      requires_more_windows: !!status?.requires_more_windows,
      next_required_window_index: status?.next_required_window_index ?? null,
      consecutive_hits: status?.consecutive_hits ?? null,
      primary_window_index: status?.primary_window_index ?? null,
      trace_len: Array.isArray(status?.trace) ? status.trace.length : null,
      details: firstNonEmpty(status?.details) || null,
    };
  }

  function buildScanProgressSummary(scanPlan, scanRuns) {
    const runs = Array.isArray(scanRuns) ? scanRuns : [];
    return {
      total_steps: Array.isArray(scanPlan?.steps) ? scanPlan.steps.length : 0,
      completed_steps: runs.length,
      revoked_detected: runs.some((run) => !!run?.status?.revoked),
      verified_steps: runs.filter((run) => !!run?.status?.verified).length,
    };
  }

  async function yieldToUi() {
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  function fillVerifyStatus(status) {
    const decisiveWindowStart =
      status?.decisive_window_start === undefined || status?.decisive_window_start === null || status?.decisive_window_start === ""
        ? null
        : status?.decisive_window_start;
    $("#rev_verify_verified").value = String(!!status?.verified);
    $("#rev_verify_accepted").value = String(!!status?.accepted);
    $("#rev_verify_revoked").value = String(!!status?.revoked);
    $("#rev_verify_decision").value = firstNonEmpty(status?.decision);
    $("#rev_verify_requires_more").value = String(!!status?.requires_more_windows);
    $("#rev_verify_next_window").value = status?.next_required_window_index ?? "";
    $("#rev_verify_consecutive_hits").value = status?.consecutive_hits ?? "";
    $("#rev_verify_revoked_window").value = status?.decisive_window_index ?? "";
    $("#rev_verify_credential_start_date").value = firstNonEmpty(
      status?.credential_start_time_human,
      formatCredentialStartTimestamp(loadedBundle)
    );
    $("#rev_verify_revoked_window_date").value = firstNonEmpty(
      status?.decisive_window_start_human,
      decisiveWindowStart === null ? "" : formatWindowTimestamp(decisiveWindowStart)
    );
    $("#rev_verify_scanned_windows").value = status?.scanned_windows ?? "";
    $("#rev_verify_elapsed_time").value = firstNonEmpty(
      status?.elapsed_time_human,
      status?.elapsed_ms === undefined || status?.elapsed_ms === null ? "" : formatElapsedMs(status.elapsed_ms)
    );
    $("#rev_verify_status_summary").value = buildSimpleStatusSummary(status);
  }

  async function refreshCredentialList() {
    Api.setStatus("Listando credenciais da wallet para verificação de revogação...");
    const r = await Api.credential.list(null, null);
    setOut({ where: "revocationVerify.refreshCredentialList", resp: r });
    credentialListLoaded = true;

    if (!r?.ok) {
      lastCredentials = [];
      filteredCredentialsView = [];
      filteredCredentialsCacheKey = "";
      credentialsPageIndex = 1;
      renderCredentialTable();
      Api.setStatus(`Erro listando credenciais: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    lastCredentials = parseCredentialsList(r.data);
    filteredCredentialsView = [];
    filteredCredentialsCacheKey = "";
    credentialsPageIndex = 1;
    renderCredentialTable();
    Api.setStatus(`Credenciais carregadas para seleção: ${getVisibleCredentials().length}.`);
  }

  function clearCredentialFilter() {
    $("#rev_verify_cred_filter").value = "";
    $("#rev_verify_attr_name_filter").value = "";
    $("#rev_verify_attr_value_filter").value = "";
    credentialsPageIndex = 1;
    filteredCredentialsCacheKey = "";
    renderCredentialTable();
  }

  async function importCredentialForVerify() {
    const genesisPath = getGenesisPathValue();
    const holderDid = toStringSafe($("#rev_verify_import_holder_did").value).trim() || null;
    const credentialFilePath = toStringSafe($("#rev_verify_import_credential_file_path").value).trim() || null;

    if (genesisPath && toStringSafe($("#rev_verify_import_genesis_path").value).trim() !== genesisPath) {
      $("#rev_verify_import_genesis_path").value = genesisPath;
    }

    resetLoadedBundleState();
    showImportResult({});

    if (!genesisPath) {
      showImportResult({
        ok: false,
        error: {
          code: "MISSING_GENESIS_PATH",
          message: "Informe o genesis path para importar a credencial.",
        },
      });
      Api.setStatus("Informe o genesis path para importar a credencial.");
      return;
    }

    const input = {
      genesisPath,
      holderDid,
      credentialFilePath,
    };

    Api.setStatus("Importando credencial para verificar revogação...");
    const r = await Api.credReceive.importAndStoreEnvelope(input);
    setOut({ where: "revocationVerify.importCredentialForVerify", input, resp: r });
    showImportResult(r);

    if (r?.canceled) {
      Api.setStatus("Importação cancelada.");
      return;
    }

    if (!r?.ok) {
      Api.setStatus(`Erro importando credencial: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    const data = parseMaybeJson(r.data) || {};
    $("#rev_verify_import_credential_file_path").value = firstNonEmpty(
      data?.credentialFilePath,
      $("#rev_verify_import_credential_file_path").value
    );
    $("#rev_verify_import_holder_did").value = firstNonEmpty(
      data?.holderDid,
      $("#rev_verify_import_holder_did").value
    );

    if (!data?.revocable) {
      await refreshCredentialList();
      const credentialId = firstNonEmpty(data?.credentialId);
      const importedRec = findCredentialById(credentialId) || {
        credentialId,
        credentialFilePath: data?.credentialFilePath || null,
        holderDid: data?.holderDid || null,
        revocable: false,
      };
      applyCredentialSelection(importedRec);
      const message = buildNonRevocableWarning(importedRec);
      showWarning(message);
      Api.setStatus("A credencial foi importada, mas não é revogável.");
      return;
    }

    const credentialId = firstNonEmpty(data?.credentialId);
    const bundleId = firstNonEmpty(data?.bundleIdLocal, credentialId ? `revocation-bundle-${credentialId}` : "");
    if (credentialId) $("#rev_verify_credential_id").value = credentialId;
    if (bundleId) $("#rev_verify_bundle_id").value = bundleId;

    await refreshCredentialList();
    const importedRec = findCredentialById(credentialId);
    if (importedRec) {
      applyCredentialSelection(importedRec);
    } else {
      showSelectedCredential({
        credentialId,
        bundleIdLocal: bundleId,
        credentialFilePath: data?.credentialFilePath || null,
        holderDid: data?.holderDid || null,
        alreadyStored: !!data?.alreadyStored,
        revocable: !!data?.revocable,
      });
    }

    if (bundleId) {
      await loadBundle();
      Api.setStatus(data?.alreadyStored
        ? `Credencial já existia na wallet e foi reutilizada para verificar revogação: ${bundleId}.`
        : `Credencial importada e pronta para verificar revogação: ${bundleId}.`);
      return;
    }

    Api.setStatus("A credencial foi importada, mas não foi possível determinar o bundle de revogação.");
  }

  async function loadBundle() {
    const bundleIdLocal = toStringSafe($("#rev_verify_bundle_id").value).trim();
    if (!bundleIdLocal) {
      const selectedRec = getSelectedCredentialRecord();
      if (selectedRec && !isCredentialRevocable(selectedRec)) {
        const message = buildNonRevocableWarning(selectedRec);
        showWarning(message);
        Api.setStatus("Credencial não revogável: não existe bundle de revogação para carregar.");
        return;
      }
      Api.setStatus("Informe o Bundle ID local.");
      return;
    }

    Api.setStatus("Carregando holder revocation bundle da wallet...");
    const r = await Api.revocationVerify.getHolderBundle({ bundleIdLocal });
    setOut({ where: "revocationVerify.loadBundle", input: { bundleIdLocal }, resp: r });
    showResult(r);

    if (!r?.ok) {
      Api.setStatus(`Erro carregando bundle: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    loadedBundle = parseMaybeJson(r.data);
    $("#rev_verify_bundle_out").value = JSON.stringify(loadedBundle || {}, null, 2);
    $("#rev_verify_credential_start_date").value = formatCredentialStartTimestamp(loadedBundle);
    const layout = getBundleWindowLayout(loadedBundle);
    if (layout) {
      $("#rev_verify_valid_windows").value = String(layout.baseWindowCount);
      $("#rev_verify_confirmation_windows").value = String(layout.confirmationWindowCount);
      $("#rev_verify_total_windows").value = String(layout.totalWindowCount);
    } else {
      $("#rev_verify_valid_windows").value = "";
      $("#rev_verify_confirmation_windows").value = "";
      $("#rev_verify_total_windows").value = "";
    }
    const inferredCredentialId = firstNonEmpty(loadedBundle?.credential_id);
    if (inferredCredentialId && !toStringSafe($("#rev_verify_credential_id").value).trim()) {
      $("#rev_verify_credential_id").value = inferredCredentialId;
    }
    const inferredRoot = firstNonEmpty(
      loadedBundle?.control?.root_merkle_l,
      loadedBundle?.control?.root_merkle_L
    );
    if (inferredRoot) {
      $("#rev_verify_expected_root").value = inferredRoot;
    }
    const control = loadedBundle?.control || {};
    const timeWindow = Number(control?.time_window);
    const unitOfTime = toStringSafe(control?.unit_of_time).trim();
    if (layout && layout.baseWindowCount === 1 && Number.isFinite(timeWindow) && timeWindow > 1) {
      Api.setStatus(
        `Bundle carregado: ${bundleIdLocal}. Aviso: esta credencial foi emitida com 1 janela válida de ${Math.trunc(timeWindow)} ${unitOfTime}, e não com várias janelas menores. Para obter 365 janelas diárias, a emissão precisa usar tamanho de cada janela = 1 e quantidade de janelas válidas = 365.`
      );
      return;
    }
    Api.setStatus(`Bundle carregado: ${bundleIdLocal}.`);
  }

  async function useCurrentWindow() {
    if (!loadedBundle) {
      await loadBundle();
      if (!loadedBundle) return;
    }
    const inferred = inferLatestAvailableWindowIndex(loadedBundle);
    if (inferred === null) {
      Api.setStatus("Não foi possível inferir as janelas disponíveis a partir do bundle.");
      return;
    }
    const plan = buildAutomaticProofWindowPlan(loadedBundle, inferred);
    if (!plan) {
      Api.setStatus("Não foi possível preparar a sequência automática de janelas.");
      return;
    }
        Api.setStatus(
          plan.additionalWindowCount > 0
            ? `A janela atual calculada seria ${plan.primaryWindowIndex}, com confirmações até a janela ${plan.latestAvailableWindowIndex}.`
            : `A janela atual calculada seria ${plan.primaryWindowIndex}.`
        );
  }

  async function buildProofSequence() {
    if (!loadedBundle) {
      await loadBundle();
      if (!loadedBundle) return;
    }

    const bundleIdLocal = toStringSafe($("#rev_verify_bundle_id").value).trim();
    const credentialIdLocal = toStringSafe($("#rev_verify_credential_id").value).trim() || null;
    let primaryWindowIndex = 0;
    let additionalWindowCount = DEFAULT_ADDITIONAL_WINDOWS;

    if (!bundleIdLocal) {
      Api.setStatus("Informe o Bundle ID local.");
      return;
    }
    if (!Number.isFinite(primaryWindowIndex) || primaryWindowIndex < 0) {
      Api.setStatus("Janela principal inválida.");
      return;
    }
    if (!Number.isFinite(additionalWindowCount) || additionalWindowCount < 0) {
      Api.setStatus("Janelas adicionais inválidas.");
      return;
    }

    const autoPlan = buildAutomaticProofWindowPlan(loadedBundle, primaryWindowIndex);
    if (autoPlan) {
      primaryWindowIndex = autoPlan.primaryWindowIndex;
      additionalWindowCount = autoPlan.additionalWindowCount;
    }

    Api.setStatus("Montando proof_sequence de revogação...");
    const r = await Api.revocationVerify.buildProofSequence({
      bundleIdLocal,
      credentialIdLocal,
      primaryWindowIndex: Math.trunc(primaryWindowIndex),
      additionalWindowCount: Math.trunc(additionalWindowCount),
    });
    setOut({
      where: "revocationVerify.buildProofSequence",
      input: {
        bundleIdLocal,
        credentialIdLocal,
        primaryWindowIndex: Math.trunc(primaryWindowIndex),
        additionalWindowCount: Math.trunc(additionalWindowCount),
      },
      resp: r,
    });
    showResult(r);

    if (!r?.ok) {
      Api.setStatus(`Erro montando proof_sequence: ${r?.error?.message || "erro desconhecido"}`);
      return;
    }

    const data = parseMaybeJson(r.data);
    $("#rev_verify_proof_json").value = JSON.stringify(data?.proof_sequence || {}, null, 2);
    const expectedRoot = firstNonEmpty(
      data?.proof_sequence?.primary_proof?.control?.root_merkle_l,
      data?.proof_sequence?.primary_proof?.control?.root_merkle_L,
      $("#rev_verify_expected_root").value
    );
    $("#rev_verify_expected_root").value = expectedRoot;
    Api.setStatus("Proof sequence montada com sucesso.");
  }

  async function verifyWindowScanStep({
    bundleIdLocal,
    credentialIdLocal,
    expectedRootMerkleL,
    policyJson,
    genesisPath,
    step,
  }) {
    const buildResp = await Api.revocationVerify.buildProofSequence({
      bundleIdLocal,
      credentialIdLocal,
      primaryWindowIndex: step.primaryWindowIndex,
      additionalWindowCount: step.additionalWindowCount,
    });

    const buildData = parseMaybeJson(buildResp?.data);
    const proofSequence = buildData?.proof_sequence || null;
    const proofSequenceJson = proofSequence ? JSON.stringify(proofSequence) : "";
    const buildSummary = summarizeBuildStep(buildResp, proofSequence);

    if (!buildResp?.ok || !proofSequenceJson) {
      return {
        ok: false,
        error: buildResp?.error?.message || "Erro montando proof_sequence para a janela.",
        proofSequence: null,
        status: null,
        run: {
          primaryWindowIndex: step.primaryWindowIndex,
          additionalWindowCount: step.additionalWindowCount,
          build: buildSummary,
          verify: null,
          status: null,
        },
      };
    }

    const verifyResp = await Api.revocationVerify.verifyProofSequence({
      proofSequenceJson,
      expectedRootMerkleL,
      policyJson,
      genesisPath,
      storeEvent: false,
    });
    const verifyData = parseMaybeJson(verifyResp?.data);
    const status = verifyData?.status || null;
    const verifySummary = summarizeVerifyStep(verifyResp, verifyData, status);
    const compactStatus = compactWindowStatus(status);
    const run = {
      primaryWindowIndex: step.primaryWindowIndex,
      additionalWindowCount: step.additionalWindowCount,
      build: buildSummary,
      verify: verifySummary,
      status: compactStatus,
    };

    if (!verifyResp?.ok || !status) {
      return {
        ok: false,
        error: verifyResp?.error?.message || "Erro desconhecido na verificação da janela.",
        proofSequence,
        status,
        run,
      };
    }

    return {
      ok: true,
      error: null,
      proofSequence,
      status,
      run,
    };
  }

  async function verifyProofSequence(options = {}) {
    if (!options?.userInitiated) return;

    const selectedRec = getSelectedCredentialRecord();
    if (selectedRec && !isCredentialRevocable(selectedRec)) {
      const message = buildNonRevocableWarning(selectedRec);
      resetBundleDerivedState();
      showWarning(message);
      Api.setStatus("Credencial não revogável: não há revogação a verificar.");
      return;
    }

    if (!loadedBundle) {
      await loadBundle();
      if (!loadedBundle) return;
    }

    const bundleIdLocal = toStringSafe($("#rev_verify_bundle_id").value).trim();
    const credentialIdLocal = toStringSafe($("#rev_verify_credential_id").value).trim() || null;
    const expectedRootMerkleL = toStringSafe($("#rev_verify_expected_root").value).trim() || null;
    const policyJson = toStringSafe($("#rev_verify_policy_json").value).trim() || null;
    const genesisPath = getGenesisPathValue() || null;

    if (!bundleIdLocal) {
      Api.setStatus("Informe o Bundle ID local.");
      return;
    }

    const scanPlan = buildExhaustiveWindowScanPlan(loadedBundle);
    if (!scanPlan || !Array.isArray(scanPlan.steps) || scanPlan.steps.length === 0) {
      Api.setStatus("Não foi possível calcular as janelas da credencial para a verificação completa.");
      return;
    }

    clearVerifyStatus();
    const scanRuns = [];
    $("#rev_verify_proof_json").value = "";
    const scanStartedAt = typeof performance !== "undefined" && typeof performance.now === "function"
      ? performance.now()
      : Date.now();

    if (scanPlan.steps.length >= VERIFY_BINARY_SEARCH_THRESHOLD) {
      const cachedProbeResults = new Map();
      const cachedConfirmationResults = new Map();
      let fallbackToExhaustive = false;
      let fallbackReason = "";

      const getProbeResult = async (windowIndex) => {
        const key = Math.max(0, Math.trunc(Number(windowIndex) || 0));
        if (cachedProbeResults.has(key)) return cachedProbeResults.get(key);
        const step = {
          primaryWindowIndex: key,
          additionalWindowCount: 0,
          lastConfirmationWindowIndex: scanPlan.lastConfirmationWindowIndex,
        };
        const result = await verifyWindowScanStep({
          bundleIdLocal,
          credentialIdLocal,
          expectedRootMerkleL,
          policyJson,
          genesisPath,
          step,
        });
        const entry = { index: key, step, result };
        cachedProbeResults.set(key, entry);
        scanRuns.push(result.run);
        return entry;
      };

      const getConfirmationResult = async (windowIndex) => {
        const key = Math.max(0, Math.trunc(Number(windowIndex) || 0));
        if (cachedConfirmationResults.has(key)) return cachedConfirmationResults.get(key);
        const step = buildWindowScanStep(scanPlan, key);
        const result = await verifyWindowScanStep({
          bundleIdLocal,
          credentialIdLocal,
          expectedRootMerkleL,
          policyJson,
          genesisPath,
          step,
        });
        const entry = { index: key, step, result };
        cachedConfirmationResults.set(key, entry);
        scanRuns.push(result.run);
        return entry;
      };

      const classifyProbeStatus = (status) => {
        if (!status?.verified) return "invalid";
        if (status?.revoked) return "candidate";
        if (status?.requires_more_windows) return "candidate";
        if (Number(status?.consecutive_hits ?? 0) > 0) return "candidate";
        if (status?.accepted && !status?.revoked) return "clean";
        if (status?.decision === "valid_not_revoked") return "clean";
        return "invalid";
      };

      let low = 0;
      let high = scanPlan.lastValidWindowIndex;
      let candidateEntry = null;

      while (low <= high) {
        const mid = Math.floor((low + high) / 2);
        Api.setStatus(`Verificando revogação com busca binária: janela ${mid} (faixa ${low}-${high})...`);
        const entry = await getProbeResult(mid);
        const status = entry?.result?.status || null;
        const probeClass = classifyProbeStatus(status);

        if (!entry?.result?.ok || probeClass === "invalid") {
          fallbackToExhaustive = true;
          fallbackReason = entry?.result?.error
            || status?.details
            || "A busca binária encontrou uma resposta inconclusiva.";
          break;
        }

        if (probeClass === "clean") {
          low = mid + 1;
        } else {
          const confirmationEntry = await getConfirmationResult(mid);
          const confirmationStatus = confirmationEntry?.result?.status || null;
          if (!confirmationEntry?.result?.ok || !confirmationStatus?.verified || confirmationStatus?.requires_more_windows) {
            fallbackToExhaustive = true;
            fallbackReason = confirmationEntry?.result?.error
              || confirmationStatus?.details
              || "Não foi possível confirmar o indício de revogação encontrado na busca binária.";
            break;
          }

          if (confirmationStatus?.revoked) {
            candidateEntry = confirmationEntry;
            high = mid - 1;
          } else {
            low = mid + 1;
          }
        }
        await yieldToUi();
      }

      if (!fallbackToExhaustive) {
        if (candidateEntry) {
          let refinedCandidate = candidateEntry;
          while (refinedCandidate.index > 0) {
            const previousProbeEntry = await getProbeResult(refinedCandidate.index - 1);
            const previousProbeStatus = previousProbeEntry?.result?.status || null;
            const previousProbeClass = classifyProbeStatus(previousProbeStatus);
            if (!previousProbeEntry?.result?.ok || previousProbeClass === "invalid") {
              fallbackToExhaustive = true;
              fallbackReason = previousProbeEntry?.result?.error
                || previousProbeStatus?.details
                || "Não foi possível confirmar a janela imediatamente anterior ao ponto de revogação.";
              break;
            }

            if (previousProbeClass === "clean") break;

            const previousConfirmationEntry = await getConfirmationResult(refinedCandidate.index - 1);
            const previousConfirmationStatus = previousConfirmationEntry?.result?.status || null;
            if (!previousConfirmationEntry?.result?.ok || !previousConfirmationStatus?.verified || previousConfirmationStatus?.requires_more_windows) {
              fallbackToExhaustive = true;
              fallbackReason = previousConfirmationEntry?.result?.error
                || previousConfirmationStatus?.details
                || "Não foi possível confirmar a janela imediatamente anterior ao ponto de revogação.";
              break;
            }
            if (!previousConfirmationStatus?.revoked) break;
            refinedCandidate = previousConfirmationEntry;
            await yieldToUi();
          }

          if (!fallbackToExhaustive) {
            $("#rev_verify_proof_json").value = JSON.stringify(refinedCandidate.result.proofSequence || {}, null, 2);
            const processingTime = buildProcessingTime(scanStartedAt);
            const orderedRuns = scanRuns.slice().sort((a, b) => Number(a?.primaryWindowIndex ?? 0) - Number(b?.primaryWindowIndex ?? 0));
            const globalStatus = {
              ...buildBinarySearchGlobalStatus(loadedBundle, scanPlan, orderedRuns, refinedCandidate.result.run),
              ...processingTime,
            };
            const progress = {
              total_steps: scanPlan.steps.length,
              completed_steps: orderedRuns.length,
              revoked_detected: true,
              verified_steps: orderedRuns.filter((run) => !!run?.status?.verified).length,
              ...processingTime,
            };
            setOut({
              where: "revocationVerify.verifyProofSequence.binarySearch",
              input: {
                bundleIdLocal,
                credentialIdLocal,
                expectedRootMerkleL,
                hasPolicyJson: !!policyJson,
                scanPlan,
                threshold: VERIFY_BINARY_SEARCH_THRESHOLD,
              },
              resp: {
                ok: true,
                globalStatus,
                progress,
                scanRuns: orderedRuns,
                processingTime,
              },
            });
            showResult({
              ok: true,
              data: {
                mode: "binary_window_search",
                threshold: VERIFY_BINARY_SEARCH_THRESHOLD,
                globalStatus,
                progress,
                scanRuns: orderedRuns,
                processingTime,
              },
            });
            fillVerifyStatus(globalStatus);
            Api.setStatus(`Revogação verificada em ${processingTime.elapsed_time_human}: a credencial foi confirmada como revogada com busca binária.`);
            return;
          }
        } else {
          const binaryOrderedRuns = scanRuns
            .slice()
            .sort((a, b) => Number(a?.primaryWindowIndex ?? 0) - Number(b?.primaryWindowIndex ?? 0));
          const tailConfirmationResult = await runTailConfirmationCheck({
            scanPlan,
            getProbeResult,
          });
          if (tailConfirmationResult?.outcome === "needs_more_windows") {
            fallbackToExhaustive = true;
            fallbackReason = "A confirmação extra nas janelas finais encontrou um indício de revogação. Como esta consulta do Holder já possui todas as janelas da credencial, a tela seguirá com a verificação completa em vez de solicitar janelas extras.";
          } else {
            const processingTime = buildProcessingTime(scanStartedAt);
            const orderedRuns = scanRuns.slice().sort((a, b) => Number(a?.primaryWindowIndex ?? 0) - Number(b?.primaryWindowIndex ?? 0));
            let globalStatus = {
              ...buildBinarySearchGlobalStatus(loadedBundle, scanPlan, binaryOrderedRuns, null),
              ...processingTime,
            };
            if (tailConfirmationResult) {
              globalStatus = mergeTailConfirmationIntoStatus(globalStatus, tailConfirmationResult);
            }
            const progress = {
              total_steps: scanPlan.steps.length,
              completed_steps: orderedRuns.length,
              revoked_detected: !!globalStatus?.revoked,
              verified_steps: orderedRuns.filter((run) => !!run?.status?.verified).length,
              ...processingTime,
            };
            setOut({
              where: "revocationVerify.verifyProofSequence.binarySearch",
              input: {
                bundleIdLocal,
                credentialIdLocal,
                expectedRootMerkleL,
                hasPolicyJson: !!policyJson,
                scanPlan,
                threshold: VERIFY_BINARY_SEARCH_THRESHOLD,
              },
              resp: {
                ok: true,
                globalStatus,
                progress,
                scanRuns: orderedRuns,
                processingTime,
              },
            });
            showResult({
              ok: true,
              data: {
                mode: "binary_window_search",
                threshold: VERIFY_BINARY_SEARCH_THRESHOLD,
                globalStatus,
                progress,
                scanRuns: orderedRuns,
                processingTime,
              },
            });
            fillVerifyStatus(globalStatus);
            Api.setStatus(
              `Revogação verificada em ${processingTime.elapsed_time_human}: a credencial não foi encontrada como revogada, e as janelas finais disponíveis também foram confirmadas.`
            );
            return;
          }
        }
      }

      if (fallbackToExhaustive) {
        Api.setStatus(`Busca binária inconclusiva; voltando para a verificação completa (${fallbackReason}).`);
        scanRuns.length = 0;
        $("#rev_verify_proof_json").value = "";
      }
    }

    for (let offset = 0; offset < scanPlan.steps.length; offset += VERIFY_SCAN_CONCURRENCY) {
      const batch = scanPlan.steps.slice(offset, offset + VERIFY_SCAN_CONCURRENCY);
      const firstStep = batch[0];
      const lastStep = batch[batch.length - 1];
      const progressStart = offset + 1;
      const progressEnd = offset + batch.length;
      Api.setStatus(
        batch.length > 1
          ? `Verificando revogação em paralelo: janelas ${firstStep.primaryWindowIndex} a ${lastStep.primaryWindowIndex} (${progressStart}-${progressEnd}/${scanPlan.steps.length})...`
          : `Verificando revogação: janela ${firstStep.primaryWindowIndex} (${progressStart}/${scanPlan.steps.length})...`
      );

      const batchResults = await Promise.all(batch.map(async (step, batchIndex) => ({
        index: offset + batchIndex,
        step,
        result: await verifyWindowScanStep({
          bundleIdLocal,
          credentialIdLocal,
          expectedRootMerkleL,
          policyJson,
          genesisPath,
          step,
        }),
      })));
      const orderedResults = batchResults.sort((a, b) => a.index - b.index);

      for (const item of orderedResults) {
        scanRuns.push(item.result.run);
      }

      const revokedItem = orderedResults
        .filter((item) => item.result.ok && item.result.status?.revoked)
        .sort((a, b) => a.step.primaryWindowIndex - b.step.primaryWindowIndex)[0];
      if (revokedItem) {
        $("#rev_verify_proof_json").value = JSON.stringify(revokedItem.result.proofSequence || {}, null, 2);
        const processingTime = buildProcessingTime(scanStartedAt);
        const globalStatus = {
          ...buildGlobalRevocationStatus(loadedBundle, scanPlan, scanRuns),
          ...processingTime,
        };
        const progress = {
          ...buildScanProgressSummary(scanPlan, scanRuns),
          ...processingTime,
        };
        setOut({
          where: "revocationVerify.verifyProofSequence.exhaustive",
          input: {
            bundleIdLocal,
            credentialIdLocal,
            expectedRootMerkleL,
            hasPolicyJson: !!policyJson,
            scanPlan,
            concurrency: VERIFY_SCAN_CONCURRENCY,
          },
          resp: {
            ok: true,
            globalStatus,
            progress,
            scanRuns,
            processingTime,
          },
        });
        showResult({
          ok: true,
          data: {
            mode: "full_window_scan",
            concurrency: VERIFY_SCAN_CONCURRENCY,
            globalStatus,
            progress,
            scanRuns,
            processingTime,
          },
        });
        fillVerifyStatus(globalStatus);
        Api.setStatus(`Revogação verificada em ${processingTime.elapsed_time_human}: a credencial está revogada em pelo menos uma janela válida.`);
        return;
      }

      const failedItem = orderedResults.find((item) => !item.result.ok);
      if (failedItem) {
        const errorMessage = failedItem.result.error || "Erro desconhecido na verificação da janela.";
        const processingTime = buildProcessingTime(scanStartedAt);
        const globalStatus = {
          ...buildGlobalRevocationStatus(loadedBundle, scanPlan, scanRuns),
          ...processingTime,
        };
        const progress = {
          ...buildScanProgressSummary(scanPlan, scanRuns),
          ...processingTime,
        };
        setOut({
          where: "revocationVerify.verifyProofSequence.exhaustive",
          input: {
            bundleIdLocal,
            credentialIdLocal,
            expectedRootMerkleL,
            hasPolicyJson: !!policyJson,
            scanPlan,
            concurrency: VERIFY_SCAN_CONCURRENCY,
          },
          resp: {
            ok: false,
            globalStatus,
            progress,
            scanRuns,
            processingTime,
          },
        });
        showResult({
          ok: false,
          error: { message: errorMessage },
          globalStatus,
          progress,
          scanRuns,
          processingTime,
        });
        fillVerifyStatus(globalStatus);
        Api.setStatus(`Erro verificando revogação após ${processingTime.elapsed_time_human}: ${errorMessage}`);
        return;
      }

      await yieldToUi();
    }

    const processingTime = buildProcessingTime(scanStartedAt);
    const globalStatus = {
      ...buildGlobalRevocationStatus(loadedBundle, scanPlan, scanRuns),
      ...processingTime,
    };
    const progress = {
      ...buildScanProgressSummary(scanPlan, scanRuns),
      ...processingTime,
    };
    setOut({
      where: "revocationVerify.verifyProofSequence.exhaustive",
      input: {
        bundleIdLocal,
        credentialIdLocal,
        expectedRootMerkleL,
        hasPolicyJson: !!policyJson,
        scanPlan,
      },
      resp: {
        ok: true,
        globalStatus,
        progress,
        scanRuns,
        concurrency: VERIFY_SCAN_CONCURRENCY,
        processingTime,
      },
    });
    showResult({
      ok: true,
      data: {
        mode: "full_window_scan",
        concurrency: VERIFY_SCAN_CONCURRENCY,
        globalStatus,
        progress,
        scanRuns,
        processingTime,
      },
    });
    fillVerifyStatus(globalStatus);
    Api.setStatus(globalStatus?.accepted
      ? `Revogação verificada em ${processingTime.elapsed_time_human}: a credencial não foi encontrada como revogada em nenhuma janela válida.`
      : `Verificação completa concluída em ${processingTime.elapsed_time_human}.`);
  }

  $("#btn_rev_verify_load_bundle").addEventListener("click", loadBundle);
  $("#btn_rev_verify_list_refresh").addEventListener("click", refreshCredentialList);
  $("#btn_rev_verify_list_search").addEventListener("click", () => {
    credentialsPageIndex = 1;
    filteredCredentialsCacheKey = "";
    renderCredentialTable();
  });
  $("#btn_rev_verify_list_clear").addEventListener("click", clearCredentialFilter);
  $("#btn_rev_verify_import_credential").addEventListener("click", importCredentialForVerify);
  if ($("#btn_rev_verify_current_window")) $("#btn_rev_verify_current_window").addEventListener("click", useCurrentWindow);
  if ($("#btn_rev_verify_build_proof")) $("#btn_rev_verify_build_proof").addEventListener("click", buildProofSequence);
  $("#btn_rev_verify_execute").addEventListener("click", () => verifyProofSequence({ userInitiated: true }));

  $("#tbl_rev_verify_credentials").addEventListener("click", async (ev) => {
    const btn = ev.target.closest("button[data-act]");
    const tr = ev.target.closest("tr[data-cred-id]");
    if (!btn || !tr) return;

    const credId = toStringSafe(tr.dataset.credId).trim();
    const rec = filteredCredentialsView.find((item) => toStringSafe(item?.id_local).trim() === credId) || null;
    if (!rec) return;

    if (btn.dataset.act === "view") {
      showSelectedCredential(rec);
      Api.setStatus(`Visualizando credencial: ${toStringSafe(rec.id_local)}`);
      return;
    }

    if (btn.dataset.act === "use") {
      $("#rev_verify_import_result").value = "";
      applyCredentialSelection(rec);
      if (!isCredentialRevocable(rec)) {
        const message = buildNonRevocableWarning(rec);
        showWarning(message);
        Api.setStatus("Credencial não revogável: não há bundle nem revogação a verificar.");
        return;
      }
      await loadBundle();
    }
  });

  $("#btn_rev_verify_warning_close").addEventListener("click", closeWarning);
  $("#rev_verify_warning_modal").addEventListener("click", (ev) => {
    if (ev.target && ev.target.id === "rev_verify_warning_modal") closeWarning();
  });
  root.addEventListener("keydown", (ev) => {
    if (ev.key !== "Escape") return;
    const modal = $("#rev_verify_warning_modal");
    if (modal && modal.style.display !== "none") closeWarning();
  });

  $("#rev_verify_cred_filter").addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter") return;
    credentialsPageIndex = 1;
    filteredCredentialsCacheKey = "";
    renderCredentialTable();
  });
  $("#rev_verify_cred_filter").addEventListener("input", () => {
    if (hasAttributeFilter()) return;
    credentialsPageIndex = 1;
    filteredCredentialsCacheKey = "";
    renderCredentialTable();
  });
  $("#rev_verify_attr_name_filter").addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter") return;
    credentialsPageIndex = 1;
    filteredCredentialsCacheKey = "";
    renderCredentialTable();
  });
  $("#rev_verify_attr_value_filter").addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter") return;
    credentialsPageIndex = 1;
    filteredCredentialsCacheKey = "";
    renderCredentialTable();
  });
  $("#rev_verify_cred_page_size").addEventListener("change", () => {
    credentialsPageIndex = 1;
    renderCredentialTable({ reuseFiltered: true });
  });
  $("#btn_rev_verify_cred_first").addEventListener("click", () => {
    credentialsPageIndex = 1;
    renderCredentialTable({ reuseFiltered: true });
  });
  $("#btn_rev_verify_cred_prev").addEventListener("click", () => {
    credentialsPageIndex -= 1;
    renderCredentialTable({ reuseFiltered: true });
  });
  $("#btn_rev_verify_cred_next").addEventListener("click", () => {
    credentialsPageIndex += 1;
    renderCredentialTable({ reuseFiltered: true });
  });
  $("#btn_rev_verify_cred_last").addEventListener("click", () => {
    credentialsPageSize = Number($("#rev_verify_cred_page_size").value || CREDENTIALS_PAGE_SIZE_DEFAULT);
    if (!Number.isFinite(credentialsPageSize) || credentialsPageSize < 1) {
      credentialsPageSize = CREDENTIALS_PAGE_SIZE_DEFAULT;
    }
    const totalPages = Math.max(1, Math.ceil(filteredCredentialsView.length / credentialsPageSize));
    credentialsPageIndex = totalPages;
    renderCredentialTable({ reuseFiltered: true });
  });
  $("#rev_verify_cred_page_index").addEventListener("change", () => {
    const value = Number($("#rev_verify_cred_page_index").value);
    if (!Number.isNaN(value) && value >= 1) credentialsPageIndex = Math.trunc(value);
    renderCredentialTable({ reuseFiltered: true });
  });

  window.addEventListener("app:pagechange", (ev) => {
    if (ev?.detail?.page !== "revocation-verify") return;
    Api.setStatus("Verificar Revogação pronto. Clique em Verificar revogação para iniciar.");
  });

  syncGenesisPathInput();
  renderCredentialTable();
  return {};
})();
