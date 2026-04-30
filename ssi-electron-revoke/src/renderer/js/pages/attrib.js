const AttribPage = (() => {
  const root = document.getElementById("page-attrib");
  if (!root) return {};
  const DEFAULT_DID_LIMIT = 150;
  const MAX_DID_LIMIT = 1000;

  root.innerHTML = `
    <div class="card">
      <h2>Escrever ATTRIBs</h2>
      <p class="small">
        Selecione um DID, escreva um ATTRIB no ledger e leia o conteúdo por chave.
      </p>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Genesis path</label>
          <input id="attrib_genesis" placeholder="/caminho/para/genesis.txn" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>DID (lista local)</label>
          <select id="attrib_did_select">
            <option value="">Selecione um DID...</option>
          </select>
        </div>
        <button class="secondary" id="btn_attrib_refresh_dids">Atualizar DIDs</button>
      </div>
      <div class="row">
        <div class="input" style="min-width:360px">
          <label>Filtro da lista de DIDs</label>
          <input id="attrib_did_filter" placeholder="Filtrar por DID, alias, verkey ou categoria..." />
        </div>
        <div class="input" style="min-width:180px">
          <label>Máximo exibido</label>
          <input id="attrib_did_limit" type="number" min="1" max="${MAX_DID_LIMIT}" value="${DEFAULT_DID_LIMIT}" />
        </div>
        <button class="secondary" id="btn_attrib_clear_filter">Limpar filtro</button>
      </div>
      <p class="small" id="attrib_did_stats">DIDs: 0</p>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>DID selecionado (editável)</label>
          <input id="attrib_did" placeholder="did:sov:... ou did curto" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:320px">
          <label>Chave do ATTRIB</label>
          <input id="attrib_key" placeholder="ex.: service_url" />
        </div>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Valor para escrita</label>
          <textarea id="attrib_value" rows="3" placeholder="ex.: https://meu-agente.com/didcomm"></textarea>
        </div>
      </div>

      <div class="row">
        <button class="primary" id="btn_attrib_write">Escrever ATTRIB</button>
        <button class="secondary" id="btn_attrib_read">Ler ATTRIB</button>
        <button class="secondary" id="btn_attrib_exists">Verificar existência</button>
      </div>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Valor lido</label>
          <textarea id="attrib_read_value" rows="3" readonly></textarea>
        </div>
      </div>

      <h3>Resultado</h3>
      <pre id="attrib_out">{}</pre>
    </div>
  `;

  const $ = (sel) => root.querySelector(sel);
  const out = $("#attrib_out");
  const didSelect = $("#attrib_did_select");
  const didFilterInput = $("#attrib_did_filter");
  const didLimitInput = $("#attrib_did_limit");
  const didStats = $("#attrib_did_stats");
  const didInput = $("#attrib_did");
  const readValue = $("#attrib_read_value");

  let didOptions = [];
  let visibleDidOptions = [];

  function setOut(obj) {
    out.textContent = JSON.stringify(obj, null, 2);
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

  function toSearchBlob(rec) {
    return normalizeText([
      rec.did,
      rec.alias,
      rec.verkey,
      rec.category,
    ].filter(Boolean).join(" "));
  }

  function renderDidSelect(items) {
    const currentDid = String(didInput.value || "").trim();
    didSelect.innerHTML = `<option value="">Selecione um DID...</option>`;

    const fragment = document.createDocumentFragment();
    items.forEach((d) => {
      const opt = document.createElement("option");
      opt.value = d.did;
      const aliasPrefix = d.alias ? `${d.alias} - ` : "";
      const suffix = d.category ? ` (${d.category})` : "";
      opt.textContent = `${aliasPrefix}${d.did}${suffix}`;
      fragment.appendChild(opt);
    });
    didSelect.appendChild(fragment);

    if (currentDid && items.some((d) => d.did === currentDid)) {
      didSelect.value = currentDid;
    }
  }

  function updateDidStats(total, filtered, shown, limit) {
    didStats.textContent = `DIDs: total ${total} | filtrados ${filtered} | exibidos ${shown} (máx ${limit})`;
  }

  function applyDidFilter() {
    const filterText = normalizeText(didFilterInput.value).trim();
    const limit = parseDidLimit(didLimitInput.value);
    didLimitInput.value = String(limit);

    const filtered = filterText
      ? didOptions.filter((d) => toSearchBlob(d).includes(filterText))
      : didOptions;

    visibleDidOptions = filtered.slice(0, limit);
    renderDidSelect(visibleDidOptions);
    updateDidStats(didOptions.length, filtered.length, visibleDidOptions.length, limit);
  }

  function extractReadValue(data) {
    if (data === undefined || data === null) return "";
    if (typeof data === "string") return data;
    if (typeof data === "number" || typeof data === "boolean") return String(data);
    if (typeof data === "object") {
      if (typeof data.value === "string") return data.value;
      if (typeof data.attribValue === "string") return data.attribValue;
      return JSON.stringify(data);
    }
    return String(data);
  }

  async function refreshDidOptions() {
    Api.setStatus("Carregando DIDs...");
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

    applyDidFilter();
    setOut({
      where: "attrib.refreshDids",
      total: didOptions.length,
      visible: visibleDidOptions.length,
      filter: String(didFilterInput.value || "").trim(),
      limit: parseDidLimit(didLimitInput.value),
      ownResp,
      externalResp: extResp,
    });
    Api.setStatus(`DIDs carregados: ${didOptions.length}. Exibindo: ${visibleDidOptions.length}.`);
  }

  function getBaseInput() {
    const genesisPath = String($("#attrib_genesis").value || "").trim();
    const did = String(didInput.value || "").trim();
    const key = String($("#attrib_key").value || "").trim();

    if (!genesisPath) {
      Api.setStatus("Informe o Genesis path.");
      return null;
    }
    if (!did) {
      Api.setStatus("Selecione ou informe um DID.");
      return null;
    }
    if (!key) {
      Api.setStatus("Informe a chave do ATTRIB.");
      return null;
    }

    return { genesisPath, did, key };
  }

  didSelect.addEventListener("change", () => {
    const selected = String(didSelect.value || "").trim();
    if (selected) didInput.value = selected;
  });
  didFilterInput.addEventListener("input", applyDidFilter);
  didLimitInput.addEventListener("input", applyDidFilter);
  didLimitInput.addEventListener("change", applyDidFilter);
  $("#btn_attrib_clear_filter").addEventListener("click", () => {
    didFilterInput.value = "";
    applyDidFilter();
  });

  $("#btn_attrib_refresh_dids").addEventListener("click", refreshDidOptions);

  $("#btn_attrib_write").addEventListener("click", async () => {
    const base = getBaseInput();
    if (!base) return;

    const value = String($("#attrib_value").value || "").trim();
    if (!value) {
      Api.setStatus("Informe o valor para escrita do ATTRIB.");
      return;
    }

    Api.setStatus("Escrevendo ATTRIB no ledger...");
    const resp = await Api.attrib.writeOnLedger(base.genesisPath, base.did, base.key, value);
    setOut({
      where: "attrib.writeOnLedger",
      input: { ...base, value },
      resp,
    });
    Api.setStatus(resp.ok ? "ATTRIB escrito no ledger." : `Erro: ${resp.error.message}`);
  });

  $("#btn_attrib_read").addEventListener("click", async () => {
    const base = getBaseInput();
    if (!base) return;

    Api.setStatus("Lendo ATTRIB do ledger...");
    const resp = await Api.attrib.readFromLedger(base.genesisPath, base.did, base.key);
    readValue.value = resp.ok ? extractReadValue(resp.data) : "";
    setOut({
      where: "attrib.readFromLedger",
      input: base,
      resp,
    });
    Api.setStatus(resp.ok ? "Leitura de ATTRIB concluída." : `Erro: ${resp.error.message}`);
  });

  $("#btn_attrib_exists").addEventListener("click", async () => {
    const base = getBaseInput();
    if (!base) return;

    Api.setStatus("Verificando existência do ATTRIB...");
    const resp = await Api.attrib.checkExists(base.genesisPath, base.did, base.key);
    setOut({
      where: "attrib.checkExists",
      input: base,
      resp,
    });

    if (resp.ok) {
      Api.setStatus(resp.data ? "ATTRIB existe no ledger." : "ATTRIB não encontrado no ledger.");
    } else {
      Api.setStatus(`Erro: ${resp.error.message}`);
    }
  });

  refreshDidOptions();
  return {};
})();
