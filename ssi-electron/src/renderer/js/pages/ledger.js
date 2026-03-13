const LedgerPage = (() => {
  const root = document.getElementById("page-ledger");

  root.innerHTML = `
    <div class="card">
      <h2>Ledger</h2>
      <p class="small">Conectar via genesis e rodar healthcheck.</p>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Genesis path</label>
          <input id="g_path" placeholder="/caminho/para/genesis.txn" />
        </div>
      </div>

      <div class="row">
        <button class="primary" id="btn_connect">Connect</button>
        <button class="secondary" id="btn_health">Healthcheck</button>
      </div>

      <h3>Resultado</h3>
      <pre id="g_out">{}</pre>
    </div>
  `;

  const $ = (id) => root.querySelector(id);
  const out = $("#g_out");
  const setOut = (obj) => (out.textContent = JSON.stringify(obj, null, 2));

  $("#btn_connect").onclick = async () => {
    Api.setStatus("Conectando no ledger...");
    const genesisPath = $("#g_path").value;
    const r = await Api.ledger.connect(genesisPath);
    setOut(r);
    Api.setStatus(r.ok ? "Conectado." : `Erro: ${r.error.message}`);
  };

  $("#btn_health").onclick = async () => {
    Api.setStatus("Healthcheck...");
    const r = await Api.ledger.health();
    setOut(r);
    Api.setStatus(r.ok ? "Health OK." : `Erro: ${r.error.message}`);
  };

  return {};
})();
