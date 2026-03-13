const WalletPage = (() => {
  const root = document.getElementById("page-wallet");

  root.innerHTML = `
    <div class="card">
      <h2>Wallet</h2>
      <p class="small">Crie/abra/feche e troque senha. (Métodos reais vêm da sua N-API.)</p>

      <div class="row">
        <div class="input" style="min-width:520px">
          <label>Wallet path (arquivo .db)</label>
          <div class="inline">
            <input id="w_path" placeholder="Selecione ou crie uma wallet.db" />
            <button class="secondary" id="btn_pick_open" title="Selecionar existente">Selecionar</button>
            <button class="secondary" id="btn_pick_save" title="Escolher nome para nova wallet">Nova...</button>
          </div>
        </div>

        <div class="input">
          <label>Senha</label>
          <input id="w_pass" type="password" />
        </div>
      </div>

      <div class="row">
        <button class="primary" id="btn_create">Criar</button>
        <button class="secondary" id="btn_open">Abrir</button>
        <button class="secondary" id="btn_close">Fechar</button>
      </div>

      <hr style="border-color:#222; margin:16px 0;" />

      <div class="row">
        <div class="input">
          <label>Senha antiga</label>
          <input id="w_old" type="password" />
        </div>
        <div class="input">
          <label>Nova senha</label>
          <input id="w_new" type="password" />
        </div>
      </div>
      <div class="row">
        <button class="secondary" id="btn_chpass">Trocar senha</button>
      </div>

      <h3>Resultado</h3>
      <pre id="w_out">{}</pre>
    </div>
  `;

  const $ = (id) => root.querySelector(id);
  const out = $("#w_out");

  function setOut(obj) {
    out.textContent = JSON.stringify(obj, null, 2);
  }

  $("#btn_pick_open").onclick = async () => {
    Api.setStatus("Selecionando wallet...");
    const r = await Api.wallet.pickPath("open");
    setOut(r);
    if (r.ok && !r.data.canceled) {
      $("#w_path").value = r.data.walletPath;
      Api.setStatus("Wallet selecionada.");
    } else {
      Api.setStatus("Seleção cancelada.");
    }
  };

  $("#btn_pick_save").onclick = async () => {
    Api.setStatus("Escolhendo nova wallet...");
    const r = await Api.wallet.pickPath("save");
    setOut(r);
    if (r.ok && !r.data.canceled) {
      $("#w_path").value = r.data.walletPath;
      Api.setStatus("Caminho da nova wallet definido.");
    } else {
      Api.setStatus("Seleção cancelada.");
    }
  };

  $("#btn_create").onclick = async () => {
    Api.setStatus("Criando wallet...");
    const walletPath = $("#w_path").value;
    const pass = $("#w_pass").value;
    const r = await Api.wallet.create(walletPath, pass);

    // após criar:
    await Api.wallet.close().catch(() => { });
    const r2 = await Api.wallet.open(walletPath, pass);
    setOut({ create: r, reopen: r2 });

    setOut(r);
    Api.setStatus(r.ok ? "Wallet criada." : `Erro: ${r.error.message}`);
  };

  $("#btn_open").onclick = async () => {
    Api.setStatus("Abrindo wallet...");
    const walletPath = $("#w_path").value;
    const pass = $("#w_pass").value;

    const r = await Api.wallet.open(walletPath, pass);
    setOut(r);
    Api.setStatus(r.ok ? "Wallet aberta." : `Erro: ${r.error.message}`);

    if (r.ok) {
      // opcional: mostrar info
      const info = await Api.wallet.info();
      setOut({ open: r, info });
    }

    const s = await Api.wallet.getSession();
    setOut({ action: r, session: s });
  };

  $("#btn_close").onclick = async () => {
    Api.setStatus("Fechando wallet...");
    const r = await Api.wallet.lock();
    setOut(r);
    Api.setStatus(r.ok ? "Wallet fechada." : `Erro: ${r.error.message}`);

    const s = await Api.wallet.getSession();
    setOut({ action: r, session: s });

  };

  $("#btn_chpass").onclick = async () => {
    Api.setStatus("Trocando senha...");
    const walletPath = $("#w_path").value;
    const oldPass = $("#w_old").value;
    const newPass = $("#w_new").value;
    const r = await Api.wallet.changePass(walletPath, oldPass, newPass);
    setOut(r);
    Api.setStatus(r.ok ? "Senha trocada." : `Erro: ${r.error.message}`);
  };

  return {};
})();
