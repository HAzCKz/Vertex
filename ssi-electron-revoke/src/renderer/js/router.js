function showPage(name) {
  const from = document.querySelector(".page:not(.hidden)")?.id || null;
  document.querySelectorAll(".page").forEach(p => p.classList.add("hidden"));
  const el = document.getElementById(`page-${name}`);
  if (el) el.classList.remove("hidden");
  window.dispatchEvent(new CustomEvent("app:pagechange", {
    detail: {
      from,
      to: el?.id || null,
      page: name,
    },
  }));
}

document.querySelectorAll(".nav").forEach(btn => {
  btn.addEventListener("click", () => showPage(btn.dataset.page));
});

(async () => {
  Api.setStatus("Iniciando...");
  try {
    const r = await Api.ping();
    if (r.ok) Api.setStatus("UI pronta. IPC OK.");
    else Api.setStatus(`Erro IPC: ${r.error.message}`);
  } catch (e) {
    Api.setStatus(`Falha: ${e.message || e}`);
  }
  showPage("wallet");
})();
