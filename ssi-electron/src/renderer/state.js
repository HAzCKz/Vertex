window.AppState = {
  walletPath: null,
  walletOpen: false,
  genesisPath: null
};

(() => {
  const GENESIS_PATH_IDS = new Set([
    "g_path",
    "genesis_path",
    "attrib_genesis",
    "create_genesis_path",
    "receive_genesis_path",
    "accept_genesis_path",
    "pres_genesis_path",
    "pres_verify_genesis_path",
  ]);
  const GENESIS_INPUT_SELECTOR = [
    "input#g_path",
    "input#genesis_path",
    "input#attrib_genesis",
    "input#create_genesis_path",
    "input#receive_genesis_path",
    "input#accept_genesis_path",
    "input#pres_genesis_path",
    "input#pres_verify_genesis_path",
  ].join(", ");
  const GENESIS_STORAGE_KEY = "ssi-electron.genesisPath";
  const trackedInputs = new Set();

  function normalizeValue(v) {
    return String(v || "").trim();
  }

  function isGenesisPathInput(node) {
    return Boolean(
      node &&
      node.tagName === "INPUT" &&
      typeof node.id === "string" &&
      GENESIS_PATH_IDS.has(node.id)
    );
  }

  function collectGenesisInputs() {
    return Array.from(document.querySelectorAll(GENESIS_INPUT_SELECTOR))
      .filter((node) => isGenesisPathInput(node));
  }

  function pickInitialGenesisPath(inputs) {
    const fromState = normalizeValue(window.AppState?.genesisPath);
    if (fromState) return fromState;

    const fromStorage = normalizeValue(window.localStorage?.getItem(GENESIS_STORAGE_KEY));
    if (fromStorage) return fromStorage;

    for (const input of inputs) {
      const value = normalizeValue(input.value);
      if (value) return value;
    }

    return "";
  }

  function persistGenesisPath(value) {
    if (!window.localStorage) return;
    try {
      if (value) {
        window.localStorage.setItem(GENESIS_STORAGE_KEY, value);
      } else {
        window.localStorage.removeItem(GENESIS_STORAGE_KEY);
      }
    } catch (_) {
      // Ignora erros de storage para não impactar o fluxo da UI.
    }
  }

  function applyGenesisPath(value, sourceInput) {
    const normalized = normalizeValue(value);
    window.AppState.genesisPath = normalized || null;
    persistGenesisPath(normalized);

    collectGenesisInputs().forEach((input) => {
      if (input === sourceInput) return;
      if (normalizeValue(input.value) !== normalized) {
        input.value = normalized;
      }
    });
  }

  function bindGenesisInput(input) {
    if (trackedInputs.has(input)) return;
    trackedInputs.add(input);

    input.addEventListener("input", (event) => {
      applyGenesisPath(event.target.value, event.target);
    });
    input.addEventListener("change", (event) => {
      applyGenesisPath(event.target.value, event.target);
    });
  }

  function setupGenesisPathSync() {
    const inputs = collectGenesisInputs();
    inputs.forEach(bindGenesisInput);

    const initial = pickInitialGenesisPath(inputs);
    applyGenesisPath(initial, null);

    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        mutation.addedNodes.forEach((node) => {
          if (!(node instanceof Element)) return;

          if (isGenesisPathInput(node)) {
            bindGenesisInput(node);
            if (!normalizeValue(node.value) && window.AppState.genesisPath) {
              node.value = window.AppState.genesisPath;
            }
          }

          node.querySelectorAll?.(GENESIS_INPUT_SELECTOR).forEach((child) => {
            if (!isGenesisPathInput(child)) return;
            bindGenesisInput(child);
            if (!normalizeValue(child.value) && window.AppState.genesisPath) {
              child.value = window.AppState.genesisPath;
            }
          });
        });
      }
    });

    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setupGenesisPathSync, { once: true });
  } else {
    setupGenesisPathSync();
  }
})();
