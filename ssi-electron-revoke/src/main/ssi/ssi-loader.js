const path = require("path");
const fs = require("fs");

function loadNative() {
  // Caminho absoluto até native/index.node (fora do src)
  const root = path.join(__dirname, "..", "..", "..");
  const nativePath = path.join(root, "native", "index.node");

  if (!fs.existsSync(nativePath)) {
    throw new Error(`N-API não encontrada em: ${nativePath}`);
  }

  // eslint-disable-next-line global-require, import/no-dynamic-require
  return require(nativePath);
}

module.exports = { loadNative };
