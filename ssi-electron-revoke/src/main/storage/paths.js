const { app } = require("electron");
const path = require("path");
const fs = require("fs");

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function getAppDataRoot() {
  return app.getPath("userData");
}

function getWalletsDir() {
  return path.join(getAppDataRoot(), "wallets");
}

function getExchangeDir() {
  return path.join(getAppDataRoot(), "exchange");
}

function getInboxDir() {
  return path.join(getExchangeDir(), "inbox");
}

function getOutboxDir() {
  return path.join(getExchangeDir(), "outbox");
}

function getLogsDir() {
  return path.join(getAppDataRoot(), "logs");
}

function ensureAppDirs() {
  ensureDir(getWalletsDir());
  ensureDir(getInboxDir());
  ensureDir(getOutboxDir());
  ensureDir(getLogsDir());
}

module.exports = {
  ensureAppDirs,
  getAppDataRoot,
  getWalletsDir,
  getExchangeDir,
  getInboxDir,
  getOutboxDir,
  getLogsDir
};
