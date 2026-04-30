const { app, BrowserWindow, Menu } = require("electron");
const path = require("path");

const { registerIpcHandlers } = require("./ipc/handlers");
const { ensureAppDirs } = require("./storage/paths");

let win;

function createWindow() {
  win = new BrowserWindow({
    width: 1200,
    height: 800,
    show: true,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "..", "preload", "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  // remove o menu superior definitivamente
  Menu.setApplicationMenu(null);

  win.loadFile(path.join(__dirname, "..", "renderer", "index.html"));
}

app.whenReady().then(() => {
  ensureAppDirs();
  registerIpcHandlers();
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  try {
    // best-effort, não bloqueie o quit
    Promise.resolve().then(() => ssi.walletClose()).catch(() => { });
  } catch (_) { }
});
