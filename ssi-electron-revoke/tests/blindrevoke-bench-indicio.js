#!/usr/bin/env node

const path = require("path");
const { spawnSync } = require("child_process");

const benchPath = path.join(__dirname, "blindrevoke-bench.js");
const indicioConfigPath = path.join(__dirname, "blindrevoke-indicio.config.json");
const userArgs = process.argv.slice(2);
const hasConfig = userArgs.includes("--config");

const child = spawnSync(
  process.execPath,
  [
    benchPath,
    ...userArgs,
    ...(hasConfig ? [] : ["--config", indicioConfigPath]),
  ],
  { stdio: "inherit" }
);

if (child.error) {
  throw child.error;
}

process.exitCode = child.status === null ? 1 : child.status;
