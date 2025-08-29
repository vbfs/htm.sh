#!/usr/bin/env node
/**
 * htm.sh - Single-file CLI (UX, real upload progress + custom help)
 */
import { program } from "commander";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { Blob } from "buffer";
import { once } from "node:events";
import inquirer from "inquirer";
import Conf from "conf";
import { bold, dim, white, cyan, yellow, magenta, lightGreen, bgLightGreen } from "kolorist";

const store = new Conf({ projectName: "htmsh" });

const CURRENT_VERSION = "0.1.8";
const DEFAULT_SPA = true;
const DEFAULT_TTL = 24 * 60 * 60 * 1000;
const MAX_RETRIES = 1;
const DEFAULT_GATEWAY = "https://htm.sh";
const SUGGESTED_PUBLIC_GATEWAY =
  process.env.SUGGESTED_PUBLIC_GATEWAY || "https://htm.sh";

const UPLOAD_ENDPOINTS = ["/api/deploy", "/deploy"]; // tenta em ordem

/* =========================
   Minimal UI
========================= */

function createUi({ quiet = false, json = false } = {}) {
  const out = (s = "") => {
    if (!quiet && !json) process.stdout.write(s + "\n");
  };
  const jout = (obj) => {
    if (json) process.stdout.write(JSON.stringify(obj) + "\n");
  };
  const line = (w = 72) => "─".repeat(w);

  const banner = () => {
    if (json) return jout({ level: "banner", name: "htm.sh" });
    out(bgLightGreen(bold("htm.sh")));
    out(
      "From shell to world. Ship static sites from your shell for free, without leaving the command line."
    );
    out("");
  };
  const section = (title) => {
    if (json) return jout({ level: "section", title });
    out(bold(title));
    out(dim(line()));
  };
  const subheader = (text) => {
    if (json) return jout({ level: "subheader", text });
    out(dim(text));
    out("");
  };
  const row = (key, value, color = "") => {
    if (json) return jout({ level: "row", key, value });
    const k = dim((key + ":").padEnd(18, " "));
    out(`  ${k} ${colorize(String(value), color)}`);
  };
  const info = (msg) =>
    json ? jout({ level: "info", msg }) : out(`info  ${msg}`);
  const warn = (msg) =>
    json ? jout({ level: "warn", msg }) : out(`warn  ${msg}`);
  const error = (msg) =>
    json ? jout({ level: "error", msg }) : out(`error ${msg}`);
  const ok = (msg) => (json ? jout({ level: "ok", msg }) : out(`ok    ${msg}`));
  const blank = () => {
    if (!json && !quiet) out("");
  };

  const bar = (label, pct, width = 28) => {
    pct = Math.max(0, Math.min(100, pct | 0));
    const filled = Math.round((pct / 100) * width);
    const empty = width - filled;
    const gauge = "[" + "=".repeat(filled) + " ".repeat(empty) + "]";
    if (json) return jout({ level: "bar", label, pct });
    const k = dim((label + ":").padEnd(18, " "));
    out(`  ${k} ${gauge} ${String(pct).padStart(3, " ")}%`);
  };

  const block = (title, lines) => {
    if (json) return jout({ level: "block", title, lines });
    const width = 74;
    const pad = (s = "") => {
      const txt = s.length > width - 4 ? s.slice(0, width - 7) + "..." : s;
      return txt.padEnd(width - 4, " ");
    };
    out("┌" + "─".repeat(width - 2) + "┐");
    out(`│ ${bold(pad(title))} │`);
    out("├" + "─".repeat(width - 2) + "┤");
    (Array.isArray(lines) ? lines : [lines]).forEach((line) => {
      out(`│ ${pad(line)} │`);
    });
    out("└" + "─".repeat(width - 2) + "┘");
  };

  const colorize = (s, c) => {
    switch (c) {
      case "cyan":
        return cyan(s);
      case "green":
        return lightGreen(s);
      case "yellow":
        return yellow(s);
      case "magenta":
        return magenta(s);
      case "white":
        return white(s);
      default:
        return s;
    }
  };

  return {
    banner,
    section,
    subheader,
    row,
    info,
    warn,
    error,
    ok,
    blank,
    bar,
    block,
    jout,
    line,
  };
}

/* =========================
   Core helpers
========================= */

function domainToProject(domain) {
  const first = String(domain).trim().split(".")[0];
  return (
    first
      .replace(/[^a-z0-9-]/gi, "-")
      .toLowerCase()
      .replace(/^-+|-+$/g, "") || "site"
  );
}

function human(bytes) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0,
    n = bytes;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(n < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

function scanDir(root) {
  let filesCount = 0,
    total = 0;
  const stack = [root];
  const SKIP = new Set([".git", "node_modules"]);
  while (stack.length) {
    const cur = stack.pop();
    const st = fs.statSync(cur);
    if (st.isDirectory()) {
      const name = path.basename(cur);
      if (SKIP.has(name)) continue;
      for (const f of fs.readdirSync(cur)) stack.push(path.join(cur, f));
    } else if (st.isFile()) {
      filesCount++;
      total += st.size;
    }
  }
  return { filesCount, totalSize: total };
}

function buildFinalUrl(gateway, urlFromServer) {
  if (!urlFromServer) return gateway.replace(/\/$/, "");
  const base = gateway.replace(/\/$/, "");
  if (urlFromServer.startsWith("http")) return urlFromServer;
  return `${base}${urlFromServer.startsWith("/") ? "" : "/"}${urlFromServer}`;
}

function parseDuration(s, fallbackMs) {
  if (!s) return fallbackMs;
  if (s === "0") return 0;
  const m = String(s)
    .trim()
    .match(/^(\d+)(ms|s|m|h|d)?$/i);
  if (!m) return fallbackMs;
  const n = Number(m[1]);
  const unit = (m[2] || "ms").toLowerCase();
  const mult =
    unit === "ms"
      ? 1
      : unit === "s"
      ? 1000
      : unit === "m"
      ? 60000
      : unit === "h"
      ? 3600000
      : 86400000;
  return n * mult;
}

function formatDuration(ms) {
  if (ms === 0) return "disabled";
  if (ms < 60000) return `${Math.round(ms / 1000)}s`;
  if (ms < 3600000) return `${Math.round(ms / 60000)}m`;
  if (ms < 86400000) return `${Math.round(ms / 3600000)}h`;
  return `${Math.round(ms / 86400000)}d`;
}

function isRailwayHost(url) {
  try {
    const u = new URL(url);
    return /\.up\.railway\.app$/i.test(u.hostname);
  } catch {
    return false;
  }
}

async function resolveGateway(optsUrl) {
  const fromFlag = optsUrl;
  const fromStore = store.get("gateway");
  const fromEnv = process.env.DEPLOY_GATEWAY;
  const gw = fromFlag || fromStore || fromEnv || DEFAULT_GATEWAY;
  const source = fromFlag
    ? "flag --url"
    : fromStore
    ? "saved (login)"
    : fromEnv
    ? "env DEPLOY_GATEWAY"
    : "default";
  return { gateway: gw.replace(/\/$/, ""), source };
}

async function maybeOfferGatewaySwitch(currentGw, ui, opts = {}) {
  if (!isRailwayHost(currentGw)) return currentGw;
  if (!opts.yes) {
    ui.block("GATEWAY WARNING", [
      "Using a Railway host as gateway may cause 404 errors.",
      `Recommended: ${SUGGESTED_PUBLIC_GATEWAY}`,
    ]);
    const { change } = await inquirer.prompt([
      {
        type: "confirm",
        name: "change",
        default: true,
        message: "Switch gateway?",
      },
    ]);
    if (!change) return currentGw;
  }
  store.set("gateway", SUGGESTED_PUBLIC_GATEWAY);
  ui.ok(`Gateway updated to ${SUGGESTED_PUBLIC_GATEWAY}`);
  return SUGGESTED_PUBLIC_GATEWAY;
}

async function healthCheck(gateway) {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 3500);
    const r = await fetch(`${gateway}/health`, { signal: ctrl.signal });
    clearTimeout(t);
    if (!r.ok) return `${r.status}`;
    const j = await r.json().catch(() => ({}));
    return j?.ok ? "ok" : "? (no ok=true)";
  } catch (e) {
    return `unreachable (${e.name === "AbortError" ? "timeout" : e.message})`;
  }
}

function extractHttpError(e) {
  const status = e?.status ?? e?.response?.status ?? null;
  const data = e?.data ?? e?.response?.data ?? null;
  const text = data?.text;
  const code = e?.code ?? data?.code ?? data?.error ?? null;
  return { status, data, text, code };
}

/* =========================
   Password Protection Helpers
========================= */

function readPasswordFromProject(rootDir) {
  const f1 = path.join(rootDir, "AUTH");
  if (fs.existsSync(f1)) {
    const raw = fs.readFileSync(f1, "utf8").trim();
    return raw || null;
  }

  return null;
}

function isNewer(a, b) {
  const pa = String(a)
    .split(".")
    .map((n) => parseInt(n, 10) || 0);
  const pb = String(b)
    .split(".")
    .map((n) => parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x > y) return true;
    if (x < y) return false;
  }
  return false;
}

async function quickVersionCheck(ui) {
  try {
    const DAY = 24 * 60 * 60 * 1000;
    const now = Date.now();
    const cached = store.get("versionCheck");

    const cacheFresh =
      cached?.timestamp &&
      now - cached.timestamp < DAY &&
      cached?.current === CURRENT_VERSION;

    if (cacheFresh) {
      const shouldWarn =
        cached.latest && isNewer(cached.latest, CURRENT_VERSION);
      if (shouldWarn) {
        ui.warn(`Update available: ${CURRENT_VERSION} → ${cached.latest}`);
        ui.info(yellow("Run with `npx htmsh@latest` for the latest version or `npm i -g htmsh@latest`"));
        ui.blank();
      }
      return;
    }

    const response = await fetch("https://registry.npmjs.org/htmsh", {
      signal: AbortSignal.timeout(2000),
    });
    if (!response.ok) return;

    const data = await response.json();
    const latest = data?.["dist-tags"]?.latest;
    const shouldWarn = latest && isNewer(latest, CURRENT_VERSION);

    store.set("versionCheck", {
      timestamp: now,
      current: CURRENT_VERSION,
      latest,
      hasUpdate: shouldWarn,
    });

    if (shouldWarn) {
      ui.warn(`Update available: ${CURRENT_VERSION} → ${latest}`);
      ui.info(yellow("Run with `npx htmsh@latest` for the latest version or `npm i -g htmsh@latest`"));
      ui.blank();
    }
  } catch {}
}

async function uploadOnce({
  endpoint,
  gatewayUrl,
  tarPath,
  project,
  spa,
  email,
  password,
  sitePassword,
  onProgress,
}) {
  const size = fs.statSync(tarPath).size;

  const rs = fs.createReadStream(tarPath, { highWaterMark: 64 * 1024 });
  const chunks = [];
  let sent = 0;

  rs.on("data", (chunk) => {
    chunks.push(chunk);
    sent += chunk.length;
    const pct = Math.min(100, Math.round((sent / size) * 100));
    onProgress?.(pct, sent, size);
  });

  await once(rs, "end");
  const blob = new Blob(chunks, { type: "application/gzip" });

  const form = new FormData();
  form.append("project", project);
  form.append("spa", spa ? "true" : "false");
  if (sitePassword !== undefined) {
    form.append("sitePassword", sitePassword);
  }
  form.append("bundle", blob, `${project}.tar.gz`);

  const basic =
    "Basic " + Buffer.from(`${email}:${password}`, "utf8").toString("base64");

  const url = new URL(`${gatewayUrl}${endpoint}`);
  url.searchParams.set("project", project);

  const res = await fetch(url.toString(), {
    method: "POST",
    headers: {
      authorization: basic,
      "x-email": email,
      "x-password": password,
    },
    body: form,
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    const err = new Error(
      `HTTP ${res.status} on ${endpoint}${text ? `: ${text}` : ""}`
    );
    err.status = res.status;
    err.response = { status: res.status, data: { text } };
    throw err;
  }

  return await res.json().catch(() => ({}));
}

async function createTarAndUpload({
  project,
  sourceDir,
  tmpDir,
  gatewayUrl,
  email,
  password,
  sitePassword,
  spa = true,
  onPackStart,
  onPackDone,
  onUploadProgress,
}) {
  if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
  const tarPath = path.join(tmpDir, `${project}.tar.gz`);

  onPackStart?.();
  await tarDirectory(sourceDir, tarPath);
  const packedSize = fs.statSync(tarPath).size;
  onPackDone?.(packedSize);

  let lastErr;
  for (const endpoint of UPLOAD_ENDPOINTS) {
    try {
      onUploadProgress?.(0, 0, packedSize);
      const res = await uploadOnce({
        endpoint,
        gatewayUrl,
        tarPath,
        project,
        spa,
        email,
        password,
        sitePassword,
        onProgress: onUploadProgress,
      });
      return res;
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error("Upload failed");
}

function tarDirectory(dir, outTarGz) {
  return new Promise((resolve, reject) => {
    const cwd = path.resolve(dir);
    const tar = spawn("tar", ["-czf", outTarGz, "-C", cwd, "."], {
      stdio: ["ignore", "ignore", "pipe"],
    });
    let errBuf = "";
    tar.stderr.on("data", (d) => (errBuf += d.toString()));
    tar.on("close", (code) => {
      if (code === 0) resolve();
      else
        reject(
          new Error(
            `tar exited with code ${code}${errBuf ? `: ${errBuf}` : ""}`
          )
        );
    });
  });
}

function hasAnyHtmlInRoot(dir) {
  try {
    const files = fs.readdirSync(dir);
    return files.some((f) => f.toLowerCase().endsWith(".html"));
  } catch {
    return false;
  }
}

program
  .name("htm.sh")
  .version(CURRENT_VERSION)
  .description("Deploy static sites with a minimal, fast CLI")
  .argument("[path]", "directory to publish (default: .)", ".")
  .argument("[domain]", "desired domain (used as project name)")
  .option("--no-spa", "disable SPA fallback")
  .option("--yes", "skip confirmation prompt", false)
  .option("--quiet", "suppress standard logs (errors still print)", false)
  .option("--json", "machine-readable logs (CI-friendly)", false)
  .option("--password <password>", "password protect the site")
  .option("--remove-password", "remove password protection")
  .action(async (argPath, argDomain, opts) => {
    const ui = createUi({ quiet: opts.quiet, json: opts.json });

    try {
      ui.blank();
      ui.banner();

      if (!store.get("seenTips")) {
        ui.block("Welcome to htm.sh", [
          "Deploy your static sites in seconds, straight from the shell.",
          "Here are some quick tips to get you started:",
          "",
          "• Run with `npx htmsh@latest ...` to ensure the newest version.",
          "• Or use `npm i -g htmsh@latest` to install global.",
          "• Use `npx htmsh project-name` to choose the project name.",
          "• Add a CNAME file in the folder to lock the subdomain.",
          "• Create AUTH w/ file user:password to protect your site.",
          "• Ensure a .html file exists in the root (e.g. index.html).",
          "• Run `npx htmsh login` once to cache your credentials.",
          "• Use --no-spa to disable routing fallback to index.html.",
          "• Check your projects and quota with `npx htmsh quota`.",
          "• Run `npx htmsh tips` to see these tips again!",
        ]);
        store.set("seenTips", true);
      }
      ui.blank();

      await quickVersionCheck(ui);

      ui.section("Initialize");
      ui.row("Resolving", "gateway");
      let { gateway, source } = await resolveGateway(opts.url);
      if (opts.url) store.set("gateway", gateway);
      ui.row("Gateway", gateway, "cyan");
      ui.row("Source", source, "magenta");
      const health = await healthCheck(gateway);
      ui.row("Healthy", health, health.includes("ok") ? "green" : "red");

      gateway = await maybeOfferGatewaySwitch(gateway, ui, opts);
      ui.blank();

      // Project
      ui.section("Project");
      const cwd = process.cwd();
      const root = path.resolve(cwd, argPath || ".");
      if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
        ui.error(`Directory not found: ${root}`);
        process.exit(1);
      }

      if (!hasAnyHtmlInRoot(root)) {
        ui.blank();
        ui.error(`No .html file found in project root: ${root}`);
        ui.info(
          yellow(
            "Make sure your site has at least one entry point HTML file (e.g. index.html or 200.html)."
          )
        );
        ui.blank();
        process.exit(1);
      }

      // tenta usar DOMAIN ou CNAME se existir
      let domain = argDomain;
      if (!domain) {
        for (const fname of ["CNAME"]) {
          const fpath = path.join(root, fname);
          if (fs.existsSync(fpath)) {
            const raw = fs.readFileSync(fpath, "utf8").trim();
            if (raw) {
              domain = raw;
              break;
            }
          }
        }
      }
      if (!domain) domain = path.basename(root);

      let project = domainToProject(domain);
      const spa = opts.spa ?? DEFAULT_SPA;

      let sitePassword = undefined;
      const pwdFromFile = readPasswordFromProject(root);
      if (pwdFromFile) {
        sitePassword = pwdFromFile;
        ui.row("Protection", "From file (AUTH)", "yellow");
      } else if (opts.removePassword) {
        sitePassword = "";
        ui.row("Protection", "Remove", "green");
      } else if (opts.password) {
        sitePassword = opts.password;
        ui.row("Protection", "Enabled", "yellow");
      }

      const { filesCount, totalSize } = scanDir(root);
      ui.row("Path", root, "white");
      ui.row("Files", filesCount, "white");
      ui.row("Size", human(totalSize), "white");
      ui.row("Project", project, "cyan");
      ui.row("Domain", `${project}.htm.sh`, "cyan");
      ui.row("SPA Routing", spa ? "enabled" : "disabled", "yellow");
      ui.blank();

      ui.section("Login");
      const creds = await getCredentials({ interactive: true });
      ui.row("Email", creds.email, "green");
      ui.blank();

      if (!opts.yes) {
        const { ok } = await inquirer.prompt([
          {
            type: "confirm",
            name: "ok",
            message: "Proceed with deployment?",
            default: true,
          },
        ]);
        if (!ok) {
          ui.info("Cancelled");
          process.exit(0);
        }
      }

      // Deploy
      ui.blank();
      ui.section("Deploy");
      ui.subheader("Packaging and uploading...");

      let lastPct = 0;
      const tmpBase = path.join(
        os.tmpdir(),
        `htmsh-${Date.now()}-${crypto.randomBytes(4).toString("hex")}`
      );
      fs.mkdirSync(tmpBase, { recursive: true });

      ui.bar("upload", 0);

      let res = null;
      let attempt = 0;
      let lastErr;

      while (attempt < MAX_RETRIES) {
        attempt++;
        try {
          res = await createTarAndUpload({
            project,
            sourceDir: root,
            tmpDir: tmpBase,
            gatewayUrl: gateway,
            email: creds.email,
            password: creds.password,
            sitePassword,
            spa,
            onPackStart: () => {},
            onPackDone: () => {},
            onUploadProgress: (pct) => {
              if (pct !== lastPct) {
                ui.bar("upload", pct);
                lastPct = pct;
              }
            },
          });

          ui.bar("propagate", 100);
          // ui.ok("Deployment completed");
          ui.blank();
          ui.row("Deployment", "completed", "green");
          ui.blank();
          break;
        } catch (e) {
          lastErr = e;
          const { status } = extractHttpError(e);
          ui.blank();
          ui.warn(
            `Upload failed (attempt ${attempt}/${MAX_RETRIES})${
              status ? ` [HTTP ${status}]` : ""
            }`
          );
          ui.blank();

          const data = e?.response?.data;
          const isConflict =
            status === 409 || data?.error === "subdomain_conflict";
          if (isConflict) {
            ui.block("SUBDOMAIN CONFLICT", [
              `The subdomain '${project}' is already taken.`,
              "Choose a different one.",
            ]);
            const ans = await inquirer.prompt([
              {
                type: "input",
                name: "newProject",
                message: "New subdomain:",
                default: `${project}-1`,
                validate: (v) =>
                  !!domainToProject(v) || "Use letters, numbers and hyphens.",
              },
            ]);
            project = domainToProject(ans.newProject);
            continue;
          }

          if (attempt >= MAX_RETRIES) {
            ui.error(
              `Deploy failed after ${MAX_RETRIES} attempts: ${e?.message || e}`
            );
            process.exit(1);
          }
        }
      }

      if (!res && lastErr) {
        ui.error(`Deploy failed: ${lastErr?.message || lastErr}`);
        process.exit(1);
      }

      ui.section("Result");
      ui.row("Domain", res?.subdomain || `${project}.htm.sh`, "green");
      ui.row("Release", res?.release || "-", "yellow");
      ui.row("Files", res?.filesCount ?? filesCount, "white");
      ui.row(
        "Size",
        res?.sizeBytes != null ? human(res.sizeBytes) : human(totalSize),
        "white"
      );
      if (res?.passwordProtected !== undefined) {
        ui.row(
          "Password",
          res.passwordProtected ? "Yes" : "No",
          res.passwordProtected ? "yellow" : "green"
        );
      }
      ui.blank();

      if (opts.json) {
        ui.jout({
          event: "deployed",
          project: res?.project || project,
          subdomain: res?.subdomain || `${project}.htm.sh`,
          release: res?.release || "-",
          files: res?.filesCount ?? filesCount,
          sizeBytes: res?.sizeBytes ?? totalSize,
          passwordProtected: res?.passwordProtected,
          gateway,
        });
        ui.blank();
        ui.row("Success! Live at ", res?.subdomain || `https://${project}.htm.sh`, "green");
        ui.blank();
      }

      process.exit(0);
    } catch (e) {
      console.error(`error ${e?.message || String(e)}`);
      process.exit(1);
    }
  });

program
  .command("tips")
  .description("Show quick usage tips")
  .option("--json", "machine-readable output", false)
  .action((opts) => {
    const ui = createUi({ json: opts.json });
    ui.blank();
    ui.banner();
    const tips = [
      "Deploy your static sites in seconds, straight from the shell.",
      "Here are some quick tips to get you started:",
      "",
      "• Use `npx htmsh project-name` to choose the project name.",
      "• Add a CNAME file in the folder to lock the subdomain.",
      "• Create AUTH w/ file user:password to protect your site.",
      "• Ensure a .html file exists in the root (e.g. index.html).",
      "• Run `npx htmsh login` once to cache your credentials.",
      "• Use --password <password> to protect your site.",
      "• Use --no-spa to disable routing fallback to index.html.",
      "• Check quota anytime with `npx htmsh quota`.",
      "• Run `npx htmsh tips` to see these tips again!",
    ];
    ui.block("Tips", tips);
  });

program
  .command("login")
  .description("Cache gateway and credentials")
  .option("--ttl <duration>", "credential cache TTL (e.g. 15m, 1h, 24h)", "24h")
  .option("--quiet", "suppress standard logs", false)
  .option("--json", "machine-readable logs", false)
  .action(async (opts) => {
    const ui = createUi({ quiet: opts.quiet, json: opts.json });

    ui.blank();
    ui.banner();
    ui.section("Login");

    let gateway =
      opts.url ||
      store.get("gateway") ||
      process.env.DEPLOY_GATEWAY ||
      DEFAULT_GATEWAY;

    ui.subheader("Please enter your credentials:");
    const { email, password } = await inquirer.prompt([
      {
        type: "input",
        name: "email",
        message: "  email:",
        validate: (v) => !!v || "Required",
      },
      {
        type: "password",
        name: "password",
        message: "  password:",
        mask: "*",
        validate: (v) => !!v || "Required",
      },
    ]);

    const ttlMs = parseDuration(opts.ttl ?? "24h", DEFAULT_TTL);

    ui.blank();
    ui.section("Session");
    ui.row("Gateway", gateway, "cyan");

    if (isRailwayHost(gateway)) {
      ui.block("GATEWAY RECOMMENDATION", [
        "Detected Railway host - this may cause issues.",
        `Consider using ${SUGGESTED_PUBLIC_GATEWAY} instead.`,
      ]);
      const { change } = await inquirer.prompt([
        {
          type: "confirm",
          name: "change",
          default: true,
          message: "Switch gateway?",
        },
      ]);
      if (change) {
        gateway = SUGGESTED_PUBLIC_GATEWAY;
        ui.row("Gateway", gateway, "cyan");
      }
    }

    store.set("gateway", gateway);
    store.set("creds", { email, password, savedAt: Date.now(), ttlMs });

    ui.row("Email", email, "green");
    ui.row("Credentials", "Stored", "green");
    ui.row("Cache", formatDuration(ttlMs), "yellow");

    if (opts.json) {
      ui.jout({ event: "login", email, gateway, ttlMs });
    }
  });

// === Helpers usados pelo comando quota ===
function makeBasicAuthHeader(email, password) {
  const token = Buffer.from(`${email}:${password}`, "utf8").toString("base64");
  return `Basic ${token}`;
}

function safeNumber(x, fallback = 0) {
  const n = Number(x);
  return Number.isFinite(n) ? n : fallback;
}

function humanBytesSafe(input) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let n = safeNumber(input, 0);
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  const val = n < 10 && i > 0 ? n.toFixed(1) : Math.round(n).toString();
  return `${val} ${units[i]}`;
}

program
  .command("quota")
  .description("Show storage quota and per-project usage")
  .option("--json", "machine-readable output", false)
  .option("--quiet", "suppress standard logs", false)
  .action(async (opts) => {
    const ui = createUi({ quiet: opts.quiet, json: opts.json });
    ui.blank();
    ui.banner();
    ui.section("quota");

    try {
      const { gateway } = await resolveGateway();
      const creds = await getCredentials({ interactive: true });

      const ENDPOINTS = ["/quota", "/api/quota"];
      let data = null;

      for (const ep of ENDPOINTS) {
        try {
          const r = await fetch(`${gateway}${ep}`, {
            method: "GET",
            headers: {
              authorization: makeBasicAuthHeader(creds.email, creds.password),
              "x-email": creds.email,
              "x-password": creds.password,
            },
          });

          if (!r.ok) {
            const text = await r.text().catch(() => "");
            throw new Error(
              `HTTP ${r.status} on ${ep}${text ? `: ${text}` : ""}`
            );
          }

          data = await r.json();
          break;
        } catch (e) {
          ui.warn(`Failed on ${ep}: ${e.message}`);
        }
      }

      if (!data) {
        ui.error(`Could not fetch quota from ${gateway}.`);
        process.exit(1);
      }

      const limit = safeNumber(data.limitBytes, 0);
      const used = safeNumber(data.usedBytes, 0);
      const remain = safeNumber(
        data.remainingBytes ?? data.canUploadBytesLeft,
        limit - used
      );

      ui.row("Limit", humanBytesSafe(limit), "cyan");
      ui.row("Used", humanBytesSafe(used), "white");
      ui.row("Remaining", humanBytesSafe(remain), "green");
      ui.blank();

      if (Array.isArray(data.projects) && data.projects.length) {
        ui.section("projects");
        for (const p of data.projects) {
          const usedP = safeNumber(p.usedBytes, 0);
          const rels = safeNumber(p.releases, 0);
          const when = p.lastDeployedAt
            ? new Date(p.lastDeployedAt).toISOString().slice(0, 10)
            : "-";
          ui.row(
            `${p.project}`,
            `${humanBytesSafe(usedP)} • ${rels} release(s) • last: ${when}`,
            "white"
          );
        }
        ui.blank();
      } else {
        ui.info("No projects found for this account.");
      }

      if (opts.json) ui.jout({ event: "quota", ...data });
    } catch (e) {
      ui.error(e?.message || String(e));
      process.exit(1);
    }
  });

program
  .command("logout")
  .description("Clear saved credentials")
  .option("--quiet", "suppress standard logs", false)
  .option("--json", "machine-readable logs", false)
  .action((opts) => {
    const ui = createUi({ quiet: opts.quiet, json: opts.json });
    store.delete("gateway");
    store.delete("creds");
    ui.ok("Logged out");
    ui.info("Cached credentials cleared");
    if (opts.json) ui.jout({ event: "logout" });
  });

program
  .command("whoami")
  .description("Show current user and gateway status")
  .option("--quiet", "suppress standard logs", false)
  .option("--json", "machine-readable logs", false)
  .action(async (opts) => {
    const ui = createUi({ quiet: opts.quiet, json: opts.json });
    ui.blank();
    ui.banner();
    ui.section("whoami");

    const saved = store.get("gateway");
    const source = saved ? "saved (login)" : "default";
    const gw = saved || DEFAULT_GATEWAY;

    ui.row("Gateway", gw, "cyan");
    ui.row("Source", source, "magenta");

    const health = await healthCheck(gw);
    ui.row("Healthy", health, health.includes("ok") ? "green" : "red");

    if (isRailwayHost(gw))
      ui.warn(`Consider switching to ${SUGGESTED_PUBLIC_GATEWAY}`);

    const creds = store.get("creds");
    if (!creds) {
      ui.blank();
      ui.warn("No cached credentials");
      ui.info(yellow("Run `npx htmsh login` to authenticate"));
      ui.blank();
      if (opts.json)
        ui.jout({ event: "whoami", authenticated: false, gateway: gw });
      return;
    }

    const ttl = creds.ttlMs ?? DEFAULT_TTL;
    const age = Date.now() - (creds.savedAt || 0);
    const left = Math.max(0, ttl - age);

    if (left > 0) {
      ui.row("Email", creds.email, "green");
      ui.row("Expires in", formatDuration(left), "yellow");
      if (opts.json)
        ui.jout({
          event: "whoami",
          authenticated: true,
          email: creds.email,
          gateway: gw,
          expiresInMs: left,
        });
    } else {
      ui.blank();
      ui.warn(`Credentials expired for ${creds.email}`);
      ui.info(yellow("Run `htmsh login` to refresh"));
      ui.blank();
      if (opts.json)
        ui.jout({
          event: "whoami",
          authenticated: false,
          email: creds.email,
          gateway: gw,
          expired: true,
        });
    }
  });

program
  .command("docs")
  .description("Show concise documentation on how to use htmsh")
  .option(
    "--section <name>",
    "Show only one section (e.g. quickstart, install, login, deploy, spa, quota, password, troubleshoot)"
  )
  .option("--json", "machine-readable output", false)
  .action((opts) => {
    const ui = createUi({ json: opts.json });
    ui.blank();
    ui.banner();

    const sections = {
      quickstart: [
        "Quickstart Deploy",
        [
          "1) Just type: `npx htmsh ./dist project-name`.",
          "2) Ensure there is a .html in the project root.",
          "3) Your site: <project-name>.htm.sh and public fallback path.",
        ],
      ],
      install: [
        "Install / Run",
        [
          "• NPX (recommended): `npx htmsh ...`",
          "• Global: `npm i -g htmsh` → `htmsh ...`",
          "• Node 18+ and `tar` required in PATH.",
        ],
      ],
      login: [
        "Login & Credentials",
        [
          "• `npx htmsh login` stores email/password locally (Conf).",
          "• TTL configurable: `npx htmsh login --ttl 24h`.",
          "• `npx htmsh whoami` shows gateway health and cache expiry.",
          "• `npx htmsh logout` clears saved credentials and gateway.",
        ],
      ],
      naming: [
        "Project Naming & Domains",
        [
          "• Project name = subdomain label (sanitized).",
          "• Choose via CLI arg: `npx htmsh ./dist my-site`.",
          "• Or put a CNAME file in the folder (FQDN or label).",
          "• Default domain: `<project>.htm.sh`.",
          "• Custom FQDN requires DNS pointing (CNAME/ALIAS).",
        ],
      ],
      spa: [
        "SPA Routing",
        [
          "• Default: SPA routing enabled (unknown paths → index.html).",
          "• Disable with `--no-spa` to return 404 on unknown paths.",
          "• Good for React/Vue/SPA routers; disable for pure MPA.",
        ],
      ],
      deploy: [
        "Deploy",
        [
          "• `npx htmsh [path] [project]` (default path is `.`).",
          "• CLI packs directory (tar.gz) and uploads with progress.",
          "• On subdomain conflict, CLI asks a new project label.",
          "• Result shows domain, release, files and size.",
        ],
      ],
      password: [
        "Password Protection",
        [
          "• Run: `npx htmsh ./dist --password mypass`",
          "• Create AUTH w/ file user:password to protect your site.",
          "• Remove: `npx htmsh ./dist --remove-password`.",
          "• Manage later (if server exposes API):",
          "    - `npx htmsh protect <project> --password <pwd>`",
          "    - `npx htmsh password <project> --set <pwd>` or `--remove`",
          "• Visitors will see the browser’s Basic Auth dialog.",
        ],
      ],
      result: [
        "Result & URLs",
        [
          "• Domain: `<project>.htm.sh`."
        ],
      ],
      quota: [
        "Quota",
        [
          "• `npx htmsh quota` shows limit, used and remaining bytes.",
          "• Also lists per-project usage and last deploy date.",
          "• If limit=0, ask admin to set MAX_USER_BYTES on gateway.",
        ],
      ],
      troubleshoot: [
        "Troubleshooting",
        [
          "• `Directory not found` → check the path argument.",
          "• `No .html file found` → ensure index.html (or any .html) in root.",
          "• 401 → login first or server missing auth support.",
          "• Subdomain conflict → choose a different project name.",
          "• Password issues → verify project ownership and credentials.",
        ],
      ],
      tips: [
        "Tips",
        [
          "• `htmsh tips` or `npx htmsh tips` to re-read quick tips.",
          "• `htmsh whoami` to validate gateway + credentials.",
          "• `--json` output for CI logs and scripting.",
          "• Create AUTH w/ file user:password to protect your site.",
        ],
      ],
    };

    const render = (title, lines) => ui.block(title, lines);

    if (opts.section) {
      const key = opts.section.toLowerCase();
      if (!sections[key]) {
        ui.error(`Unknown section: ${opts.section}`);
        ui.info(
          "Available: quickstart, install, login, naming, spa, deploy, password, result, quota, troubleshoot, tips"
        );
        return;
      }
      const [title, lines] = sections[key];
      render(title, lines);
      return;
    }

    const order = [
      "quickstart",
      "install",
      "login",
      "naming",
      "spa",
      "deploy",
      "password",
      "result",
      "quota",
      "troubleshoot",
      "tips",
    ];

    for (const k of order) {
      const [title, lines] = sections[k];
      render(title, lines);
      ui.blank();
    }
  });

program.configureHelp({
  helpWidth: 80,
  optionTerm: (option) => option.flags,
  commandTerm: (cmd) => cmd.name(),
  helpInformation() {
    const lines = [];
    const push = (s = "") => lines.push(s);
    const sep = dim("─".repeat(72));

    push(bold("Usage"));
    push(sep);
    push("  npx htmsh [options] [command] [path] [domain]");
    push("");

    push(bold("Description"));
    push(sep);
    push("  Deploy static sites with a minimal, fast CLI");
    push("");

    push(bold("Arguments"));
    push(sep);
    push(`  ${dim("path:".padEnd(20))} directory to publish (default: .)`);
    push(
      `  ${dim("domain:".padEnd(20))} desired domain (used as project name)`
    );
    push("");

    push(bold("Options"));
    push(sep);
    for (const o of this.visibleOptions()) {
      const term = o.flags;
      const desc = o.description || "";
      push(`  ${dim((term + ":").padEnd(20))} ${desc}`);
    }
    push("");

    const cmds = this.visibleCommands();
    if (cmds.length) {
      push(bold("Commands"));
      push(sep);
      for (const c of cmds) {
        push(`  ${dim((c.name() + ":").padEnd(20))} ${c.description()}`);
      }
      push("");
    }

    return lines.join("\n");
  },
});

program.helpInformation = function () {
  const lines = [];
  const sep = dim("─".repeat(72));

  lines.push("");
  lines.push(bold("Usage"));
  lines.push(sep);
  lines.push("  htmsh [options] [command] [path] [domain]");
  lines.push("");

  lines.push(bold("Description"));
  lines.push(sep);
  lines.push("  Deploy static sites with a minimal, fast CLI");
  lines.push("");

  lines.push(bold("Arguments"));
  lines.push(sep);
  lines.push(`  ${dim("path:".padEnd(20))} directory to publish (default: .)`);
  lines.push(
    `  ${dim("domain:".padEnd(20))} desired domain (used as project name)`
  );
  lines.push("");

  lines.push(bold("Options"));
  lines.push(sep);
  for (const o of this.options) {
    lines.push(`  ${dim((o.flags + ":").padEnd(20))} ${o.description || ""}`);
  }
  lines.push("");

  if (this.commands.length) {
    lines.push(bold("Commands"));
    lines.push(sep);
    for (const c of this.commands) {
      lines.push(`  ${dim((c.name() + ":").padEnd(20))} ${c.description()}`);
    }
    lines.push("");
  }

  return lines.join("\n");
};

program.parse();

async function getCredentials({ interactive }) {
  const cached = store.get("creds");
  const now = Date.now();
  const ttl = cached?.ttlMs ?? DEFAULT_TTL;

  if (cached && cached.savedAt && now - cached.savedAt < ttl) {
    return { email: cached.email, password: cached.password, fromCache: true };
  }
  if (!interactive) throw new Error("Credentials required");

  const ans = await inquirer.prompt([
    {
      type: "input",
      name: "email",
      message: "  Email:",
      validate: (v) => !!v || "Required",
    },
    {
      type: "password",
      name: "password",
      message: "  Password:",
      mask: "*",
      validate: (v) => !!v || "Required",
    },
  ]);

  store.set("creds", {
    email: ans.email,
    password: ans.password,
    savedAt: now,
    ttlMs: DEFAULT_TTL,
  });

  return { ...ans, firstTime: !cached };
}
