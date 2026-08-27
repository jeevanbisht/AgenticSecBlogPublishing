import assert from "node:assert/strict";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { basename, dirname } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const profile = readFileSync(new URL("../src/pages/systems/[id].astro", import.meta.url), "utf8");
const panel = readFileSync(new URL("../src/components/EvidencePanel.astro", import.meta.url), "utf8");
const config = readFileSync(new URL("../astro.config.mjs", import.meta.url), "utf8");
const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const prepare = readFileSync(
  new URL("../../scripts/prepare_site_data.py", import.meta.url),
  "utf8",
);
const atom = readFileSync(new URL("../src/pages/atom.xml.js", import.meta.url), "utf8");
const wrangler = readFileSync(new URL("../../wrangler.jsonc", import.meta.url), "utf8");
const bootstrap = JSON.parse(
  readFileSync(
    new URL("../../deployment/downstream/bootstrap-layout.json", import.meta.url),
    "utf8",
  ),
);

test("capability headings cannot render bare confidence", () => {
  assert.doesNotMatch(profile, /<h3>[^<]*confidence/i);
  assert.match(profile, /<EvidencePanel panel=/);
  assert.match(profile, /<summary>Assertion support<\/summary>/);
});

test("evidence panel renders explicit NONE_FOUND and UNKNOWN states", () => {
  assert.match(panel, /NONE_FOUND/);
  assert.match(panel, /UNKNOWN/);
});

test("site is static and has sitemap integration", () => {
  assert.match(config, /output: "static"/);
  assert.match(config, /sitemap\(\)/);
  assert.doesNotMatch(config, /adapter/);
  assert.match(wrangler, /"pages_build_output_dir": "\.\/site\/dist"/);
  assert.match(wrangler, /"compatibility_date": "2026-08-26"/);
});

test("publication mode consumes only the validated public bundle", () => {
  assert.match(packageJson.scripts["prepare-data"], /prepare_site_data\.py/);
  assert.doesNotMatch(packageJson.scripts["prepare-data"], /generate_site_data\.py/);
  assert.doesNotMatch(prepare, /sqlite|database_path/i);
  assert.match(prepare, /validate_publication_bundle/);
  assert.match(atom, /context\.site/);
  assert.doesNotMatch(atom, /agentic-security-intelligence\.pages\.dev/);
});

test("downstream bootstrap is self-contained and prepares without SQLite", () => {
  const root = fileURLToPath(new URL("../..", import.meta.url));
  for (const path of bootstrap.required_paths) {
    assert.equal(existsSync(`${root}/${path}`), true, `missing bootstrap path: ${path}`);
  }
  assert.equal(bootstrap.required_paths.includes("data"), false);
  assert.match(packageJson.scripts.build, /prepare-data.*astro build/);
  const prepared = spawnSync(
    "python",
    ["../scripts/prepare_site_data.py", "--bundle", "../publication"],
    {
      cwd: fileURLToPath(new URL("..", import.meta.url)),
      env: {
        ...process.env,
        ASI_DATABASE_PATH: `${root}/missing-never-created.db`,
      },
      encoding: "utf8",
    },
  );
  assert.equal(prepared.status, 0, prepared.stderr);
  assert.doesNotMatch(prepared.stdout, /sqlite|database/i);

  if (process.env.ASI_BOOTSTRAP_STAGED !== "1") {
    const stage = `${root}/.bootstrap-test-${process.pid}`;
    rmSync(stage, { recursive: true, force: true });
    try {
      for (const path of bootstrap.required_paths) {
        const source = `${root}/${path}`;
        const destination = `${stage}/${path}`;
        mkdirSync(dirname(destination), { recursive: true });
        cpSync(source, destination, {
          recursive: true,
          filter: (candidate) =>
            ![".astro", "dist", "node_modules"].includes(basename(candidate)),
        });
      }
      symlinkSync(
        `${root}/site/node_modules`,
        `${stage}/site/node_modules`,
        process.platform === "win32" ? "junction" : "dir",
      );
      assert.ok(process.env.npm_execpath, "npm_execpath is required for staged npm test");
      const nested = spawnSync(
        process.execPath,
        [process.env.npm_execpath, "test"],
        {
          cwd: `${stage}/site`,
          env: { ...process.env, ASI_BOOTSTRAP_STAGED: "1" },
          encoding: "utf8",
        },
      );
      assert.equal(nested.status, 0, `${nested.stdout}\n${nested.stderr}`);
    } finally {
      rmSync(stage, { recursive: true, force: true });
    }
  }
});
