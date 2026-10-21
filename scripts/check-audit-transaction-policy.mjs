import fs from "node:fs";
import path from "node:path";
import { rustSourceRoots } from "./lib/rust-sources.mjs";

const root = path.resolve(import.meta.dirname, "..");
// The api/ tree is a cargo workspace; scan every crate, not just the top one.
const sourceRoot = path.join(root, "api", "src");
const sourceRoots = rustSourceRoots(root);

function rustFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) return rustFiles(target);
    return entry.isFile() && entry.name.endsWith(".rs") ? [target] : [];
  });
}

function count(source, expression) {
  return [...source.matchAll(expression)].length;
}

const files = sourceRoots
  .flatMap((dir) => rustFiles(dir))
  .filter((file) => !file.endsWith(path.join("audit", "actor.rs")));
const source = files.map((file) => fs.readFileSync(file, "utf8")).join("\n");
const coupled = count(source, /\.log_(?:org|login|mfa|platform)_with_db\s*\(/g);
const standalone = count(source, /\.log_(?:org|login|mfa|platform)\s*\(/g);
const generic = count(
  source,
  /enqueue_(?:org|login|mfa|platform)_with_connection\s*\(/g,
);

const expected = { coupled: 50, standalone: 4, generic: 5 };
for (const [kind, actual] of Object.entries({ coupled, standalone, generic })) {
  if (actual !== expected[kind]) {
    throw new Error(
      `Audit ${kind} call count changed: expected ${expected[kind]}, found ${actual}. ` +
        "Classify the change and update docs/checker in the same review.",
    );
  }
}

const standaloneAllowlist = new Map([
  ["api/src/handlers/user.rs", 2],
  ["api/src/handlers/auth/mfa.rs", 1],
  ["api/src/handlers/auth/oauth.rs", 1],
]);
for (const file of files) {
  const relative = path.relative(root, file);
  const actual = count(
    fs.readFileSync(file, "utf8"),
    /\.log_(?:org|login|mfa|platform)\s*\(/g,
  );
  const allowed = standaloneAllowlist.get(relative) ?? 0;
  if (actual !== allowed) {
    throw new Error(
      `Standalone audit calls in ${relative}: expected ${allowed}, found ${actual}`,
    );
  }
}

const platformSource = rustFiles(path.join(sourceRoot, "handlers", "platform"))
  .map((file) => fs.readFileSync(file, "utf8"))
  .join("\n");
const platformHelperCalls = count(platformSource, /create_audit_log\s*\(/g);
if (platformHelperCalls !== 10) {
  throw new Error(
    `Platform audit helper caller count changed: expected 10, found ${platformHelperCalls}`,
  );
}

for (const relative of [
  "api/crates/authos-services/src/services/audit.rs",
  "api/src/handlers/platform/mod.rs",
  "api/crates/authos-store/src/store/login_events.rs",
]) {
  const contents = fs.readFileSync(path.join(root, relative), "utf8");
  if (/audit_log[^;\n]*\.insert|new_event\.insert/.test(contents)) {
    throw new Error(`Legacy direct final-table audit insert returned in ${relative}`);
  }
}

if (
  /(?:organization_audit_log|platform_audit_log|mfa_audit_log|login_events)::Entity::insert/.test(
    source,
  )
) {
  throw new Error("Direct audit final-table Entity::insert bypass detected");
}

console.log(
  `Audit policy OK: ${coupled} transaction-coupled handle calls, ` +
    `${standalone} standalone result calls, ${generic} generic durable enqueue paths, ` +
    `${platformHelperCalls} platform helper callers.`,
);
