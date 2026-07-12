#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { parseDocument } from "yaml";

function inspect(value, source, path = [], result = { checkoutCount: 0 }) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => inspect(item, source, [...path, index], result));
    return result;
  }
  if (!value || typeof value !== "object") return result;

  if (typeof value.uses === "string" && value.uses.startsWith("actions/checkout@")) {
    result.checkoutCount += 1;
    if (!value.with || value.with["persist-credentials"] !== false) {
      throw new Error(`${source}:${path.join(".")}: checkout must set with.persist-credentials to boolean false`);
    }
  }
  for (const [key, child] of Object.entries(value)) inspect(child, source, [...path, key], result);
  return result;
}

function validateWorkflow(path) {
  const document = parseDocument(readFileSync(path, "utf8"), {
    prettyErrors: false,
    strict: true,
    uniqueKeys: true,
  });
  if (document.errors.length) throw document.errors[0];
  return inspect(document.toJS({ maxAliasCount: 100 }), path);
}

const paths = process.argv.slice(2);
if (paths.length === 0) throw new Error("workflow path required");
let checkoutCount = 0;
for (const path of paths) checkoutCount += validateWorkflow(path).checkoutCount;
if (checkoutCount === 0) throw new Error("no checkout action found");
process.stdout.write(`${JSON.stringify({ ok: true, checkout_count: checkoutCount })}\n`);
