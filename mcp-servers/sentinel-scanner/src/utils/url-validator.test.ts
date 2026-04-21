import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { isPublicUrl } from "./url-validator.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = resolve(here, "../../../../tests/fixtures/url-validator");

const privateUrls = readFileSync(resolve(fixturesDir, "private.txt"), "utf8")
  .trim()
  .split("\n");
const publicUrls = readFileSync(resolve(fixturesDir, "public.txt"), "utf8")
  .trim()
  .split("\n");

for (const url of privateUrls) {
  test(`rejects private URL: ${url}`, () => {
    assert.equal(isPublicUrl(url), false);
  });
}

for (const url of publicUrls) {
  test(`accepts public URL: ${url}`, () => {
    assert.equal(isPublicUrl(url), true);
  });
}
