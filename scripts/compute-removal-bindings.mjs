#!/usr/bin/env node

import { constants } from "node:fs";
import { open } from "node:fs/promises";
import process from "node:process";

import {
  parseRemovalProfile,
  removalProfileDigest,
  removalSmtpDigest,
  validateSmtpConfig,
} from "../dist/lib/removal.mjs";
import { scanProfileDigest } from "../dist/lib/live-scan.mjs";

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}

async function readPrivateJson(path, label) {
  if (!Number.isInteger(constants.O_NOFOLLOW)) throw new Error(`${label}_nofollow_unavailable`);
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    throw new Error(`${label}_file_unavailable`);
  }
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || (metadata.mode & 0o077) !== 0) {
      throw new Error(`${label}_file_must_be_private_mode_0600`);
    }
    return await handle.readFile({ encoding: "utf8" });
  } catch (error) {
    if (error instanceof Error && error.message === `${label}_file_must_be_private_mode_0600`) throw error;
    throw new Error(`${label}_file_unavailable`);
  } finally {
    try {
      await handle.close();
    } catch {
      // The descriptor is never reused; do not expose path-bearing close errors.
    }
  }
}

async function main() {
  const [profileId, profilePath, smtpPath] = process.argv.slice(2);
  if (!/^profile_[a-f0-9]{16,32}$/.test(profileId ?? "") || !profilePath || !smtpPath) {
    throw new Error("usage: compute-removal-bindings.mjs PROFILE_ID PRIVATE_PROFILE_JSON PRIVATE_SMTP_JSON");
  }
  const profilePayload = await readPrivateJson(profilePath, "profile");
  const smtpPayload = await readPrivateJson(smtpPath, "smtp");
  const profile = parseRemovalProfile(profilePayload);
  const smtp = validateSmtpConfig(JSON.parse(smtpPayload), profile);
  process.stdout.write(`${JSON.stringify({
    scanProfileDigests: { [profileId]: scanProfileDigest(profilePayload) },
    authorizedProfileDigests: { [profileId]: removalProfileDigest(profilePayload) },
    smtpTransportDigest: removalSmtpDigest(smtp),
  }, null, 2)}\n`);
}

main().catch((error) => fail(error instanceof Error ? error.message : "binding_generation_failed"));
