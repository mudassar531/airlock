/**
 * Ed25519 keypair management for signing the audit chain head.
 *
 * `airlock init` generates a keypair under `~/.airlock/keys/`. The private
 * key is written PEM-encoded with 0600 mode; the public key is 0644. The
 * `sign(headHash)` helper produces a detached signature over the current
 * chain head, which `verify(headHash, signature)` can check independently
 * with only the public key — supporting workflows where you ship the audit
 * log to a reviewer with the public key but not the private key.
 *
 * Algorithm choice: ed25519 is the right default for offline signing —
 * small keys, small signatures, fast verification, no parameter pitfalls.
 */

import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";
import { writeFileSync, readFileSync, existsSync, chmodSync } from "node:fs";

import { airlockPaths, ensureAirlockHome, type AirlockPaths } from "../config.js";

export interface KeypairPaths {
  privateKeyPath: string;
  publicKeyPath: string;
}

/**
 * Generate an ed25519 keypair and write it to the standard Airlock paths
 * with restrictive permissions. Idempotent only if `force=false` and keys
 * already exist (returns the existing paths without rewriting).
 */
export function generateKeypair(
  paths: AirlockPaths = airlockPaths(),
  force: boolean = false,
): KeypairPaths {
  ensureAirlockHome(paths);
  if (
    !force &&
    existsSync(paths.privateKeyPath) &&
    existsSync(paths.publicKeyPath)
  ) {
    return { privateKeyPath: paths.privateKeyPath, publicKeyPath: paths.publicKeyPath };
  }
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const publicPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  writeFileSync(paths.privateKeyPath, privatePem, { mode: 0o600 });
  writeFileSync(paths.publicKeyPath, publicPem, { mode: 0o644 });
  try {
    chmodSync(paths.privateKeyPath, 0o600);
    chmodSync(paths.publicKeyPath, 0o644);
  } catch {
    // best effort
  }
  return { privateKeyPath: paths.privateKeyPath, publicKeyPath: paths.publicKeyPath };
}

export function loadPrivateKey(path: string): KeyObject {
  const pem = readFileSync(path, "utf8");
  return createPrivateKey(pem);
}

export function loadPublicKey(path: string): KeyObject {
  const pem = readFileSync(path, "utf8");
  return createPublicKey(pem);
}

/**
 * Sign an arbitrary string (typically the audit chain head hash) and return
 * the signature as base64. ed25519 doesn't use a separate digest algorithm,
 * so the algorithm argument to `crypto.sign` is `null`.
 */
export function signString(payload: string, privateKey: KeyObject): string {
  const sig = cryptoSign(null, Buffer.from(payload, "utf8"), privateKey);
  return sig.toString("base64");
}

export function verifyString(
  payload: string,
  signatureBase64: string,
  publicKey: KeyObject,
): boolean {
  try {
    return cryptoVerify(
      null,
      Buffer.from(payload, "utf8"),
      publicKey,
      Buffer.from(signatureBase64, "base64"),
    );
  } catch {
    return false;
  }
}
