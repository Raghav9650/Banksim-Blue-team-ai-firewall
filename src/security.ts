import type { EncryptedAuditEnvelope, FirewallRequest, UserAuditLog } from "./types";

const banksimPasswordDerivationIterations = 600_000;
const banksimKeyDerivationDomain = "BankSim account-private audit key v1";
const banksimUserAuditKeyCache = new Map<string, CryptoKey>();
const banksimUserAuditKeyCacheLimit = 4;

export function clearUserAuditEncryptionKeyCache(): void {
  banksimUserAuditKeyCache.clear();
}

async function createAuditKeyCacheIdentifier(
  accountPassword: string,
  accountId: string,
  profileEncryptionSaltHex: string,
): Promise<string> {
  const cacheMaterial = new TextEncoder().encode(
    `${banksimKeyDerivationDomain}\u0000${accountId}\u0000${profileEncryptionSaltHex.toLowerCase()}\u0000${accountPassword}`,
  );
  const fingerprint = new Uint8Array(await crypto.subtle.digest("SHA-256", cacheMaterial));
  return Array.from(fingerprint, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes: Uint8Array): string {
  let binaryString = "";
  for (const byte of bytes) binaryString += String.fromCharCode(byte);
  return btoa(binaryString);
}

function base64ToBytes(encodedText: string): ArrayBuffer {
  const binaryString = atob(encodedText);
  const decodedBuffer = new ArrayBuffer(binaryString.length);
  const decodedBytes = new Uint8Array(decodedBuffer);
  for (let byteIndex = 0; byteIndex < binaryString.length; byteIndex += 1) {
    decodedBytes[byteIndex] = binaryString.charCodeAt(byteIndex);
  }
  return decodedBuffer;
}

export async function createUserAuditEncryptionKey(
  accountPassword: string,
  accountId: string,
  profileEncryptionSaltHex: string,
): Promise<CryptoKey> {
  if (
    accountPassword.length < 1 ||
    accountId.length < 1 ||
    !/^[\da-f]{32}$/iu.test(profileEncryptionSaltHex)
  ) {
    throw new Error("The private audit key could not be unlocked: account key metadata is invalid.");
  }

  const saltBytes = Uint8Array.from(
    profileEncryptionSaltHex.match(/.{2}/gu)!.map((hexByte) => Number.parseInt(hexByte, 16)),
  );
  const cacheIdentifier = await createAuditKeyCacheIdentifier(
    accountPassword,
    accountId,
    profileEncryptionSaltHex,
  );
  const cachedKey = banksimUserAuditKeyCache.get(cacheIdentifier);
  if (cachedKey) return cachedKey;

  const passwordMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(`${banksimKeyDerivationDomain}\u0000${accountId}\u0000${accountPassword}`),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations: banksimPasswordDerivationIterations,
    },
    passwordMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  banksimUserAuditKeyCache.set(cacheIdentifier, derivedKey);
  while (banksimUserAuditKeyCache.size > banksimUserAuditKeyCacheLimit) {
    const oldestCacheIdentifier = banksimUserAuditKeyCache.keys().next().value as string | undefined;
    if (!oldestCacheIdentifier) break;
    banksimUserAuditKeyCache.delete(oldestCacheIdentifier);
  }
  return derivedKey;
}

export async function encryptPrivateAuditValue(
  privateAuditKey: CryptoKey,
  sensitiveValue: string,
): Promise<EncryptedAuditEnvelope> {
  const uniqueInitializationVector = crypto.getRandomValues(new Uint8Array(12));
  const encryptedValue = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: uniqueInitializationVector },
    privateAuditKey,
    new TextEncoder().encode(sensitiveValue),
  );
  return {
    version: 1,
    algorithm: "AES-GCM",
    iv: bytesToBase64(uniqueInitializationVector),
    ciphertext: bytesToBase64(new Uint8Array(encryptedValue)),
  };
}

export async function decryptPrivateAuditValue(
  privateAuditKey: CryptoKey,
  envelopeJson: string,
): Promise<string> {
  let encryptedEnvelope: EncryptedAuditEnvelope;
  try {
    const parsedEnvelope: unknown = JSON.parse(envelopeJson);
    if (
      !parsedEnvelope ||
      typeof parsedEnvelope !== "object" ||
      !("version" in parsedEnvelope) ||
      !("algorithm" in parsedEnvelope) ||
      !("iv" in parsedEnvelope) ||
      !("ciphertext" in parsedEnvelope) ||
      parsedEnvelope.version !== 1 ||
      parsedEnvelope.algorithm !== "AES-GCM" ||
      typeof parsedEnvelope.iv !== "string" ||
      typeof parsedEnvelope.ciphertext !== "string"
    ) {
      throw new Error("Encrypted audit record has an unsupported envelope.");
    }
    encryptedEnvelope = parsedEnvelope as EncryptedAuditEnvelope;
  } catch (error) {
    throw new Error(
      error instanceof Error
        ? `Private audit record could not be parsed: ${error.message}`
        : "Private audit record could not be parsed.",
    );
  }

  try {
    const clearTextBytes = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64ToBytes(encryptedEnvelope.iv),
      },
      privateAuditKey,
      base64ToBytes(encryptedEnvelope.ciphertext),
    );
    return new TextDecoder().decode(clearTextBytes);
  } catch (error) {
    if (
      error &&
      typeof error === "object" &&
      "name" in error &&
      error.name === "OperationError"
    ) {
      throw new Error(
        "Encrypted with prior credentials: private audit record could not be decrypted with this account's encryption key.",
        { cause: error },
      );
    }
    throw new Error("Private audit record could not be decrypted with this account's encryption key.", {
      cause: error,
    });
  }
}

export function isPriorCredentialsDecryptionError(error: unknown): boolean {
  return error instanceof Error && error.message.startsWith("Encrypted with prior credentials:");
}

export async function encryptAuditRequest(
  privateAuditKey: CryptoKey,
  requestPayload: FirewallRequest,
): Promise<string> {
  return JSON.stringify(await encryptPrivateAuditValue(privateAuditKey, JSON.stringify(requestPayload)));
}

export async function decryptAuditLog(
  privateAuditKey: CryptoKey,
  encryptedLog: UserAuditLog,
): Promise<UserAuditLog> {
  let decryptedRequestText: string;
  try {
    decryptedRequestText = await decryptPrivateAuditValue(
      privateAuditKey,
      encryptedLog.incoming_prompt,
    );
  } catch (error) {
    if (!isPriorCredentialsDecryptionError(error)) throw error;
    return {
      ...encryptedLog,
      incoming_prompt: "Encrypted with prior credentials",
      sanitized_payload: encryptedLog.sanitized_payload
        ? "Encrypted with prior credentials"
        : null,
    };
  }
  let parsedRequest: FirewallRequest;
  try {
    const parsedPayload: unknown = JSON.parse(decryptedRequestText);
    if (
      !parsedPayload ||
      typeof parsedPayload !== "object" ||
      !("target_tool" in parsedPayload) ||
      !("memo" in parsedPayload) ||
      typeof parsedPayload.target_tool !== "string" ||
      typeof parsedPayload.memo !== "string"
    ) {
      throw new Error("Encrypted request does not match the expected format.");
    }
    parsedRequest = parsedPayload as FirewallRequest;
  } catch (error) {
    throw new Error(
      error instanceof Error
        ? `Private request details could not be decoded: ${error.message}`
        : "Private request details could not be decoded.",
    );
  }

  const incomingPrompt = [
    `tool=${parsedRequest.target_tool}`,
    parsedRequest.amount ? `amount=${parsedRequest.amount}` : "",
    parsedRequest.target_identifier ? `target=${parsedRequest.target_identifier}` : "",
    `memo=${parsedRequest.memo}`,
  ]
    .filter((segment) => segment.length > 0)
    .join(" | ");

  let sanitizedPayload: string | null = null;
  if (encryptedLog.sanitized_payload) {
    try {
      const decryptedApprovedPayload = await decryptPrivateAuditValue(
        privateAuditKey,
        encryptedLog.sanitized_payload,
      );
      sanitizedPayload = JSON.stringify({
        ...parsedRequest,
        memo: parsedRequest.memo.normalize("NFKC").replace(/\s+/gu, " ").trim(),
        signals: encryptedLog.signals,
        compliance_hash: encryptedLog.compliance_hash,
        encrypted_payload: decryptedApprovedPayload,
      });
    } catch (error) {
      if (!isPriorCredentialsDecryptionError(error)) throw error;
      sanitizedPayload = "Encrypted with prior credentials";
    }
  }

  return { ...encryptedLog, incoming_prompt: incomingPrompt, sanitized_payload: sanitizedPayload };
}
