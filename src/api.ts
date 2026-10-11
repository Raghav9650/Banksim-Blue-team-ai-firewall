import type {
  FirewallDecision,
  FirewallLog,
  FirewallMetrics,
  FirewallRequest,
  SimulatedBankAccount,
  SimulatedDepositReceipt,
  SimulationReceipt,
} from "./types";

export async function readBankSimApiJson<ResponseShape>(
  apiResponse: Response,
  routePath: string,
): Promise<ResponseShape> {
  const responseText = await apiResponse.text();
  let responseContent: unknown;
  try {
    responseContent = JSON.parse(responseText);
  } catch {
    const returnedHtml =
      apiResponse.headers.get("content-type")?.includes("text/html") ||
      /^\s*<!doctype html|^\s*<html/iu.test(responseText);
    if (returnedHtml) {
      throw new Error(
        `BankSim API route ${routePath} returned an HTML page instead of JSON (HTTP ${apiResponse.status}). Check Vercel's API function routing and redeploy.`,
      );
    }
    throw new Error(
      `BankSim API route ${routePath} returned an invalid JSON response (HTTP ${apiResponse.status}).`,
    );
  }

  if (!apiResponse.ok) {
    const reportedError =
      responseContent &&
      typeof responseContent === "object" &&
      "error" in responseContent
        ? String(responseContent.error)
        : `Request failed with HTTP ${apiResponse.status}.`;
    throw new Error(reportedError);
  }
  return responseContent as ResponseShape;
}

async function banksimApiRequest<ResponseShape>(
  routePath: string,
  accessToken: string,
  requestBody?: unknown,
): Promise<ResponseShape> {
  const apiResponse = await fetch(routePath, {
    method: requestBody === undefined ? "GET" : "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      ...(requestBody === undefined ? {} : { "Content-Type": "application/json" }),
    },
    body: requestBody === undefined ? undefined : JSON.stringify(requestBody),
  });

  return readBankSimApiJson<ResponseShape>(apiResponse, routePath);
}

export const evaluateFirewallRequest = (
  request: FirewallRequest,
  accessToken: string,
  encryptedAuditPayload: string,
) =>
  banksimApiRequest<FirewallDecision>("/api/firewall/evaluate", accessToken, {
    ...request,
    encrypted_audit_payload: encryptedAuditPayload,
  });

export const simulateSafeTransaction = (
  request: FirewallRequest,
  accessToken: string,
  encryptedAuditPayload: string,
  idempotencyKey: string,
) =>
  banksimApiRequest<SimulationReceipt>("/api/banking/simulate", accessToken, {
    ...request,
    encrypted_audit_payload: encryptedAuditPayload,
    idempotency_key: idempotencyKey,
  });

export const loadSimulatedBankAccount = (accessToken: string) =>
  banksimApiRequest<SimulatedBankAccount>("/api/banking/account", accessToken);

export const depositSimulatedFunds = (
  amount: string,
  accessToken: string,
  idempotencyKey: string,
) =>
  banksimApiRequest<SimulatedDepositReceipt>("/api/banking/deposit", accessToken, {
    amount,
    idempotency_key: idempotencyKey,
  });

export const loadFirewallLogs = (accessToken: string, limit = 50) =>
  banksimApiRequest<FirewallLog[]>(`/api/logs?limit=${limit}`, accessToken);

export const loadFirewallMetrics = (accessToken: string) =>
  banksimApiRequest<FirewallMetrics>("/api/metrics", accessToken);
