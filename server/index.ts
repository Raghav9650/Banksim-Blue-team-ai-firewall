import "dotenv/config";
import { createHash, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import express, { type ErrorRequestHandler, type Request, type Response } from "express";
import { z } from "zod";
import type { FirewallRequest, TargetTool } from "../src/types.ts";
import {
  evaluateBankSimFirewall,
  isValidTargetIdentifier,
  isValidTransferAmount,
} from "./firewall.ts";
import { verifyBankSimAccessToken } from "./auth.ts";
import {
  auditPersistenceMode,
  fetchFirewallLogs,
  fetchFirewallMetrics,
  fetchSimulatedBankAccount,
  postSimulatedDeposit,
  postSimulatedTransfer,
  persistFirewallLog,
  SimulatedBankingError,
} from "./repository.ts";

const app = express();
const projectDirectory = fileURLToPath(new URL("..", import.meta.url));
const compiledClientDirectory = join(projectDirectory, "dist");
const servicePort = Number(process.env.PORT ?? 4174);
const toolAllowlist = new Set<TargetTool>([
  "BALANCE_CHECK",
  "TRANSFER_SIMULATION",
  "MEMO_REVIEW",
]);
const firewallRequestSchema = z
  .object({
    target_tool: z.enum(["BALANCE_CHECK", "TRANSFER_SIMULATION", "MEMO_REVIEW"]),
    amount: z.string().max(32).optional(),
    target_identifier: z.string().max(48).optional(),
    memo: z.string().max(1800),
    encrypted_audit_payload: z.string().min(1).max(12_000),
    idempotency_key: z.string().uuid().optional(),
  })
  .strict();
const simulatedDepositSchema = z.object({
  amount: z.string().max(32),
  idempotency_key: z.string().uuid(),
}).strict();
const apiPathsServedByFunction = new Set([
  "/health",
  "/banking/account",
  "/banking/deposit",
  "/banking/simulate",
  "/firewall/evaluate",
  "/logs",
  "/metrics",
]);

type RequestState = { requestStartedAt: number; bankSimUserId?: string };
const requestStateByIp = new Map<string, { windowStartedAt: number; requestCount: number }>();
const requestWindowDurationMs = 60_000;
const requestWindowCapacity = 90;

app.disable("x-powered-by");
app.use(express.json({ limit: "12kb", strict: true }));
app.use((request: Request, _response: Response, next) => {
  if (
    process.env.VERCEL &&
    !request.path.startsWith("/api/") &&
    apiPathsServedByFunction.has(request.path)
  ) {
    request.url = `/api${request.url}`;
  }
  next();
});
app.use("/api", async (request: Request, response: Response, next) => {
  if (request.path === "/health") {
    next();
    return;
  }
  const authorizationHeader = request.header("authorization");
  const accessToken = authorizationHeader?.startsWith("Bearer ")
    ? authorizationHeader.slice("Bearer ".length).trim()
    : "";
  if (!accessToken) {
    response.status(401).json({ error: "Sign in is required to access personal BankSim data." });
    return;
  }
  try {
    const authenticatedUser = await verifyBankSimAccessToken(accessToken);
    (request as Request & RequestState).bankSimUserId = authenticatedUser.id;
    next();
  } catch (error) {
    const authError = error instanceof Error ? error.message : "Unable to verify the sign-in session.";
    const serviceConfigurationMissing =
      authError.includes("configure SUPABASE_URL") ||
      authError.includes("SUPABASE_ANON_KEY");
    response.status(serviceConfigurationMissing ? 503 : 401).json({ error: authError });
  }
});

app.use("/api", (request: Request, response: Response, next) => {
  const requesterAddress = request.ip ?? "unknown";
  const currentTime = Date.now();
  const accountIdentifier = (request as Request & RequestState).bankSimUserId ?? requesterAddress;
  const addressWindow = requestStateByIp.get(accountIdentifier);
  if (!addressWindow || currentTime - addressWindow.windowStartedAt >= requestWindowDurationMs) {
    if (requestStateByIp.size >= 5_000) {
      for (const [knownAddress, knownWindow] of requestStateByIp) {
        if (currentTime - knownWindow.windowStartedAt >= requestWindowDurationMs) {
          requestStateByIp.delete(knownAddress);
        }
        if (requestStateByIp.size < 4_000) break;
      }
    }
    if (requestStateByIp.size >= 5_000) {
      response.status(503).json({ error: "The request throttle is at capacity; retry shortly." });
      return;
    }
    requestStateByIp.set(accountIdentifier, { windowStartedAt: currentTime, requestCount: 1 });
    (request as Request & RequestState).requestStartedAt = currentTime;
    next();
    return;
  }
  addressWindow.requestCount += 1;
  if (addressWindow.requestCount > requestWindowCapacity) {
    response.status(429).json({ error: "Request rate limit reached. Retry after the current window." });
    return;
  }
  (request as Request & RequestState).requestStartedAt = currentTime;
  next();
});

function blockedBoundaryDecision(explanation: string) {
  return {
    status: "BLOCKED" as const,
    risk_score: 1,
    threat_category: "STRUCTURAL_ANOMALY" as const,
    explanation,
  };
}

async function createPersistedEvaluation(
  accountOwnerId: string,
  parsedRequest: FirewallRequest,
  encryptedAuditPayload: string,
  requestStartedAt: number,
) {
  const firewallEvaluation = evaluateBankSimFirewall(parsedRequest);
  const evaluationTimestamp = new Date().toISOString();
  const complianceHash = createHash("sha256")
    .update(
      JSON.stringify({
        encryptedAuditPayload,
        decision: firewallEvaluation.decision,
        timestamp: evaluationTimestamp,
      }),
    )
    .digest("hex");
  await persistFirewallLog({
    user_id: accountOwnerId,
    timestamp: evaluationTimestamp,
    incoming_prompt: encryptedAuditPayload,
    target_tool: parsedRequest.target_tool,
    firewall_status: firewallEvaluation.decision.status,
    risk_score: firewallEvaluation.decision.risk_score,
    threat_category: firewallEvaluation.decision.threat_category,
    engine_explanation: firewallEvaluation.decision.explanation,
    sanitized_payload:
      firewallEvaluation.decision.status === "APPROVED" ? encryptedAuditPayload : null,
    signals: firewallEvaluation.signals,
    compliance_hash: complianceHash,
    latency_ms: Math.max(0, Date.now() - requestStartedAt),
  });
  return firewallEvaluation;
}

async function readStrictFirewallRequest(request: Request, response: Response) {
  const validatedRequest = firewallRequestSchema.safeParse(request.body);
  if (!validatedRequest.success) {
    response.status(400).json(
      blockedBoundaryDecision(
        "Fail-safe boundary engaged: the request did not match the strict, allowlisted input shape; no banking action was routed.",
      ),
    );
    return null;
  }
  try {
    const encryptedAuditEnvelope: unknown = JSON.parse(validatedRequest.data.encrypted_audit_payload);
    if (
      !encryptedAuditEnvelope ||
      typeof encryptedAuditEnvelope !== "object" ||
      !("version" in encryptedAuditEnvelope) ||
      !("algorithm" in encryptedAuditEnvelope) ||
      !("iv" in encryptedAuditEnvelope) ||
      !("ciphertext" in encryptedAuditEnvelope) ||
      encryptedAuditEnvelope.version !== 1 ||
      encryptedAuditEnvelope.algorithm !== "AES-GCM" ||
      typeof encryptedAuditEnvelope.iv !== "string" ||
      typeof encryptedAuditEnvelope.ciphertext !== "string" ||
      encryptedAuditEnvelope.iv.length > 64 ||
      encryptedAuditEnvelope.ciphertext.length > 11_000
    ) {
      throw new Error("Unsupported encrypted request envelope.");
    }
    const initializationVector = Buffer.from(encryptedAuditEnvelope.iv, "base64");
    const encryptedBytes = Buffer.from(encryptedAuditEnvelope.ciphertext, "base64");
    if (initializationVector.length !== 12 || encryptedBytes.length < 16) {
      throw new Error("Encrypted request envelope has invalid AES-GCM fields.");
    }
  } catch {
    response.status(400).json(
      blockedBoundaryDecision(
        "Fail-safe boundary engaged: private audit encryption metadata is missing or malformed.",
      ),
    );
    return null;
  }
  if (!toolAllowlist.has(validatedRequest.data.target_tool)) {
    response.status(400).json(blockedBoundaryDecision("The requested tool is not on the simulator allowlist."));
    return null;
  }
  return validatedRequest.data satisfies FirewallRequest & { encrypted_audit_payload: string };
}

app.get("/api/health", (_request, response) => {
  response.json({
    status: auditPersistenceMode === "supabase" ? "operational" : "setup_required",
    authentication_configured: Boolean(process.env.SUPABASE_URL && process.env.SUPABASE_ANON_KEY),
    audit_persistence: auditPersistenceMode,
  });
});

app.get("/api/banking/account", async (request, response, next) => {
  try {
    response.json(
      await fetchSimulatedBankAccount((request as Request & RequestState).bankSimUserId!),
    );
  } catch (error) {
    next(error);
  }
});

app.post("/api/banking/deposit", async (request, response, next) => {
  const parsedDeposit = simulatedDepositSchema.safeParse(request.body);
  if (!parsedDeposit.success || !isValidTransferAmount(parsedDeposit.data.amount)) {
    response.status(400).json({
      error: "Enter a simulated deposit from $0.01 to $5,000.00 using at most two decimal places.",
    });
    return;
  }
  try {
    const accountOwnerId = (request as Request & RequestState).bankSimUserId!;
    const depositReceipt = await postSimulatedDeposit(
      accountOwnerId,
      parsedDeposit.data.amount,
      parsedDeposit.data.idempotency_key,
    );
    response.json({
      ...depositReceipt,
      account: await fetchSimulatedBankAccount(accountOwnerId),
      result: "Simulated deposit posted. No real money was received.",
    });
  } catch (error) {
    if (error instanceof SimulatedBankingError) {
      response.status(error.statusCode).json({ error: error.message });
      return;
    }
    next(error);
  }
});

app.post("/api/firewall/evaluate", async (request, response, next) => {
  const parsedRequest = await readStrictFirewallRequest(request, response);
  if (!parsedRequest) return;
  try {
    const firewallEvaluation = await createPersistedEvaluation(
      (request as Request & RequestState).bankSimUserId!,
      parsedRequest,
      parsedRequest.encrypted_audit_payload,
      (request as Request & RequestState).requestStartedAt,
    );
    response.json(firewallEvaluation.decision);
  } catch (error) {
    next(error);
  }
});

app.post("/api/banking/simulate", async (request, response, next) => {
  const parsedRequest = await readStrictFirewallRequest(request, response);
  if (!parsedRequest) return;
  try {
    const firewallEvaluation = await createPersistedEvaluation(
      (request as Request & RequestState).bankSimUserId!,
      parsedRequest,
      parsedRequest.encrypted_audit_payload,
      (request as Request & RequestState).requestStartedAt,
    );
    if (firewallEvaluation.decision.status !== "APPROVED") {
      response.status(403).json(firewallEvaluation.decision);
      return;
    }
    if (
      parsedRequest.target_tool === "TRANSFER_SIMULATION" &&
      (!isValidTransferAmount(parsedRequest.amount) ||
        !isValidTargetIdentifier(parsedRequest.target_identifier))
    ) {
      response.status(400).json({
        error: "Transfer simulation requires an amount from 0.01 to 5,000 and a valid 4–24 character target identifier.",
      });
      return;
    }
    const accountOwnerId = (request as Request & RequestState).bankSimUserId!;
    let transferReceipt: { reference: string; balance: string } | null = null;
    let accountState: Awaited<ReturnType<typeof fetchSimulatedBankAccount>> | null = null;
    if (parsedRequest.target_tool === "TRANSFER_SIMULATION") {
      if (!parsedRequest.idempotency_key) {
        response.status(400).json({ error: "A unique transfer request key is required." });
        return;
      }
      transferReceipt = await postSimulatedTransfer(
        accountOwnerId,
        parsedRequest.amount!,
        parsedRequest.target_identifier!,
        parsedRequest.encrypted_audit_payload,
        parsedRequest.idempotency_key,
      );
    } else if (parsedRequest.target_tool === "BALANCE_CHECK") {
      accountState = await fetchSimulatedBankAccount(accountOwnerId);
    }
    const simulationReference = `SIM-${randomUUID().slice(0, 8).toUpperCase()}`;
    response.json({
      reference: transferReceipt?.reference ?? simulationReference,
      result:
        parsedRequest.target_tool === "BALANCE_CHECK"
          ? "Simulated balance inquiry completed. No live bank data was accessed."
          : parsedRequest.target_tool === "TRANSFER_SIMULATION"
            ? "Simulated transfer posted to both BankSim accounts. No real funds moved."
            : "Memo reviewed. No financial action was requested.",
      amount: parsedRequest.amount,
      destination: parsedRequest.target_identifier,
      balance: transferReceipt?.balance ?? accountState?.balance,
      memo: firewallEvaluation.sanitized_memo,
      simulated_at: new Date().toISOString(),
    });
  } catch (error) {
    if (error instanceof SimulatedBankingError) {
      response.status(error.statusCode).json({ error: error.message });
      return;
    }
    next(error);
  }
});

app.get("/api/logs", async (request, response, next) => {
  const requestedLimit = Number(request.query.limit ?? 50);
  if (!Number.isInteger(requestedLimit) || requestedLimit < 1 || requestedLimit > 200) {
    response.status(400).json({ error: "Log limit must be an integer between 1 and 200." });
    return;
  }
  try {
    response.json(
      await fetchFirewallLogs(
        (request as Request & RequestState).bankSimUserId!,
        requestedLimit,
      ),
    );
  } catch (error) {
    next(error);
  }
});

app.get("/api/metrics", async (_request, response, next) => {
  try {
    response.json(
      await fetchFirewallMetrics((_request as Request & RequestState).bankSimUserId!),
    );
  } catch (error) {
    next(error);
  }
});

if (existsSync(compiledClientDirectory)) {
  app.use(express.static(compiledClientDirectory, { index: false }));
  app.use((request, response, next) => {
    if (request.method !== "GET" || request.path.startsWith("/api/")) {
      next();
      return;
    }
    response.sendFile(join(compiledClientDirectory, "index.html"), (sendFailure) => {
      if (sendFailure) next(sendFailure);
    });
  });
}

const requestFailureHandler: ErrorRequestHandler = (error, _request, response, _next) => {
  const requestFailure = error instanceof Error ? error : new Error("Unknown request processing failure.");
  console.error("[BankSim firewall]", requestFailure.message);
  if (response.headersSent) return;
  response.status(503).json({
    error: "Audit persistence or request processing failed. The banking action was not executed.",
  });
};
app.use(requestFailureHandler);

if (!process.env.VERCEL) {
  app.listen(servicePort, () => {
    console.info(
      `[BankSim] API listening on ${servicePort}; audit persistence: ${auditPersistenceMode}.`,
    );
  });
}

export default app;
