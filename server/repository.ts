import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type {
  FirewallLog,
  FirewallMetrics,
  SimulatedBankAccount,
  SimulatedBankTransaction,
  ThreatCategory,
} from "../src/types.ts";

export interface NewFirewallLog extends Omit<FirewallLog, "log_id" | "user_id"> {
  user_id: string;
}

export class SimulatedBankingError extends Error {
  constructor(
    message: string,
    readonly statusCode: 400 | 404 | 409,
  ) {
    super(message);
    this.name = "SimulatedBankingError";
  }
}

const threatCategories: ThreatCategory[] = [
  "PROMPT_INJECTION",
  "JAILBREAK",
  "ROLEPLAY_ATTACK",
  "MEMO_INJECTION",
  "STRUCTURAL_ANOMALY",
  "NONE",
];

function createBankSimServiceClient(): SupabaseClient {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !supabaseServiceRoleKey) {
    throw new Error(
      "Private audit storage is unavailable: configure SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.",
    );
  }
  return createClient(supabaseUrl, supabaseServiceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
}

let supabaseServiceClient: SupabaseClient | null = null;

function getServiceClient(): SupabaseClient {
  if (!supabaseServiceClient) supabaseServiceClient = createBankSimServiceClient();
  return supabaseServiceClient;
}

export const auditPersistenceMode =
  process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY ? "supabase" : "not-configured";

export async function persistFirewallLog(logEntry: NewFirewallLog): Promise<FirewallLog> {
  const { data: insertedRecord, error: insertFailure } = await getServiceClient()
    .from("banksim_firewall_logs")
    .insert(logEntry)
    .select("log_id,user_id,timestamp,incoming_prompt,target_tool,firewall_status,risk_score,threat_category,engine_explanation,sanitized_payload,signals,compliance_hash,latency_ms")
    .single();
  if (insertFailure) throw new Error(`Supabase audit write failed: ${insertFailure.message}`);
  return insertedRecord as FirewallLog;
}

export async function fetchFirewallLogs(
  accountOwnerId: string,
  requestedLimit: number,
): Promise<FirewallLog[]> {
  const { data: auditRows, error: readFailure } = await getServiceClient()
    .from("banksim_firewall_logs")
    .select("log_id,user_id,timestamp,incoming_prompt,target_tool,firewall_status,risk_score,threat_category,engine_explanation,sanitized_payload,signals,compliance_hash,latency_ms")
    .eq("user_id", accountOwnerId)
    .order("timestamp", { ascending: false })
    .limit(requestedLimit);
  if (readFailure) throw new Error(`Supabase private audit read failed: ${readFailure.message}`);
  return (auditRows ?? []) as FirewallLog[];
}

function constructMetrics(auditRows: FirewallLog[]): FirewallMetrics {
  const blockedRows = auditRows.filter((row) => row.firewall_status === "BLOCKED");
  const averageRisk =
    auditRows.length === 0
      ? 0
      : auditRows.reduce((riskTotal, row) => riskTotal + Number(row.risk_score), 0) /
        auditRows.length;
  const structurallyValidAuditCount = auditRows.filter(
    (row) =>
      Number.isFinite(Date.parse(row.timestamp)) &&
      Number.isFinite(Number(row.risk_score)) &&
      Number(row.risk_score) >= 0 &&
      Number(row.risk_score) <= 1 &&
      (row.firewall_status === "APPROVED" || row.firewall_status === "BLOCKED") &&
      Number.isInteger(row.latency_ms) &&
      row.latency_ms >= 0,
  ).length;
  const hourlyTimeline: FirewallMetrics["timeline"] = [];
  const currentTime = Date.now();

  for (let hoursBack = 23; hoursBack >= 0; hoursBack -= 1) {
    const hourStart = new Date(currentTime - hoursBack * 60 * 60 * 1000);
    hourStart.setMinutes(0, 0, 0);
    const hourRows = auditRows.filter((row) => {
      const rowDate = new Date(row.timestamp);
      return rowDate >= hourStart && rowDate.getTime() < hourStart.getTime() + 60 * 60 * 1000;
    });
    hourlyTimeline.push({
      label: hourStart.toLocaleTimeString("en-US", { hour: "2-digit", hour12: false }),
      approved: hourRows.filter((row) => row.firewall_status === "APPROVED").length,
      blocked: hourRows.filter((row) => row.firewall_status === "BLOCKED").length,
    });
  }

  return {
    total_inspected: auditRows.length,
    threats_neutralized: blockedRows.length,
    average_risk: Number(averageRisk.toFixed(3)),
    memos_inspected: auditRows.length,
    health_coefficient:
      auditRows.length === 0
        ? 1
        : Number((structurallyValidAuditCount / auditRows.length).toFixed(3)),
    timeline: hourlyTimeline,
    category_totals: threatCategories.map((category) => ({
      category,
      count: auditRows.filter((row) => row.threat_category === category).length,
    })),
  };
}

export async function fetchFirewallMetrics(accountOwnerId: string): Promise<FirewallMetrics> {
  const rowsForMetrics = await fetchFirewallLogs(accountOwnerId, 500);
  return constructMetrics(rowsForMetrics);
}

export async function fetchSimulatedBankAccount(accountOwnerId: string): Promise<SimulatedBankAccount> {
  const { data: profile, error: profileFailure } = await getServiceClient()
    .from("bank_users")
    .select("account_number,balance")
    .eq("uuid", accountOwnerId)
    .single();
  if (profileFailure || !profile) {
    throw new Error(`Simulated bank account read failed: ${profileFailure?.message ?? "Account not found."}`);
  }

  const { data: transactions, error: transactionsFailure } = await getServiceClient()
    .from("banksim_simulated_transactions")
    .select("transaction_id,reference,transaction_type,amount,counterparty_account,memo,balance_after,created_at")
    .eq("account_owner_id", accountOwnerId)
    .order("created_at", { ascending: false })
    .limit(10);
  if (transactionsFailure) {
    if (
      transactionsFailure.message.includes("banksim_simulated_transactions") ||
      transactionsFailure.message.includes("schema cache")
    ) {
      throw new Error(
        "Simulated banking schema is not installed. Run the updated sql/supabase.sql in Supabase SQL Editor.",
      );
    }
    throw new Error(`Simulated bank activity read failed: ${transactionsFailure.message}`);
  }

  return {
    account_number: profile.account_number,
    balance: String(profile.balance),
    recent_transactions: (transactions ?? []) as SimulatedBankTransaction[],
  };
}

function parseBankingMutationResult(
  result: unknown,
  operation: "deposit" | "transfer",
): { reference: string; balance: string } {
  if (
    result === null ||
    typeof result !== "object" ||
    !("reference" in result) ||
    typeof result.reference !== "string" ||
    !("balance" in result) ||
    (typeof result.balance !== "string" && typeof result.balance !== "number")
  ) {
    throw new Error(`Simulated ${operation} returned an invalid account receipt.`);
  }
  return { reference: result.reference, balance: String(result.balance) };
}

function raiseBankingMutationFailure(
  errorMessage: string,
  operation: "deposit" | "transfer",
): never {
  if (errorMessage.includes("INSUFFICIENT_SIMULATED_FUNDS")) {
    throw new SimulatedBankingError("Insufficient simulated funds for this transfer.", 409);
  }
  if (errorMessage.includes("SIMULATED_RECIPIENT_NOT_FOUND")) {
    throw new SimulatedBankingError("No BankSim account was found for that recipient.", 404);
  }
  if (errorMessage.includes("SIMULATED_ACCOUNT_NOT_FOUND")) {
    throw new SimulatedBankingError("The signed-in BankSim account could not be found.", 404);
  }
  if (errorMessage.includes("SIMULATED_INVALID_AMOUNT")) {
    throw new SimulatedBankingError("Enter a valid simulated amount from $0.01 to $5,000.00.", 400);
  }
  if (
    errorMessage.includes("SIMULATED_SELF_TRANSFER_NOT_ALLOWED") ||
    errorMessage.includes("SIMULATED_INVALID_MEMO") ||
    errorMessage.includes("SIMULATED_INVALID_IDEMPOTENCY_KEY")
  ) {
    throw new SimulatedBankingError("The simulated transaction details are invalid.", 400);
  }
  throw new Error(`Simulated ${operation} could not be posted: ${errorMessage}`);
}

export async function postSimulatedDeposit(
  accountOwnerId: string,
  amount: string,
  idempotencyKey: string,
): Promise<{ reference: string; balance: string }> {
  const { data: mutationResult, error: mutationFailure } = await getServiceClient().rpc(
    "banksim_simulated_deposit",
    {
      p_owner_id: accountOwnerId,
      p_amount: amount,
      p_idempotency_key: idempotencyKey,
    },
  );
  if (mutationFailure) raiseBankingMutationFailure(mutationFailure.message, "deposit");
  return parseBankingMutationResult(mutationResult, "deposit");
}

export async function postSimulatedTransfer(
  accountOwnerId: string,
  amount: string,
  recipientAccountNumber: string,
  encryptedMemo: string,
  idempotencyKey: string,
): Promise<{ reference: string; balance: string }> {
  const { data: mutationResult, error: mutationFailure } = await getServiceClient().rpc(
    "banksim_simulated_transfer",
    {
      p_sender_id: accountOwnerId,
      p_recipient_account: recipientAccountNumber,
      p_amount: amount,
      p_encrypted_memo: encryptedMemo,
      p_idempotency_key: idempotencyKey,
    },
  );
  if (mutationFailure) raiseBankingMutationFailure(mutationFailure.message, "transfer");
  return parseBankingMutationResult(mutationResult, "transfer");
}
