export type FirewallStatus = "APPROVED" | "BLOCKED";
export type ThreatCategory =
  | "PROMPT_INJECTION"
  | "JAILBREAK"
  | "ROLEPLAY_ATTACK"
  | "MEMO_INJECTION"
  | "STRUCTURAL_ANOMALY"
  | "NONE";
export type TargetTool = "BALANCE_CHECK" | "TRANSFER_SIMULATION" | "MEMO_REVIEW";
export type ViewName = "overview" | "sandbox" | "ledger";

export interface FirewallDecision {
  status: FirewallStatus;
  risk_score: number;
  threat_category: ThreatCategory;
  explanation: string;
}

export interface FirewallRequest {
  target_tool: TargetTool;
  amount?: string;
  target_identifier?: string;
  memo: string;
}

export interface EncryptedAuditEnvelope {
  version: 1;
  algorithm: "AES-GCM";
  iv: string;
  ciphertext: string;
}

export interface FirewallSignals {
  character_entropy: number;
  manipulation_markers: number;
  punctuation_density: number;
  structural_irregularity: number;
  scanned_characters: number;
}

export interface FirewallLog {
  log_id: string;
  user_id: string;
  timestamp: string;
  incoming_prompt: string;
  target_tool: string;
  firewall_status: FirewallStatus;
  risk_score: number;
  threat_category: ThreatCategory;
  engine_explanation: string;
  sanitized_payload: string | null;
  signals: FirewallSignals;
  compliance_hash: string;
  latency_ms: number;
}

export interface UserAuditLog extends Omit<FirewallLog, "incoming_prompt" | "sanitized_payload"> {
  incoming_prompt: string;
  sanitized_payload: string | null;
}

export interface FirewallMetrics {
  total_inspected: number;
  threats_neutralized: number;
  average_risk: number;
  memos_inspected: number;
  health_coefficient: number;
  timeline: Array<{ label: string; approved: number; blocked: number }>;
  category_totals: Array<{ category: ThreatCategory; count: number }>;
}

export interface SimulationReceipt {
  reference: string;
  result: string;
  amount?: string;
  destination?: string;
  balance?: string;
  memo: string;
  simulated_at: string;
}

export interface SimulatedBankTransaction {
  transaction_id: string;
  reference: string;
  transaction_type: "DEPOSIT" | "TRANSFER_DEBIT" | "TRANSFER_CREDIT";
  amount: string;
  counterparty_account: string;
  memo: string;
  balance_after: string;
  created_at: string;
}

export interface SimulatedBankAccount {
  account_number: string;
  balance: string;
  recent_transactions: SimulatedBankTransaction[];
}

export interface SimulatedDepositReceipt {
  reference: string;
  balance: string;
  account: SimulatedBankAccount;
  result: string;
}
