import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import {
  Activity,
  ArrowUpRight,
  Banknote,
  Bell,
  Blocks,
  Bug,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  Command,
  Copy,
  Fingerprint,
  Gauge,
  LockKeyhole,
  LogOut,
  ScanSearch,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  TerminalSquare,
  X,
  Zap,
} from "lucide-react";
import {
  evaluateFirewallRequest,
  loadFirewallLogs,
  loadFirewallMetrics,
  loadSimulatedBankAccount,
  depositSimulatedFunds,
  readBankSimApiJson,
  simulateSafeTransaction,
} from "./api";
import { AuthenticationScreen } from "./AuthScreen";
import { LiveSandbox, examplePayloads } from "./components/LiveSandbox";
import {
  createUserAuditEncryptionKey,
  clearUserAuditEncryptionKeyCache,
  decryptAuditLog,
  decryptPrivateAuditValue,
  encryptAuditRequest,
  encryptPrivateAuditValue,
  isPriorCredentialsDecryptionError,
} from "./security";
import { supabaseClient, supabaseConfigurationReady } from "./supabase";
import type {
  FirewallDecision,
  FirewallLog,
  FirewallMetrics,
  FirewallRequest,
  SimulationReceipt,
  SimulatedBankAccount,
  ViewName,
} from "./types";

const initialRequest: FirewallRequest = {
  target_tool: "TRANSFER_SIMULATION",
  amount: "125.50",
  target_identifier: "",
  memo: "Monthly rent for apartment 4B",
};

const navigationItems: Array<{ id: ViewName; label: string; icon: typeof Gauge }> = [
  { id: "overview", label: "Command center", icon: Gauge },
  { id: "sandbox", label: "Live sandbox", icon: TerminalSquare },
  { id: "ledger", label: "Security ledger", icon: Blocks },
];

function displayClock(timestamp: string): string {
  return new Date(timestamp).toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

async function decryptSimulatedBankActivity(
  privateAuditKey: CryptoKey,
  account: SimulatedBankAccount,
): Promise<SimulatedBankAccount> {
  const recentTransactions = await Promise.all(
    (Array.isArray(account.recent_transactions) ? account.recent_transactions : []).map(async (transaction) => {
      if (transaction.transaction_type !== "TRANSFER_DEBIT") return transaction;
      let decodedRequestText: string;
      try {
        decodedRequestText = await decryptPrivateAuditValue(privateAuditKey, transaction.memo);
      } catch (error) {
        if (isPriorCredentialsDecryptionError(error)) {
          return { ...transaction, memo: "Encrypted with prior credentials" };
        }
        throw error;
      }
      const decodedRequest: unknown = JSON.parse(decodedRequestText);
      if (
        decodedRequest === null ||
        typeof decodedRequest !== "object" ||
        !("memo" in decodedRequest) ||
        typeof decodedRequest.memo !== "string"
      ) {
        throw new Error("A private simulated transfer memo could not be decoded.");
      }
      return { ...transaction, memo: decodedRequest.memo };
    }),
  );
  return { ...account, recent_transactions: recentTransactions };
}

function RiskPill({ score }: { score: number }) {
  const riskTone = score >= 0.44 ? "risk-high" : score >= 0.23 ? "risk-medium" : "risk-low";
  return <span className={`risk-pill ${riskTone}`}>{score.toFixed(2)}</span>;
}

function VerdictBadge({ status }: { status: "APPROVED" | "BLOCKED" | "REVIEW" }) {
  const isApproved = status === "APPROVED";
  const isReview = status === "REVIEW";
  return (
    <span className={`verdict-badge ${isApproved ? "approved" : isReview ? "review" : "blocked"}`}>
      {isApproved ? <CircleCheck size={13} /> : isReview ? <CircleAlert size={13} /> : <ShieldAlert size={13} />}
      {status}
    </span>
  );
}

function getLogFinalDecision(row: FirewallLog): "APPROVED" | "BLOCKED" | "REVIEW" {
  return row.signals.final_decision === "REVIEW"
    ? "REVIEW"
    : row.signals.final_decision === "ALLOW"
      ? "APPROVED"
      : row.signals.final_decision === "BLOCK"
        ? "BLOCKED"
        : row.firewall_status;
}

function EmptyMetrics(): FirewallMetrics {
  return {
    total_inspected: 0,
    threats_neutralized: 0,
    average_risk: 0,
    memos_inspected: 0,
    health_coefficient: 1,
    timeline: [],
    category_totals: [],
  };
}

function App() {
  const [authSession, setAuthSession] = useState<Session | null>(null);
  const [privateAuditKey, setPrivateAuditKey] = useState<CryptoKey | null>(null);
  const [authInitializing, setAuthInitializing] = useState(true);
  const [accountProfileLoading, setAccountProfileLoading] = useState(false);
  const [authBusy, setAuthBusy] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [authNotice, setAuthNotice] = useState<string | null>(null);
  const [accountDisplayName, setAccountDisplayName] = useState("");
  const [simulatedBankAccount, setSimulatedBankAccount] = useState<SimulatedBankAccount | null>(null);
  const [simulatedDepositAmount, setSimulatedDepositAmount] = useState("1000.00");
  const [simulatedDepositBusy, setSimulatedDepositBusy] = useState(false);
  const [simulatedBankingNotice, setSimulatedBankingNotice] = useState<string | null>(null);
  const authenticatedAccountId = useRef<string | null>(null);
  const depositIdempotencyKey = useRef<{ amount: string; key: string } | null>(null);
  const transferIdempotencyKey = useRef<{ request: string; key: string } | null>(null);
  const [accountMenuOpen, setAccountMenuOpen] = useState(false);
  const accountMenuRef = useRef<HTMLDivElement>(null);
  const [activeView, setActiveView] = useState<ViewName>("overview");
  const [requestDraft, setRequestDraft] = useState<FirewallRequest>(initialRequest);
  const [decision, setDecision] = useState<FirewallDecision | null>(null);
  const [simulationReceipt, setSimulationReceipt] = useState<SimulationReceipt | null>(null);
  const [evaluationBusy, setEvaluationBusy] = useState(false);
  const [engineStep, setEngineStep] = useState(0);
  const [logs, setLogs] = useState<FirewallLog[]>([]);
  const [metrics, setMetrics] = useState<FirewallMetrics>(EmptyMetrics);
  const [selectedLog, setSelectedLog] = useState<FirewallLog | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [requestError, setRequestError] = useState<string | null>(null);
  const [persistenceState, setPersistenceState] = useState<"online" | "not-configured">("not-configured");
  const [copiedHash, setCopiedHash] = useState(false);

  useEffect(() => {
    if (!accountMenuOpen) return;

    function closeAccountMenuOnOutsideInteraction(event: PointerEvent) {
      if (event.target instanceof Node && !accountMenuRef.current?.contains(event.target)) {
        setAccountMenuOpen(false);
      }
    }

    function closeAccountMenuOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") setAccountMenuOpen(false);
    }

    document.addEventListener("pointerdown", closeAccountMenuOnOutsideInteraction);
    document.addEventListener("keydown", closeAccountMenuOnEscape);
    return () => {
      document.removeEventListener("pointerdown", closeAccountMenuOnOutsideInteraction);
      document.removeEventListener("keydown", closeAccountMenuOnEscape);
    };
  }, [accountMenuOpen]);

  useEffect(() => {
    if (!supabaseClient) {
      setAuthInitializing(false);
      return;
    }

    let stillMounted = true;
    const { data: authSubscription } = supabaseClient.auth.onAuthStateChange((_event, nextSession) => {
      if (!stillMounted) return;
      const nextAccountId = nextSession?.user.id ?? null;
      if (authenticatedAccountId.current !== nextAccountId) {
        clearUserAuditEncryptionKeyCache();
        authenticatedAccountId.current = nextAccountId;
        setAccountDisplayName("");
        setAccountProfileLoading(Boolean(nextSession));
        setPrivateAuditKey(null);
        setLogs([]);
        setMetrics(EmptyMetrics());
        setSimulatedBankAccount(null);
        setSimulatedBankingNotice(null);
        depositIdempotencyKey.current = null;
        transferIdempotencyKey.current = null;
        setSelectedLog(null);
        setRequestDraft(initialRequest);
        setDecision(null);
        setSimulationReceipt(null);
        setActiveView("overview");
        setSearchTerm("");
        setStatusFilter("ALL");
        setRequestError(null);
      }
      setAuthSession(nextSession);
      if (!nextSession) setAccountDisplayName("");
    });

    void supabaseClient.auth.getSession().then(({ data: sessionResult, error: sessionError }) => {
      if (!stillMounted) return;
      if (sessionError) {
        setAuthError(sessionError.message);
      } else {
        authenticatedAccountId.current = sessionResult.session?.user.id ?? null;
        setAccountDisplayName("");
        setAccountProfileLoading(Boolean(sessionResult.session));
        setAuthSession(sessionResult.session);
      }
      setAuthInitializing(false);
    }).catch((error: unknown) => {
      if (!stillMounted) return;
      setAuthError(error instanceof Error ? error.message : "Could not restore your private session.");
      setAuthInitializing(false);
    });

    return () => {
      stillMounted = false;
      authSubscription.subscription.unsubscribe();
    };
  }, []);

  useEffect(() => {
    const accountId = authSession?.user.id;
    const configuredSupabaseClient = supabaseClient;
    if (!configuredSupabaseClient || !accountId) {
      setAccountProfileLoading(false);
      return;
    }

    let isMounted = true;
    setAccountProfileLoading(true);
    const savedAccountProfile = configuredSupabaseClient
      .from("bank_users")
      .select("clear_name")
      .eq("uuid", accountId)
      .single();
    async function loadSavedAccountName() {
      try {
        const { data: accountProfile, error: profileReadError } = await savedAccountProfile;
        if (!isMounted) return;
        if (profileReadError || !accountProfile?.clear_name.trim()) {
          throw new Error(
            `Could not load your saved account name. Run the BankSim SQL setup in Supabase. ${profileReadError?.message ?? ""}`.trim(),
          );
        }
        setAccountDisplayName(accountProfile.clear_name);
        setAuthError(null);
      } catch (error) {
        if (!isMounted) return;
        setAuthError(error instanceof Error ? error.message : "Could not load your saved account name.");
      } finally {
        if (isMounted) setAccountProfileLoading(false);
      }
    }

    void loadSavedAccountName();

    return () => {
      isMounted = false;
    };
  }, [authSession?.user.id]);

  async function unlockPrivateAccountAudit(accountId: string, accountPassword: string) {
    if (!supabaseClient) throw new Error("Supabase configuration is missing.");
    const { data: accountProfile, error: profileReadError } = await supabaseClient
      .from("bank_users")
      .select("clear_name,encryption_salt,key_verification")
      .eq("uuid", accountId)
      .single();
    if (profileReadError || !accountProfile) {
      throw new Error(
        `Could not load your private account profile. Run the BankSim SQL setup in Supabase. ${profileReadError?.message ?? ""}`.trim(),
      );
    }

    const unlockedPrivateKey = await createUserAuditEncryptionKey(
      accountPassword,
      accountId,
      accountProfile.encryption_salt,
    );
    const verificationProof = "BankSim account-private audit key verification v1";
    if (accountProfile.key_verification) {
      const savedProof = await decryptPrivateAuditValue(
        unlockedPrivateKey,
        accountProfile.key_verification,
      );
      if (savedProof !== verificationProof) {
        throw new Error("That password does not unlock this account's private audit history.");
      }
    } else {
      const privateProofEnvelope = await encryptPrivateAuditValue(
        unlockedPrivateKey,
        verificationProof,
      );
      const { error: keySetupError } = await supabaseClient
        .from("bank_users")
        .update({ key_verification: JSON.stringify(privateProofEnvelope) })
        .eq("uuid", accountId);
      if (keySetupError) {
        throw new Error(`Could not secure your account encryption key: ${keySetupError.message}`);
      }
    }

    setAccountDisplayName(accountProfile.clear_name);
    setPrivateAuditKey(unlockedPrivateKey);
  }

  async function signInToPrivateWorkspace(email: string, password: string) {
    if (!supabaseClient) return;
    setAuthBusy(true);
    setAuthError(null);
    setAuthNotice(null);
    setPrivateAuditKey(null);
    try {
      const { data: signInResult, error: signInError } = await supabaseClient.auth.signInWithPassword({
        email,
        password,
      });
      if (signInError) throw signInError;
      await unlockPrivateAccountAudit(signInResult.user.id, password);
      setAuthSession(signInResult.session);
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Could not sign in to the private workspace.");
    } finally {
      setAuthBusy(false);
    }
  }

  async function registerPrivateWorkspace(name: string, email: string, password: string) {
    if (!supabaseClient) return;
    setAuthBusy(true);
    setAuthError(null);
    setAuthNotice(null);
    setPrivateAuditKey(null);
    try {
      const { data: registrationResult, error: registrationError } = await supabaseClient.auth.signUp({
        email,
        password,
        options: {
          data: { clear_name: name },
          emailRedirectTo: window.location.origin,
        },
      });
      if (registrationError) throw registrationError;
      if (registrationResult.session && registrationResult.user) {
        await unlockPrivateAccountAudit(registrationResult.user.id, password);
        setAuthSession(registrationResult.session);
      } else if (registrationResult.session) {
        throw new Error("Supabase returned a session without an account identity.");
      } else {
        setAuthNotice("Check your email to confirm the account, then sign in to unlock your private workspace.");
      }
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Could not create the private workspace.");
    } finally {
      setAuthBusy(false);
    }
  }

  async function unlockExistingPrivateWorkspace(password: string) {
    if (!authSession) return;
    setAuthBusy(true);
    setAuthError(null);
    setAuthNotice(null);
    try {
      await unlockPrivateAccountAudit(authSession.user.id, password);
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Could not unlock this private workspace.");
    } finally {
      setAuthBusy(false);
    }
  }

  async function signOutOfPrivateWorkspace() {
    if (!supabaseClient) return;
    setAuthBusy(true);
    setAuthError(null);
    try {
      const { error: signOutError } = await supabaseClient.auth.signOut();
      if (signOutError) throw signOutError;
      clearUserAuditEncryptionKeyCache();
      setPrivateAuditKey(null);
      setAuthSession(null);
      setAuthNotice("You have signed out. Your private audit encryption key was cleared from memory.");
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Could not safely end this session.");
    } finally {
      setAuthBusy(false);
    }
  }

  const refreshOperationsData = useCallback(async () => {
    const accessToken = authSession?.access_token;
    if (!accessToken || !privateAuditKey) return;
    const [encryptedLogs, fetchedMetrics, fetchedBankAccount] = await Promise.all([
      loadFirewallLogs(accessToken, 100),
      loadFirewallMetrics(accessToken),
      loadSimulatedBankAccount(accessToken),
    ]);
    const decryptedLogs = await Promise.all(
      encryptedLogs.map((encryptedLog) => decryptAuditLog(privateAuditKey, encryptedLog)),
    );
    setLogs(decryptedLogs);
    setMetrics(fetchedMetrics);
    setSimulatedBankAccount(await decryptSimulatedBankActivity(privateAuditKey, fetchedBankAccount));
  }, [authSession?.access_token, privateAuditKey]);

  useEffect(() => {
    if (!authSession || !privateAuditKey) return;
    let isMounted = true;
    const loadInitialConsoleState = async () => {
      try {
        const [encryptedLogs, fetchedMetrics, fetchedBankAccount, healthResponse] = await Promise.all([
          loadFirewallLogs(authSession.access_token, 100),
          loadFirewallMetrics(authSession.access_token),
          loadSimulatedBankAccount(authSession.access_token),
          fetch("/api/health").then((response) =>
            readBankSimApiJson<{ audit_persistence: string; status: string }>(
              response,
              "/api/health",
            ),
          ),
        ]);
        if (!isMounted) return;
        const decryptedLogs = await Promise.all(
          encryptedLogs.map((encryptedLog) => decryptAuditLog(privateAuditKey, encryptedLog)),
        );
        if (!isMounted) return;
        setLogs(decryptedLogs);
        setMetrics(fetchedMetrics);
        setSimulatedBankAccount(await decryptSimulatedBankActivity(privateAuditKey, fetchedBankAccount));
        setPersistenceState(healthResponse.audit_persistence === "supabase" ? "online" : "not-configured");
        setRequestError(null);
      } catch (error) {
        if (!isMounted) return;
        setRequestError(error instanceof Error ? error.message : "Unable to reach the firewall API.");
      }
    };
    void loadInitialConsoleState();
    const refreshTimer = window.setInterval(() => {
      void refreshOperationsData().catch((error: unknown) => {
        if (!isMounted) return;
        setRequestError(error instanceof Error ? error.message : "A live refresh failed.");
      });
    }, 8_000);
    return () => {
      isMounted = false;
      window.clearInterval(refreshTimer);
    };
  }, [authSession, privateAuditKey, refreshOperationsData]);

  const filteredLogs = useMemo(() => {
    const normalizedSearch = searchTerm.trim().toLowerCase();
    return logs.filter((row) => {
      const matchesStatus = statusFilter === "ALL" || getLogFinalDecision(row) === statusFilter;
      const matchesText =
        normalizedSearch.length === 0 ||
        `${row.incoming_prompt} ${row.threat_category} ${row.target_tool}`
          .toLowerCase()
          .includes(normalizedSearch);
      return matchesStatus && matchesText;
    });
  }, [logs, searchTerm, statusFilter]);

  async function submitEvaluation() {
    if (!authSession || !privateAuditKey) {
      setRequestError("Unlock your private workspace before inspecting a request.");
      return;
    }
    setEvaluationBusy(true);
    setDecision(null);
    setSimulationReceipt(null);
    setRequestError(null);
    setEngineStep(1);
    try {
      const requestBeingInspected = { ...requestDraft };
      const requestFingerprint = JSON.stringify({
        ...requestBeingInspected,
        amount: requestBeingInspected.amount
          ? Number(requestBeingInspected.amount).toFixed(2)
          : undefined,
        target_identifier: requestBeingInspected.target_identifier?.trim().toUpperCase(),
      });
      const encryptedInspectionRecord = await encryptAuditRequest(privateAuditKey, requestBeingInspected);
      const firewallVerdict = await evaluateFirewallRequest(
        requestBeingInspected,
        authSession.access_token,
        encryptedInspectionRecord,
      );
      setDecision(firewallVerdict);
      setEngineStep(2);
      if (firewallVerdict.status === "APPROVED") {
        setEngineStep(3);
        const encryptedRoutingRecord = await encryptAuditRequest(privateAuditKey, requestBeingInspected);
        const transferRequestKey =
          transferIdempotencyKey.current?.request === requestFingerprint
            ? transferIdempotencyKey.current.key
            : crypto.randomUUID();
        if (requestBeingInspected.target_tool === "TRANSFER_SIMULATION") {
          transferIdempotencyKey.current = { request: requestFingerprint, key: transferRequestKey };
        }
        const safeMockReceipt = await simulateSafeTransaction(
          requestBeingInspected,
          authSession.access_token,
          encryptedRoutingRecord,
          transferRequestKey,
        );
        setSimulationReceipt(safeMockReceipt);
        setEngineStep(4);
      }
      await refreshOperationsData();
      if (requestBeingInspected.target_tool === "TRANSFER_SIMULATION") {
        transferIdempotencyKey.current = null;
      }
    } catch (error) {
      setRequestError(error instanceof Error ? error.message : "Firewall processing failed.");
      setEngineStep(0);
    } finally {
      setEvaluationBusy(false);
    }
  }

  async function submitSimulatedDeposit() {
    if (!authSession || !privateAuditKey || !simulatedBankAccount) {
      setRequestError("Your private simulated account is not ready yet.");
      return;
    }
    setSimulatedDepositBusy(true);
    setRequestError(null);
    setSimulatedBankingNotice(null);
    try {
      const depositFingerprint = Number.isFinite(Number(simulatedDepositAmount))
        ? Number(simulatedDepositAmount).toFixed(2)
        : simulatedDepositAmount;
      const depositKey =
        depositIdempotencyKey.current?.amount === depositFingerprint
          ? depositIdempotencyKey.current.key
          : crypto.randomUUID();
      depositIdempotencyKey.current = { amount: depositFingerprint, key: depositKey };
      const depositReceipt = await depositSimulatedFunds(
        simulatedDepositAmount,
        authSession.access_token,
        depositKey,
      );
      const decryptedAccount = await decryptSimulatedBankActivity(
        privateAuditKey,
        depositReceipt.account,
      );
      setSimulatedBankAccount(decryptedAccount);
      depositIdempotencyKey.current = null;
      setSimulatedBankingNotice(depositReceipt.result);
    } catch (error) {
      setRequestError(error instanceof Error ? error.message : "Simulated deposit could not be posted.");
    } finally {
      setSimulatedDepositBusy(false);
    }
  }

  function applyExamplePayload(selectedPayload: (typeof examplePayloads)[number]) {
    setRequestDraft(selectedPayload.request);
    setDecision(null);
    setSimulationReceipt(null);
    setEngineStep(0);
    setRequestError(null);
  }

  function navigateTo(view: ViewName) {
    setActiveView(view);
    setSelectedLog(null);
  }

  const pageTitle =
    activeView === "sandbox"
      ? "Live sandbox"
      : activeView === "ledger"
        ? "Security ledger"
        : "Command center";
  const authenticationScreenLoading =
    authInitializing || (Boolean(authSession) && accountProfileLoading && !accountDisplayName);

  if (authenticationScreenLoading || (authSession && !privateAuditKey)) {
    return (
      <AuthenticationScreen
        supabaseConfigured={supabaseConfigurationReady}
        loading={authenticationScreenLoading}
        session={authSession}
        accountName={accountDisplayName}
        busy={authBusy}
        error={authError}
        notice={authNotice}
        onSignIn={signInToPrivateWorkspace}
        onSignUp={registerPrivateWorkspace}
        onUnlock={unlockExistingPrivateWorkspace}
        onSignOut={signOutOfPrivateWorkspace}
        onClearMessage={() => { setAuthError(null); setAuthNotice(null); }}
      />
    );
  }

  if (!authSession || !privateAuditKey) {
    return (
      <AuthenticationScreen
        supabaseConfigured={supabaseConfigurationReady}
        loading={authenticationScreenLoading}
        session={authSession}
        accountName={accountDisplayName}
        busy={authBusy}
        error={authError}
        notice={authNotice}
        onSignIn={signInToPrivateWorkspace}
        onSignUp={registerPrivateWorkspace}
        onUnlock={unlockExistingPrivateWorkspace}
        onSignOut={signOutOfPrivateWorkspace}
        onClearMessage={() => { setAuthError(null); setAuthNotice(null); }}
      />
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-mark">
            <Shield size={18} strokeWidth={1.8} />
            <span />
          </div>
          <div>
            <div className="brand-name">BANK<span>SIM</span></div>
            <div className="brand-subtitle">BLUE-TEAM FIREWALL</div>
          </div>
        </div>

        <div className="workspace-label">WORKSPACE <ChevronDown size={12} /></div>
        <div className="workspace-switcher">
          <div className="workspace-icon"><Banknote size={15} /></div>
          <div className="workspace-copy">
            <strong>Northstar Bank</strong>
            <span>Security operations</span>
          </div>
          <ChevronDown className="workspace-chevron" size={14} />
        </div>

        <div className="nav-caption">OPERATIONS</div>
        <nav className="primary-nav" aria-label="Primary navigation">
          {navigationItems.map((item) => {
            const NavigationIcon = item.icon;
            return (
              <button
                className={`nav-link ${activeView === item.id ? "active" : ""}`}
                key={item.id}
                onClick={() => navigateTo(item.id)}
              >
                <NavigationIcon size={16} />
                <span>{item.label}</span>
                {item.id === "ledger" && metrics.threats_neutralized > 0 && (
                  <span className="nav-count">{metrics.threats_neutralized}</span>
                )}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-divider" />
        <div className="nav-caption">SYSTEM</div>
        <div className="system-status">
          <span className="live-indicator" />
          <span>Firewall operational</span>
          <span className="status-latency">READY</span>
        </div>
        <div className="system-status subtle">
          <span className={`db-indicator ${persistenceState}`} />
          <span>Private encrypted audit</span>
          <span className="status-mode">{persistenceState === "online" ? "LIVE" : "LOCKED"}</span>
        </div>

        <div className="sidebar-footer">
          <div className="operator-avatar">{(accountDisplayName || "B").slice(0, 1).toUpperCase()}</div>
          <div className="operator-copy"><strong>{accountDisplayName || "BankSim user"}</strong><span>Private workspace</span></div>
          <SlidersHorizontal size={15} className="operator-settings" />
        </div>
      </aside>

      <main className="main-column">
        <header className="topbar">
          <div className="topbar-heading">
            <span className="breadcrumb-root">Operations</span>
            <ChevronRight size={13} />
            <span>{pageTitle}</span>
          </div>
          <div className="topbar-actions">
            <span className="environment-chip"><span /> SIMULATION ENV</span>
            <button className="icon-button" aria-label="Search ledger" onClick={() => navigateTo("ledger")}><Search size={17} /></button>
            <button className="icon-button notification-button" aria-label="Threat notifications" onClick={() => navigateTo("ledger")}>
              <Bell size={17} />
              {metrics.threats_neutralized > 0 && <span />}
            </button>
            <div className="topbar-separator" />
            <div className="topbar-account" ref={accountMenuRef}>
              <div className="topbar-user">
                <div className="operator-avatar small">{(accountDisplayName || "B").slice(0, 1).toUpperCase()}</div>
                <span>{accountDisplayName.split(" ")[0] || "Account"}</span>
              </div>
              <button
                className="topbar-account-toggle"
                type="button"
                aria-label="Open account menu"
                aria-haspopup="menu"
                aria-expanded={accountMenuOpen}
                aria-controls="account-menu"
                onClick={() => setAccountMenuOpen((menuOpen) => !menuOpen)}
              >
                <ChevronDown size={13} />
              </button>
              {accountMenuOpen && (
                <div className="account-menu" id="account-menu" role="menu">
                  <button
                    className="account-menu-item"
                    type="button"
                    role="menuitem"
                    disabled={authBusy}
                    onClick={() => {
                      setAccountMenuOpen(false);
                      void signOutOfPrivateWorkspace();
                    }}
                  >
                    <LogOut size={14} />
                    <span>{authBusy ? "Signing out…" : "Sign out"}</span>
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        <div className="page-content">
          {requestError && (
            <div className="global-error"><CircleAlert size={15} /><span>{requestError}</span><button aria-label="Dismiss error" onClick={() => setRequestError(null)}><X size={14} /></button></div>
          )}
          {activeView === "overview" && (
            <OverviewView
              metrics={metrics}
              logs={logs}
              onOpenSandbox={() => navigateTo("sandbox")}
              onOpenLedger={() => navigateTo("ledger")}
              onSelectLog={(row) => {
                setSelectedLog(row);
                setActiveView("ledger");
              }}
            />
          )}
          {activeView === "sandbox" && (
            <LiveSandbox
              account={simulatedBankAccount}
              depositAmount={simulatedDepositAmount}
              setDepositAmount={setSimulatedDepositAmount}
              depositBusy={simulatedDepositBusy}
              bankingNotice={simulatedBankingNotice}
              onDeposit={() => void submitSimulatedDeposit()}
              requestDraft={requestDraft}
              setRequestDraft={setRequestDraft}
              decision={decision}
              simulationReceipt={simulationReceipt}
              engineStep={engineStep}
              busy={evaluationBusy}
              onSubmit={() => void submitEvaluation()}
              onApplyExample={applyExamplePayload}
            />
          )}
          {activeView === "ledger" && (
            <LedgerView
              logs={filteredLogs}
              allCount={logs.length}
              selectedLog={selectedLog}
              searchTerm={searchTerm}
              statusFilter={statusFilter}
              copiedHash={copiedHash}
              onSearch={setSearchTerm}
              onFilter={setStatusFilter}
              onSelect={setSelectedLog}
              onClose={() => setSelectedLog(null)}
              onCopyHash={async (hash) => {
                await navigator.clipboard.writeText(hash);
                setCopiedHash(true);
                window.setTimeout(() => setCopiedHash(false), 1400);
              }}
            />
          )}
        </div>
        <footer className="app-footer">
          <span><LockKeyhole size={12} /> DEFENSIVE SIMULATION ONLY</span>
          <span>POLICY ENGINE <strong>v1.0.4</strong></span>
          <span className="footer-right"><span className="live-indicator" /> ALL SYSTEMS NOMINAL <span className="footer-divider">/</span> UTC {new Date().toLocaleTimeString("en-US", { hour12: false, timeZone: "UTC" })}</span>
        </footer>
      </main>
    </div>
  );
}

function PageHeading({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow: string;
  title: string;
  description: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <div className="eyebrow"><span />{eyebrow}</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action && <div className="page-heading-action">{action}</div>}
    </div>
  );
}

function OverviewView({
  metrics,
  logs,
  onOpenSandbox,
  onOpenLedger,
  onSelectLog,
}: {
  metrics: FirewallMetrics;
  logs: FirewallLog[];
  onOpenSandbox: () => void;
  onOpenLedger: () => void;
  onSelectLog: (row: FirewallLog) => void;
}) {
  const recentThreats = logs.filter((row) => getLogFinalDecision(row) !== "APPROVED").slice(0, 4);
  const categoryTotals = Array.isArray(metrics.category_totals) ? metrics.category_totals : [];
  const metricCards = [
    {
      label: "THREATS NEUTRALIZED",
      value: metrics.threats_neutralized.toLocaleString("en-US"),
      detail: "isolated before tool routing",
      icon: ShieldAlert,
      tone: "red",
      micro: <ThreatSparkline />,
    },
    {
      label: "CORE RISK INDEX",
      value: metrics.average_risk.toFixed(2),
      detail: "mean score · 0.00—1.00",
      icon: Activity,
      tone: "amber",
      micro: <RiskRing risk={metrics.average_risk} />,
    },
    {
      label: "MEMOS INSPECTED",
      value: metrics.memos_inspected.toLocaleString("en-US"),
      detail: "free-text fields analyzed",
      icon: ScanSearch,
      tone: "blue",
      micro: <MemoGlyph />,
    },
    {
      label: "SYSTEM HEALTH",
      value: `${(metrics.health_coefficient * 100).toFixed(1)}%`,
      detail: "auditable request integrity",
      icon: Zap,
      tone: "green",
      micro: <HealthGlyph />,
    },
  ];

  return (
    <>
      <PageHeading
        eyebrow="THREAT POSTURE / LIVE"
        title="Command center"
        description="Defensive telemetry across every intercepted banking interaction."
        action={<button className="primary-button" onClick={onOpenSandbox}><Sparkles size={15} /> Open live sandbox <ArrowUpRight size={14} /></button>}
      />

      <section className="metric-grid" aria-label="Firewall executive metrics">
        {metricCards.map((metric) => {
          const MetricIcon = metric.icon;
          return (
            <article className={`metric-card metric-${metric.tone}`} key={metric.label}>
              <div className="metric-card-top">
                <span>{metric.label}</span>
                <MetricIcon size={15} />
              </div>
              <div className="metric-card-main">
                <div className="metric-value">{metric.value}</div>
                <div className="metric-micro">{metric.micro}</div>
              </div>
              <div className="metric-card-bottom"><span className="metric-dot" />{metric.detail}</div>
              <div className="metric-edge" />
            </article>
          );
        })}
      </section>

      <section className="dashboard-grid">
        <article className="panel chart-panel">
          <div className="panel-heading">
            <div><div className="panel-kicker">TRAFFIC ANALYSIS</div><h2>Attack distribution</h2></div>
            <div className="chart-heading-right"><span className="live-caption"><span className="live-indicator" /> LIVE</span><span className="period-label" aria-label="Chart range: last 24 hours">Last 24 hours</span></div>
          </div>
          <div className="chart-stat-line"><strong>{metrics.total_inspected}</strong><span>inspected requests</span><span className="chart-separator" /><span className="chart-legend approved-legend"><i /> ALLOW</span><span className="chart-legend review-legend"><i /> REVIEW</span><span className="chart-legend blocked-legend"><i /> BLOCK</span></div>
          <FirewallTimeline timeline={metrics.timeline} />
          <div className="chart-axis-labels"><span>24H AGO</span><span>18H</span><span>12H</span><span>06H</span><span>NOW</span></div>
        </article>

        <article className="panel threat-panel">
          <div className="panel-heading">
            <div><div className="panel-kicker">LIVE DETECTIONS</div><h2>Threat breakdown</h2></div>
            <button className="ghost-icon-button" aria-label="Open all threat logs" onClick={onOpenLedger}><ArrowUpRight size={15} /></button>
          </div>
          <div className="threat-breakdown">
            {categoryTotals
              .filter((item) => item.category !== "NONE")
              .sort((first, second) => second.count - first.count)
              .map((item, index) => {
                const maximumCount = Math.max(1, ...categoryTotals.map((itemCount) => itemCount.count));
                return (
                  <div className="threat-break-row" key={item.category}>
                    <div className={`threat-index threat-index-${index + 1}`}>{String(index + 1).padStart(2, "0")}</div>
                    <div className="threat-break-copy">
                      <div><strong>{item.category.replaceAll("_", " ")}</strong><span>{item.count}</span></div>
                      <div className="bar-track"><span style={{ width: `${Math.max(item.count > 0 ? 8 : 0, (item.count / maximumCount) * 100)}%` }} /></div>
                    </div>
                  </div>
                );
              })}
            {categoryTotals.filter((item) => item.category !== "NONE").every((item) => item.count === 0) && (
              <div className="empty-threat-state"><ShieldCheck size={20} /><span>No threat signatures in this window.</span><small>Test a payload in the live sandbox to populate detections.</small></div>
            )}
          </div>
          <button className="panel-text-link" onClick={onOpenLedger}>View security ledger <ArrowUpRight size={13} /></button>
        </article>
      </section>

      <section className="panel activity-panel">
        <div className="panel-heading activity-heading">
          <div><div className="panel-kicker">AUDIT STREAM</div><h2>Recent interceptions</h2></div>
          <button className="subtle-button" onClick={onOpenLedger}>View full ledger <ArrowUpRight size={13} /></button>
        </div>
        {recentThreats.length === 0 ? (
          <div className="empty-activity"><div className="empty-activity-icon"><ShieldCheck size={17} /></div><span>Quiet perimeter. No blocked or review decisions in the current audit window.</span><button onClick={onOpenSandbox}>Run a security test <ChevronRight size={13} /></button></div>
        ) : (
          <div className="recent-threat-list">
            {recentThreats.map((row) => (
              <button className="recent-threat-row" key={row.log_id} onClick={() => onSelectLog(row)}>
                <span className={`recent-threat-icon ${getLogFinalDecision(row) === "REVIEW" ? "review" : ""}`}><Bug size={14} /></span>
                <span className="recent-threat-category">{row.threat_category.replaceAll("_", " ")}</span>
                <span className="recent-threat-prompt">{row.incoming_prompt}</span>
                <VerdictBadge status={getLogFinalDecision(row)} />
                <RiskPill score={row.risk_score} />
                <span className="recent-threat-time">{displayClock(row.timestamp)}</span>
                <ChevronRight size={14} />
              </button>
            ))}
          </div>
        )}
      </section>
    </>
  );
}

function ThreatSparkline() {
  return <svg className="sparkline red-sparkline" viewBox="0 0 72 36" aria-hidden="true"><path d="M1 28 L10 26 L18 29 L27 17 L35 22 L44 11 L52 17 L62 7 L71 10" /><path className="spark-fill" d="M1 28 L10 26 L18 29 L27 17 L35 22 L44 11 L52 17 L62 7 L71 10 L71 36 L1 36 Z" /></svg>;
}

function RiskRing({ risk }: { risk: number }) {
  const ringColor = risk >= 0.44 ? "#ef4444" : "#f59e0b";
  return <div className="risk-ring" style={{ background: `conic-gradient(${ringColor} ${risk * 360}deg, #202735 0deg)` }}><span /></div>;
}

function MemoGlyph() {
  return <div className="memo-glyph"><span /><span /><span /><span /><i /></div>;
}

function HealthGlyph() {
  return <svg className="health-glyph" viewBox="0 0 55 34" aria-hidden="true"><path d="M1 19h11l5-11 9 20 8-16 5 7h15" /><circle cx="39" cy="19" r="2.5" /></svg>;
}

function FirewallTimeline({
  timeline,
}: {
  timeline: Array<{ label: string; approved: number; blocked: number; review: number }>;
}) {
  const validTimeline = Array.isArray(timeline) ? timeline : [];
  const chartWidth = 640;
  const chartHeight = 152;
  const pointCount = Math.max(validTimeline.length, 2);
  const chartMaximum = Math.max(2, ...validTimeline.map((row) => row.approved + row.blocked + (row.review ?? 0)));
  const approvedPoints = validTimeline.map((row, index) => ({
    x: (index / (pointCount - 1)) * chartWidth,
    y: chartHeight - (row.approved / chartMaximum) * (chartHeight - 16) - 6,
  }));
  const blockedPoints = validTimeline.map((row, index) => ({
    x: (index / (pointCount - 1)) * chartWidth,
    y: chartHeight - (row.blocked / chartMaximum) * (chartHeight - 16) - 6,
  }));
  const reviewPoints = validTimeline.map((row, index) => ({
    x: (index / (pointCount - 1)) * chartWidth,
    y: chartHeight - ((row.review ?? 0) / chartMaximum) * (chartHeight - 16) - 6,
  }));
  const pathFor = (points: Array<{ x: number; y: number }>) =>
    points.map((point, index) => `${index === 0 ? "M" : "L"} ${point.x} ${point.y}`).join(" ");
  const areaPath = approvedPoints.length
    ? `${pathFor(approvedPoints)} L ${chartWidth} ${chartHeight} L 0 ${chartHeight} Z`
    : "";

  return (
    <div className="timeline-chart">
      <div className="chart-y-labels"><span>{chartMaximum}</span><span>{Math.ceil(chartMaximum / 2)}</span><span>0</span></div>
      <svg viewBox={`0 0 ${chartWidth} ${chartHeight}`} preserveAspectRatio="none" role="img" aria-label="Allowed, review, and blocked request counts by hour">
        <defs><linearGradient id="approvedArea" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stopColor="#10b981" stopOpacity=".18" /><stop offset="1" stopColor="#10b981" stopOpacity="0" /></linearGradient></defs>
        {[0.14, 0.5, 0.86].map((lineY) => <line key={lineY} x1="0" x2={chartWidth} y1={chartHeight * lineY} y2={chartHeight * lineY} className="chart-grid-line" />)}
        {approvedPoints.length > 0 && <path d={areaPath} fill="url(#approvedArea)" />}
        {approvedPoints.length > 1 && <path d={pathFor(approvedPoints)} className="approved-line" />}
        {reviewPoints.length > 1 && <path d={pathFor(reviewPoints)} className="review-line" />}
        {blockedPoints.length > 1 && <path d={pathFor(blockedPoints)} className="blocked-line" />}
        {approvedPoints.map((point, index) => validTimeline[index]?.approved ? <circle key={`a${index}`} cx={point.x} cy={point.y} r="2.5" className="approved-point" /> : null)}
        {reviewPoints.map((point, index) => validTimeline[index]?.review ? <circle key={`r${index}`} cx={point.x} cy={point.y} r="2.5" className="review-point" /> : null)}
        {blockedPoints.map((point, index) => validTimeline[index]?.blocked ? <circle key={`b${index}`} cx={point.x} cy={point.y} r="2.5" className="blocked-point" /> : null)}
      </svg>
      {validTimeline.length === 0 && <div className="chart-empty-label">Awaiting the first inspected request</div>}
      <div className="chart-live-marker"><span /></div>
    </div>
  );
}

function LedgerView({
  logs,
  allCount,
  selectedLog,
  searchTerm,
  statusFilter,
  copiedHash,
  onSearch,
  onFilter,
  onSelect,
  onClose,
  onCopyHash,
}: {
  logs: FirewallLog[];
  allCount: number;
  selectedLog: FirewallLog | null;
  searchTerm: string;
  statusFilter: string;
  copiedHash: boolean;
  onSearch: (value: string) => void;
  onFilter: (value: string) => void;
  onSelect: (row: FirewallLog) => void;
  onClose: () => void;
  onCopyHash: (hash: string) => Promise<void>;
}) {
  return (
    <>
      <PageHeading
        eyebrow="APPEND-ONLY / AUDIT TRAIL"
        title="Security ledger"
        description="Inspect request verdicts, boundary telemetry, and approval integrity hashes."
        action={<span className="ledger-count"><span className="live-indicator" />{allCount} RECORDS IN WINDOW</span>}
      />
      <section className="panel ledger-panel">
        <div className="ledger-toolbar">
          <div className="ledger-toolbar-title"><div className="ledger-lock-icon"><LockKeyhole size={15} /></div><div><strong>Firewall audit events</strong><span>ORDERED BY CAPTURE TIME · NEWEST FIRST</span></div></div>
          <div className="ledger-controls">
            <label className="ledger-search"><Search size={14} /><input value={searchTerm} onChange={(event) => onSearch(event.target.value)} placeholder="Search prompts, tools…" /></label>
            <label className="filter-select-wrap"><SlidersHorizontal size={13} /><select value={statusFilter} onChange={(event) => onFilter(event.target.value)}><option value="ALL">All verdicts</option><option value="BLOCKED">Blocked</option><option value="REVIEW">Review</option><option value="APPROVED">Approved</option></select><ChevronDown size={12} /></label>
          </div>
        </div>
        <div className="ledger-table-wrap">
          <table className="ledger-table">
            <thead><tr><th>EVENT / TIME</th><th>TOOL ROUTE</th><th>INPUT SNAPSHOT</th><th>VERDICT</th><th>RISK</th><th>LATENCY</th><th /></tr></thead>
            <tbody>
              {logs.map((row) => (
                <tr className={selectedLog?.log_id === row.log_id ? "selected" : ""} key={row.log_id} onClick={() => onSelect(row)} tabIndex={0} onKeyDown={(event) => { if (event.key === "Enter") onSelect(row); }}>
                  <td><span className="event-time">{displayClock(row.timestamp)}</span><span className="event-date">{new Date(row.timestamp).toLocaleDateString("en-US", { month: "short", day: "2-digit" })}</span></td>
                  <td><span className="tool-pill">{row.target_tool.replaceAll("_", " ")}</span></td>
                  <td><span className="input-snapshot" title={row.incoming_prompt}>{row.incoming_prompt}</span><span className={`category-label ${getLogFinalDecision(row) !== "APPROVED" ? "danger" : ""}`}>{row.threat_category.replaceAll("_", " ")}</span></td>
                  <td><VerdictBadge status={getLogFinalDecision(row)} /></td>
                  <td><RiskPill score={row.risk_score} /></td>
                  <td><span className="latency-value">{row.latency_ms}<small>ms</small></span></td>
                  <td><ChevronRight size={14} className="row-chevron" /></td>
                </tr>
              ))}
              {logs.length === 0 && <tr><td colSpan={7}><div className="ledger-empty"><div><Command size={18} /></div><strong>No events match this view.</strong><span>Run an inspection from the live sandbox to add an audit entry.</span></div></td></tr>}
            </tbody>
          </table>
        </div>
        <div className="ledger-table-footer"><span>SHOWING <strong>{logs.length}</strong> OF <strong>{allCount}</strong> EVENTS</span><span><LockKeyhole size={11} /> LEDGER IS READ-ONLY</span><div><button aria-label="Previous page" disabled><ChevronLeft size={14} /></button><span>1</span><button aria-label="Next page" disabled><ChevronRight size={14} /></button></div></div>
      </section>
      {selectedLog && (
        <div className="inspection-backdrop" onClick={onClose}>
          <aside className="inspection-drawer" onClick={(event) => event.stopPropagation()}>
            <div className="drawer-heading"><div><span className="panel-kicker">EVENT INSPECTOR / DETAIL</span><h2>Audit inspection</h2></div><button className="icon-button" onClick={onClose} aria-label="Close inspection"><X size={17} /></button></div>
            <div className="drawer-verdict-row"><VerdictBadge status={getLogFinalDecision(selectedLog)} /><RiskPill score={selectedLog.risk_score} /><span>{displayClock(selectedLog.timestamp)}</span></div>
            <div className="drawer-section"><div className="drawer-section-heading"><span>RAW REQUEST SNAPSHOT</span><span className="read-only-tag">READ ONLY</span></div><pre className="raw-prompt">{selectedLog.incoming_prompt}</pre></div>
            <div className="drawer-section"><div className="drawer-section-heading"><span>VERDICT ANALYSIS</span><span>{selectedLog.target_tool.replaceAll("_", " ")}</span></div><div className="analysis-category"><ShieldAlert size={15} /><strong>{selectedLog.threat_category.replaceAll("_", " ")}</strong></div><p className="drawer-explanation">{selectedLog.engine_explanation}</p></div>
            <div className="drawer-section"><div className="drawer-section-heading"><span>STRUCTURAL SIGNALS</span><span>ENGINE TELEMETRY</span></div>
              {selectedLog.signals ? (
                <div className="signal-grid">
                  {Object.entries(selectedLog.signals).map(([signalName, signalValue]) => (
                    <div className="signal-cell" key={signalName}><span>{signalName.replaceAll("_", " ")}</span><strong>{signalName.endsWith("density") || signalName.endsWith("entropy") ? Number(signalValue).toFixed(4) : signalValue}</strong></div>
                  ))}
                </div>
              ) : <div className="signals-unavailable"><CircleAlert size={14} /> Feature signal detail was not recorded for this event.</div>}
            </div>
            <div className="drawer-section"><div className="drawer-section-heading"><span>COMPLIANCE INTEGRITY</span><Fingerprint size={14} /></div><div className="hash-block"><span>SHA-256 REQUEST BINDING</span><code>{selectedLog.compliance_hash}</code><button onClick={() => void onCopyHash(selectedLog.compliance_hash)}><Copy size={12} />{copiedHash ? "COPIED" : "COPY HASH"}</button></div></div>
            <div className="drawer-footer"><span><LockKeyhole size={12} /> IMMUTABLE AUDIT RECORD</span><span>{selectedLog.latency_ms} ms</span></div>
          </aside>
        </div>
      )}
    </>
  );
}

export default App;
