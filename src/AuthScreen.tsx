import { useState, type FormEvent } from "react";
import {
  ArrowRight,
  ArrowUpRight,
  BadgeCheck,
  Eye,
  EyeOff,
  Fingerprint,
  KeyRound,
  LockKeyhole,
  Mail,
  Shield,
  ShieldCheck,
  Sparkles,
  UserRound,
  UserRoundPlus,
} from "lucide-react";
import type { Session } from "@supabase/supabase-js";

interface AuthenticationScreenProps {
  supabaseConfigured: boolean;
  loading: boolean;
  session: Session | null;
  accountName: string;
  busy: boolean;
  error: string | null;
  notice: string | null;
  onSignIn: (email: string, password: string) => Promise<void>;
  onSignUp: (name: string, email: string, password: string) => Promise<void>;
  onUnlock: (password: string) => Promise<void>;
  onSignOut: () => Promise<void>;
  onClearMessage: () => void;
}

export function AuthenticationScreen({
  supabaseConfigured,
  loading,
  session,
  accountName,
  busy,
  error,
  notice,
  onSignIn,
  onSignUp,
  onUnlock,
  onSignOut,
  onClearMessage,
}: AuthenticationScreenProps) {
  const [isRegistrationView, setIsRegistrationView] = useState(false);
  const [fullName, setFullName] = useState("");
  const [emailAddress, setEmailAddress] = useState("");
  const [accountPassword, setAccountPassword] = useState("");
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [formValidationMessage, setFormValidationMessage] = useState<string | null>(null);
  const isUnlockView = session !== null;

  async function submitAuthenticationForm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormValidationMessage(null);
    onClearMessage();
    if (!supabaseConfigured || isUnlockView || loading) return;
    if (isRegistrationView) {
      const normalizedName = fullName.trim();
      if (normalizedName.length < 2) {
        setFormValidationMessage("Enter the name you want to see on your private workspace.");
        return;
      }
      if (accountPassword.length < 12) {
        setFormValidationMessage("Use at least 12 characters for your account and encryption password.");
        return;
      }
      await onSignUp(normalizedName, emailAddress.trim(), accountPassword);
      return;
    }
    if (accountPassword.length === 0) {
      setFormValidationMessage("Enter your password to sign in and unlock your encrypted audit history.");
      return;
    }
    await onSignIn(emailAddress.trim(), accountPassword);
  }

  async function submitUnlockForm(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormValidationMessage(null);
    onClearMessage();
    if (!isUnlockView) return;
    if (accountPassword.length === 0) {
      setFormValidationMessage("Enter the password used for this account's audit encryption key.");
      return;
    }
    await onUnlock(accountPassword);
  }

  if (loading) {
    return (
      <main className="auth-loading">
        <span className="auth-loader-mark"><Shield size={22} /></span>
        <strong>Securing your workspace</strong>
        <span>Restoring your encrypted BankSim session</span>
      </main>
    );
  }

  return (
    <main className="auth-page">
      <section className="auth-story">
        <div className="auth-story-inner">
          <a className="auth-brand" href="/" aria-label="BankSim home">
            <span className="auth-brand-mark"><ShieldCheck size={20} /><i /></span>
            <span>BANKSIM<span className="auth-brand-blue"> / DEFENSE</span></span>
          </a>
          <div className="auth-story-body">
            <div className="auth-story-eyebrow"><span className="auth-orbit-dot" /> PRIVATE BY DESIGN <span>·</span> V1.0</div>
            <h1>Trust your<br />transactions to<br /><em>no one.</em></h1>
            <p>A personal blue-team command desk. Every memo inspected. Every audit record encrypted to your account.</p>
            <div className="auth-art" aria-hidden="true">
              <div className="auth-art-grid" />
              <div className="auth-art-orbit auth-art-orbit-outer" />
              <div className="auth-art-orbit auth-art-orbit-middle" />
              <div className="auth-art-orbit auth-art-orbit-inner" />
              <div className="auth-art-core"><ShieldCheck size={30} strokeWidth={1.4} /></div>
              <div className="auth-art-node node-top"><Fingerprint size={14} /><span>PRIVATE KEY</span></div>
              <div className="auth-art-node node-left"><LockKeyhole size={14} /><span>ENCRYPTED</span></div>
              <div className="auth-art-node node-right"><BadgeCheck size={14} /><span>VERIFIED</span></div>
              <span className="auth-art-coordinate coordinate-one">51°30'26.4"N</span>
              <span className="auth-art-coordinate coordinate-two">AES / 256</span>
            </div>
            <div className="auth-story-foot"><span><i /> PRIVATE WORKSPACE</span><span>YOUR DATA. YOUR KEY.</span></div>
          </div>
          <div className="auth-story-footer"><span>© BANKSIM SECURITY STUDIO</span><span>BUILT FOR DEFENDERS</span></div>
        </div>
      </section>

      <section className="auth-main">
        <div className="auth-topline"><span>SECURE ACCESS</span><span><i /> TLS PROTECTED</span></div>
        <div className="auth-form-wrap">
          <div className="auth-form-emblem">{isUnlockView ? <KeyRound size={19} /> : isRegistrationView ? <UserRoundPlus size={19} /> : <Sparkles size={19} />}</div>
          {isUnlockView ? (
            <>
              <div className="auth-form-eyebrow">YOUR PRIVATE WORKSPACE</div>
              <h2>Welcome back{accountName ? `, ${accountName.split(" ")[0]}` : ""}.</h2>
              <p className="auth-form-intro">Your session is secure. Unlock your account key to decrypt your personal security history.</p>
              <div className="auth-account-chip"><span className="auth-account-avatar">{(accountName || "B").slice(0, 1).toUpperCase()}</span><span><strong>{accountName || "Your BankSim account"}</strong><small>Private workspace · password required</small></span><BadgeCheck size={15} /></div>
              <form className="auth-form" onSubmit={(event) => void submitUnlockForm(event)}>
                <label className="auth-label" htmlFor="banksim-unlock-password">ACCOUNT PASSWORD</label>
                <div className="auth-input-wrap"><KeyRound size={15} /><input id="banksim-unlock-password" type={passwordVisible ? "text" : "password"} autoComplete="current-password" value={accountPassword} onChange={(event) => setAccountPassword(event.target.value)} placeholder="Enter your account password" autoFocus /><button type="button" onClick={() => setPasswordVisible((currentValue) => !currentValue)} aria-label={passwordVisible ? "Hide password" : "Show password"}>{passwordVisible ? <EyeOff size={15} /> : <Eye size={15} />}</button></div>
                <div className="auth-key-note"><LockKeyhole size={13} /><span>Password derives your private AES-256 key in this browser. It is <strong>never stored</strong> by BankSim.</span></div>
                {(formValidationMessage || error || notice) && <div className={`auth-feedback ${error ? "feedback-error" : notice ? "feedback-success" : ""}`}>{error ?? formValidationMessage ?? notice}</div>}
                <button className="auth-submit" disabled={busy || !supabaseConfigured} type="submit">{busy ? <span className="auth-button-spinner" /> : <>Unlock my workspace <ArrowRight size={15} /></>}{busy && "Unlocking private data…"}</button>
              </form>
              <button className="auth-secondary-link" onClick={() => void onSignOut()}>Not you? Sign out of this device <ArrowUpRight size={13} /></button>
            </>
          ) : (
            <>
              <div className="auth-form-eyebrow">{isRegistrationView ? "CREATE YOUR PRIVATE SPACE" : "BANKSIM OPERATIONS"}</div>
              <h2>{isRegistrationView ? "Start secure." : "Good to see you."}</h2>
              <p className="auth-form-intro">{isRegistrationView ? "One protected workspace for your firewall runs, threat intel and audit trail." : "Sign in to open your personal blue-team operations workspace."}</p>
              {!supabaseConfigured ? (
                <div className="auth-setup-callout"><LockKeyhole size={16} /><strong>Connect your Supabase project</strong><span>Add VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY to your local .env file, then restart the app. See the Supabase setup guide in README.</span></div>
              ) : (
                <form className="auth-form" onSubmit={(event) => void submitAuthenticationForm(event)}>
                  {isRegistrationView && <><label className="auth-label" htmlFor="banksim-name">YOUR NAME</label><div className="auth-input-wrap"><UserRound size={15} /><input id="banksim-name" type="text" autoComplete="name" maxLength={80} value={fullName} onChange={(event) => setFullName(event.target.value)} placeholder="Name for your workspace" required /></div></>}
                  <label className="auth-label" htmlFor="banksim-email">WORK EMAIL</label>
                  <div className="auth-input-wrap"><Mail size={15} /><input id="banksim-email" type="email" autoComplete="email" maxLength={254} value={emailAddress} onChange={(event) => setEmailAddress(event.target.value)} placeholder="you@company.com" required /></div>
                  <label className="auth-label auth-password-label" htmlFor="banksim-password">{isRegistrationView ? "PASSWORD & PRIVATE KEY" : "PASSWORD"}{!isRegistrationView && <span>ENCRYPTS YOUR PRIVATE HISTORY</span>}</label>
                  <div className="auth-input-wrap"><KeyRound size={15} /><input id="banksim-password" type={passwordVisible ? "text" : "password"} autoComplete={isRegistrationView ? "new-password" : "current-password"} minLength={isRegistrationView ? 12 : 1} maxLength={128} value={accountPassword} onChange={(event) => setAccountPassword(event.target.value)} placeholder={isRegistrationView ? "At least 12 characters" : "Enter your password"} required /><button type="button" onClick={() => setPasswordVisible((currentValue) => !currentValue)} aria-label={passwordVisible ? "Hide password" : "Show password"}>{passwordVisible ? <EyeOff size={15} /> : <Eye size={15} />}</button></div>
                  {isRegistrationView && <div className="auth-key-note"><Fingerprint size={13} /><span>Used locally to derive your private encryption key. Keep this password safe; password resets cannot decrypt older audit entries.</span></div>}
                  {(formValidationMessage || error || notice) && <div className={`auth-feedback ${error ? "feedback-error" : notice ? "feedback-success" : ""}`}>{error ?? formValidationMessage ?? notice}</div>}
                  <button className="auth-submit" disabled={busy} type="submit">{busy ? <span className="auth-button-spinner" /> : <>{isRegistrationView ? "Create my secure account" : "Sign in securely"} <ArrowRight size={15} /></>}{busy && "Securing your account…"}</button>
                  <div className="auth-form-privacy"><ShieldCheck size={13} /> PRIVATE ACCOUNT <span /> OWNER-ONLY AUDIT DATA</div>
                </form>
              )}
              {supabaseConfigured && <div className="auth-switch">{isRegistrationView ? "Already have a private workspace?" : "New to BankSim?"}<button onClick={() => { setIsRegistrationView((currentValue) => !currentValue); setAccountPassword(""); setFormValidationMessage(null); onClearMessage(); }}>{isRegistrationView ? "Sign in" : "Create an account"}</button></div>}
            </>
          )}
        </div>
        <div className="auth-main-footer"><span>PRIVATE ACCOUNTS / ENCRYPTED AUDIT</span><span>NO REAL MONEY MOVES</span></div>
      </section>
    </main>
  );
}
