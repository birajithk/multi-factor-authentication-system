"use client";

import { useEffect, useRef, useState, type FormEvent } from "react";
import { ArrowRight, ArrowLeft, Check, ChevronRight, CircleHelp, Copy, Download, Eye, EyeOff, Fingerprint, KeyRound, Keyboard, LoaderCircle, LockKeyhole, ShieldCheck, SlidersHorizontal, Smartphone, Volume2, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogDescription, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/server";

type View = "password" | "choose" | "totp" | "key" | "recovery" | "codes" | "account";
type Account = { configured: boolean; hasPassword: boolean; email: string; phase: "password" | "enroll" | "verify" | "authenticated"; hasTotp: boolean; hasKey: boolean; recoveryRemaining?: number; expiresAt?: number; recent?: boolean };
type Preferences = { contrast: boolean; large: boolean; speech: boolean };

async function api<T = Record<string, unknown>>(action: string, body?: object): Promise<T> {
  const response = await fetch(`/api/auth/${action}`, {
    method: body ? "POST" : "GET", credentials: "same-origin", cache: "no-store",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await response.json() as T & { error?: string };
  if (!response.ok) throw new Error(data.error || "We couldn’t complete that step. Please try again.");
  return data;
}

export default function AuthApp() {
  const [account, setAccount] = useState<Account | null>(null);
  const [view, setView] = useState<View>("password");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [password, setPassword] = useState("");
  const [visible, setVisible] = useState(false);
  const [code, setCode] = useState("");
  const [secret, setSecret] = useState("");
  const [uri, setUri] = useState("");
  const [codes, setCodes] = useState<string[]>([]);
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [preferences, setPreferences] = useState<Preferences>({ contrast: false, large: false, speech: false });
  const heading = useRef<HTMLHeadingElement>(null);
  const errorBox = useRef<HTMLDivElement>(null);
  const hasLoaded = useRef(false);
  const speechRef = useRef(false);

  const setup = !account?.configured;
  const enrollment = setup || adding;
  const step = view === "password" ? 0 : ["account", "codes"].includes(view) ? 2 : 1;
  const titles: Record<View, string> = {
    password: setup ? account?.hasPassword ? "Continue your setup" : "Set up your secure sign-in" : "Welcome back",
    choose: enrollment ? "Choose your second factor" : "Verify it’s you",
    totp: enrollment ? "Connect your authenticator" : "Enter your verification code",
    key: enrollment ? "Add a passkey or security key" : "Use your passkey or security key",
    recovery: "Use a recovery code", codes: "Keep a way back in", account: "You’re securely signed in",
  };
  const instructions: Record<View, string> = {
    password: setup ? "Choose a password with at least 15 characters. You can paste it or use your password manager. Then choose a second factor." : "Enter your Accessway password, then continue to your second factor. Pasting and password managers are supported.",
    choose: "Choose an authenticator app or a registered passkey or security key. Each option works with a keyboard and a screen reader.",
    totp: enrollment ? "Copy the setup key into your authenticator app, or open the app link. Choose time based codes. Then paste the six digit code to verify." : "Open your authenticator app and find Accessway. Paste the current six digit code. If it expires, use the next code. Your place is saved.",
    key: "Continue to your device’s security prompt. Follow its instructions to use a fingerprint, device PIN, or security key. You can cancel and choose another method.",
    recovery: "Paste one unused recovery code that you saved during setup. Each code works once and replaces your second factor.",
    codes: "Save these recovery codes in a safe location such as your password manager. They are shown only once. Each code can replace your second factor once.",
    account: "Both authentication factors are verified. You can add another sign-in method or sign out.",
  };

  function speak(text: string) {
    if (!("speechSynthesis" in window)) { setNotice("Spoken guidance is unavailable in this browser. All instructions are available as text."); return; }
    window.speechSynthesis.cancel();
    const utterance = new SpeechSynthesisUtterance(text);
    utterance.rate = 0.9;
    window.speechSynthesis.speak(utterance);
  }
  function go(next: View) { setError(""); setNotice(""); setCode(""); setView(next); }
  async function refresh() {
    const status = await api<Account>("status");
    setAccount(status);
    setView(status.phase === "authenticated" ? "account" : status.phase === "enroll" || status.phase === "verify" ? "choose" : "password");
    return status;
  }
  useEffect(() => {
    try { const p = JSON.parse(localStorage.getItem("accessway-preferences") || "{}"); setPreferences({ contrast: p.contrast === true, large: p.large === true, speech: p.speech === true }); } catch { /* Preferences are optional. */ }
    refresh().catch(e => setError(e.message)).finally(() => setLoading(false));
    return () => { window.speechSynthesis?.cancel(); };
  }, []);
  useEffect(() => {
    document.documentElement.dataset.contrast = preferences.contrast ? "high" : "normal";
    document.documentElement.dataset.text = preferences.large ? "large" : "normal";
    speechRef.current = preferences.speech;
    try { localStorage.setItem("accessway-preferences", JSON.stringify(preferences)); } catch { /* Storage can be unavailable. */ }
  }, [preferences]);
  useEffect(() => {
    if (loading) return;
    if (hasLoaded.current) heading.current?.focus();
    hasLoaded.current = true;
    if (speechRef.current) speak(`${titles[view]}. ${instructions[view]}`);
  }, [view, loading]);
  useEffect(() => { if (error) errorBox.current?.focus(); }, [error]);
  useEffect(() => {
    if (!account?.expiresAt) return;
    const timer = setInterval(() => {
      const seconds = account.expiresAt! - Math.floor(Date.now() / 1000);
      if (seconds <= 0) {
        setCodes([]); setSecret(""); setUri(""); setAdding(false);
        setAccount(a => a ? { ...a, phase: "password", expiresAt: undefined } : a);
        go("password"); setNotice("Your session expired. Please enter your password to continue.");
      } else if (seconds <= 120) setNotice("Your session will end within two minutes. Save any recovery codes, then sign in again if needed.");
    }, 15000);
    return () => clearInterval(timer);
  }, [account?.expiresAt]);
  useEffect(() => {
    const context = (document as any).modelContext;
    if (!context?.registerTool) return;
    const lifecycle = new AbortController();
    try {
      Promise.resolve(context.registerTool({
        name: "set_accessibility_preferences", title: "Set accessibility preferences",
        description: "Set this page’s high contrast and larger text preferences. Does not enter credentials or authenticate.",
        inputSchema: { type: "object", properties: { contrast: { type: "boolean" }, large: { type: "boolean" } }, required: ["contrast", "large"], additionalProperties: false },
        annotations: { readOnlyHint: false, untrustedContentHint: false },
        async execute(input: any) {
          if (!input || typeof input.contrast !== "boolean" || typeof input.large !== "boolean" || Object.keys(input).some(k => !["contrast", "large"].includes(k))) throw new Error("Provide contrast and large as booleans.");
          setPreferences(p => ({ ...p, contrast: input.contrast, large: input.large }));
          await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
          return { contrast: document.documentElement.dataset.contrast === "high", large: document.documentElement.dataset.text === "large" };
        },
      }, { signal: lifecycle.signal })).catch(() => {});
    } catch { /* Optional browser capability. */ }
    return () => lifecycle.abort();
  }, []);

  async function run(operation: () => Promise<void>) {
    if (busy) return;
    setBusy(true); setError(""); setNotice("");
    try { await operation(); } catch (e) { setError(e instanceof Error ? e.message : "Something went wrong. Please try again."); }
    finally { setBusy(false); }
  }
  async function submitPassword(event: FormEvent) {
    event.preventDefault();
    await run(async () => {
      if (!account?.hasPassword && [...password].length < 15) throw new Error("Use at least 15 characters for your password. A phrase of several words works well.");
      await api(setup ? "setup" : "password", { password });
      setPassword(""); setVisible(false); await refresh(); go("choose");
    });
  }
  async function choose(method: "totp" | "key" | "recovery", add = false) {
    await run(async () => {
      setAdding(add);
      if (method === "totp" && (setup || add)) {
        const result = await api<{ secret: string; uri: string }>("totp/setup", {}); setSecret(result.secret); setUri(result.uri);
      }
      go(method);
    });
  }
  async function finish(result: { recoveryCodes?: string[] }) {
    setSecret(""); setUri(""); setCode(""); setAdding(false);
    await refresh();
    if (result.recoveryCodes) { setCodes(result.recoveryCodes); go("codes"); }
    else { go("account"); setNotice("Verification complete."); }
  }
  async function submitCode(event: FormEvent) {
    event.preventDefault();
    await run(async () => {
      const route = view === "recovery" ? "recovery/verify" : enrollment ? "totp/enroll" : "totp/verify";
      await finish(await api<{ recoveryCodes?: string[] }>(route, { code }));
    });
  }
  async function useKey() {
    await run(async () => {
      if (!("PublicKeyCredential" in window)) throw new Error("This browser cannot use passkeys. Choose an authenticator app or try a browser that supports security keys.");
      try {
        const mode = enrollment ? "register" : "authenticate";
        const options = await api(`key/${mode}/options`, {});
        const response = enrollment ? await startRegistration({ optionsJSON: options as unknown as PublicKeyCredentialCreationOptionsJSON }) : await startAuthentication({ optionsJSON: options as unknown as PublicKeyCredentialRequestOptionsJSON });
        await finish(await api<{ recoveryCodes?: string[] }>(`key/${mode}/verify`, { response }));
      } catch (e) {
        if (e instanceof Error && (e.name === "NotAllowedError" || e.name === "WebAuthnError")) throw new Error("The security prompt was cancelled, timed out, or could not use this key. Try again or choose another method.");
        throw e;
      }
    });
  }
  async function signOut() { await run(async () => { await api("logout", {}); setCodes([]); setSecret(""); setAdding(false); await refresh(); go("password"); setNotice("You’ve signed out of Accessway."); }); }
  async function copy(text: string, label: string) {
    try { await navigator.clipboard.writeText(text); setNotice(`${label} copied.`); }
    catch { setNotice("Copy is unavailable. Select the text and use your device’s copy command."); }
  }
  function downloadCodes() {
    const blob = new Blob([`Accessway recovery codes\nAccount: ${account?.email}\n\nStore privately. Each code works once, after your password.\n\n${codes.join("\n")}\n`], { type: "text/plain" });
    const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = "accessway-recovery-codes.txt"; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); setNotice("Recovery codes downloaded. Keep the file private.");
  }

  const primary = (text: string, onClick?: () => void) => <Button className="primary-action" type={onClick ? "button" : "submit"} onClick={onClick} disabled={busy || loading}>{busy ? <LoaderCircle className="animate-spin" aria-hidden="true" /> : null}{busy ? "Please wait…" : text}{!busy && <ArrowRight aria-hidden="true" />}</Button>;
  const otp = <div className="field"><label htmlFor="verification-code">6-digit verification code</label><InputOTP id="verification-code" name="one-time-code" autoComplete="one-time-code" inputMode="numeric" maxLength={6} value={code} onChange={setCode} pattern="^[0-9]*$" pasteTransformer={p => p.replace(/[\s-]/g, "")} aria-describedby="code-help" aria-invalid={!!error} containerClassName="otp-container"><InputOTPGroup className="otp-group" aria-hidden="true">{Array.from({ length: 6 }, (_, i) => <InputOTPSlot key={i} index={i} className="otp-slot" />)}</InputOTPGroup></InputOTP><p id="code-help" className="field-help">Paste the whole code. If it changes, use the next one.</p></div>;

  return <div className="app-shell">
    <a className="skip-link" href="#main">Skip to authentication</a>
    <header className="site-header">
      <a className="brand" href="/" aria-label="Accessway home"><span className="brand-symbol" aria-hidden="true">a</span><span>accessway<span className="brand-period">.</span></span></a>
      <div className="header-actions">
        <Dialog><DialogTrigger asChild><Button variant="ghost" className="utility-button"><CircleHelp aria-hidden="true" /><span>Help</span></Button></DialogTrigger><DialogContent className="accessible-dialog"><DialogTitle>Help with signing in</DialogTitle><DialogDescription>Choose the method that works for you.</DialogDescription><div className="help-copy"><h3>Using a keyboard or screen reader</h3><p>Use Tab and Shift + Tab to move between controls, and Enter to continue. Use your screen reader’s heading shortcuts to find the current step. Every field has a label and supports pasting.</p><h3>Codes and security keys</h3><p>Authenticator codes change every 30 seconds. If a code is rejected, wait for the next one and check your device’s clock. A passkey may ask for your device PIN or fingerprint.</p><h3>Lost your second factor?</h3><p>After entering your password, choose “Use a recovery code.” If you have no saved recovery code or working second factor, access cannot be restored in this prototype. Your ChatGPT sign-in does not bypass Accessway MFA.</p><h3>About this prototype</h3><p>Accessway adds a separate MFA gate to your signed-in account. It stores encrypted authenticator secrets and hashed passwords on the server. Formal assistive-technology user testing and an independent security review are still needed before wider use.</p><p><a href="https://www.w3.org/WAI/WCAG22/Understanding/accessible-authentication-minimum.html" target="_blank" rel="noreferrer">Accessible authentication guidance (opens in a new tab)</a></p></div></DialogContent></Dialog>
        <Dialog><DialogTrigger asChild><Button variant="outline" className="utility-button accessibility-trigger"><SlidersHorizontal aria-hidden="true" /><span>Accessibility</span></Button></DialogTrigger><DialogContent className="accessible-dialog"><DialogTitle>Make yourself comfortable</DialogTitle><DialogDescription>These preferences apply to this browser.</DialogDescription><div className="preference"><div><label htmlFor="contrast">High contrast</label><p>Stronger borders and a black-and-white surface.</p></div><Switch id="contrast" checked={preferences.contrast} onCheckedChange={v => setPreferences(p => ({ ...p, contrast: v }))} /></div><div className="preference"><div><label htmlFor="large-text">Larger text</label><p>Increase text and control sizes.</p></div><Switch id="large-text" checked={preferences.large} onCheckedChange={v => setPreferences(p => ({ ...p, large: v }))} /></div><div className="preference"><div><label htmlFor="speech">Spoken guidance</label><p>Read step instructions aloud. Your password and codes are never read automatically.</p></div><Switch id="speech" checked={preferences.speech} onCheckedChange={v => { setPreferences(p => ({ ...p, speech: v })); if (v) speak("Spoken guidance is on. Instructions will be read when the step changes."); else window.speechSynthesis?.cancel(); }} /></div><p className="field-help">Screen reader support is always available. Spoken guidance is optional and may overlap with your screen reader.</p></DialogContent></Dialog>
      </div>
    </header>

    <div className="workspace">
      <aside className="journey-panel" aria-label="Authentication progress">
        <div className="journey-top"><span className="eyebrow"><ShieldCheck aria-hidden="true" /> SECURE ACCESS, MADE ACCESSIBLE</span><h2>Your account.<br />Your way in.</h2><p>Two layers of protection.<br />One clear step at a time.</p></div>
        <ol className="step-list">{[
          [setup ? "Create your password" : "Enter your password", "Your first layer of protection"],
          [setup ? "Add a second factor" : "Verify it’s you", "A method that works for you"],
          ["You’re ready", "Secure access to your account"],
        ].map(([title, subtitle], i) => <li key={i} className={i === step ? "current" : i < step ? "complete" : "upcoming"} aria-current={i === step ? "step" : undefined}><span className="step-number" aria-hidden="true">{i < step ? <Check /> : `0${i + 1}`}</span><div><span className="step-title">{title}</span><span className="step-description">{subtitle}</span><span className="sr-only">{i < step ? "Completed" : i === step ? "Current step" : "Upcoming"}</span></div></li>)}</ol>
        <div className="journey-note"><Keyboard aria-hidden="true" /><p>A clear path, from the first Tab<br className="desktop-break" /> to the final Enter.</p></div>
        <span className="panel-bottom">BUILT AROUND YOU</span>
      </aside>

      <main id="main" tabIndex={-1} className="auth-main">
        <div className="auth-content" aria-busy={busy || loading}>
          <div className="form-topline"><span className="step-caption">STEP {String(step + 1).padStart(2, "0")} OF 03</span><Button variant="ghost" className="listen-button" onClick={() => speak(`${titles[view]}. ${instructions[view]}`)}><Volume2 aria-hidden="true" />Listen to instructions</Button></div>
          <h1 ref={heading} tabIndex={-1}>{titles[view]}</h1>
          <p className="intro">{view === "password" ? setup ? "Start with a password. Then we’ll add a second way to confirm it’s you." : "Enter your password to continue to your second layer of protection." : view === "choose" ? "Choose how you’d like to confirm your identity." : view === "totp" ? enrollment ? "Add Accessway to your authenticator app. You can use the setup key without a camera." : "Open your authenticator app and find the code for Accessway." : view === "key" ? "Use your device’s fingerprint, PIN, or a physical security key." : view === "recovery" ? "Enter one of the unused codes you saved during setup." : view === "codes" ? "Save these recovery codes somewhere private. They’re shown only once." : "Your password and second factor have both been verified."}</p>
          {error && <div className="message error-message" role="alert" ref={errorBox} tabIndex={-1}><CircleHelp aria-hidden="true" /><p>{error}</p></div>}
          <div role="status" aria-live="polite" aria-atomic="true">{notice && <div className="message notice-message"><Check aria-hidden="true" /><p>{notice}</p></div>}</div>
          {loading ? <div className="loading-state" role="status"><LoaderCircle className="animate-spin" aria-hidden="true" />Checking your account…</div> : !account ? <div className="unavailable"><p>Your account could not be loaded.</p>{primary("Try again", () => run(async () => { await refresh(); }))}<a className="text-link" href="/signin-with-chatgpt?return_to=%2F" target="_top">Sign in with ChatGPT</a></div> : <>
            {view === "password" && <form onSubmit={submitPassword}>
              <div className="field"><label htmlFor="account-email">Account email</label><input id="account-email" name="username" type="email" autoComplete="username" value={account.email} readOnly aria-describedby="email-help" /><p id="email-help" className="field-help">Linked to your signed-in account.</p></div>
              <div className="field"><label htmlFor="password">{!account.hasPassword ? "Create a password" : "Password"}</label><div className="password-field"><input id="password" name="password" type={visible ? "text" : "password"} autoComplete={!account.hasPassword ? "new-password" : "current-password"} value={password} onChange={e => setPassword(e.target.value)} required maxLength={128} aria-invalid={!!error} aria-describedby="password-help" placeholder={setup ? "A phrase you can keep safe" : "Enter your password"} /><Button type="button" variant="ghost" onClick={() => setVisible(!visible)} aria-label={visible ? "Hide password" : "Show password"} aria-pressed={visible}>{visible ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}</Button></div><p id="password-help" className="field-help">{setup ? "At least 15 characters. Spaces and pasting are welcome." : "Use your password manager or paste your password."}</p></div>
              {primary(setup ? "Continue to second factor" : "Continue securely")}
              <div className="privacy-note"><LockKeyhole aria-hidden="true" /><span>Your password stays private and is never read aloud.</span></div>
            </form>}
            {view === "choose" && <div className="method-list">
              {(setup || account.hasKey) && <button className="method-card" onClick={() => choose("key")} disabled={busy}><span className="method-icon"><Fingerprint aria-hidden="true" /></span><span className="method-copy"><span className="method-heading">Passkey or security key <span className="recommendation">RECOMMENDED</span></span><span>Use your device or a physical key.<br />No code to read or type.</span></span><ChevronRight aria-hidden="true" /></button>}
              {(setup || account.hasTotp) && <button className="method-card" onClick={() => choose("totp")} disabled={busy}><span className="method-icon"><Smartphone aria-hidden="true" /></span><span className="method-copy"><span className="method-heading">Authenticator app</span><span>Use a 6-digit code from your app.<br />Copy, paste, and autofill supported.</span></span><ChevronRight aria-hidden="true" /></button>}
              {!setup && <Button variant="ghost" className="recovery-link" onClick={() => choose("recovery")}><KeyRound aria-hidden="true" />Use a recovery code</Button>}
              <div className="quiet-info"><ShieldCheck aria-hidden="true" /><p>{setup ? "You can add another method after setup. We’ll also give you recovery codes." : "Only a method you’ve already registered can verify your account."}</p></div>
            </div>}
            {view === "totp" && <form onSubmit={submitCode}>
              {enrollment && <div className="setup-box"><span className="mini-label">1. ADD YOUR SETUP KEY</span><p>In your authenticator, add a time-based account named “Accessway” with this key:</p><label className="sr-only" htmlFor="setup-key">Authenticator setup key</label><textarea id="setup-key" className="secret-value" readOnly value={secret} spellCheck={false} /><div className="inline-actions"><Button type="button" variant="outline" onClick={() => copy(secret, "Setup key")}><Copy aria-hidden="true" />Copy key</Button><a className="text-link" href={uri}>Open authenticator app</a></div><p className="field-help">Keep this key private. Never share it with anyone.</p></div>}
              {enrollment && <p className="mini-label">2. VERIFY YOUR APP</p>}{otp}{primary(enrollment ? "Verify and finish setup" : "Verify code")}
            </form>}
            {view === "key" && <div><div className="key-instructions"><span className="large-method-icon"><Fingerprint aria-hidden="true" /></span><h2>{enrollment ? "Your device handles this step" : "Your key is your second factor"}</h2><p>Continue to open the security prompt. Follow the instructions to confirm with your device PIN, fingerprint, or security key.</p></div>{primary(enrollment ? "Create passkey or register key" : "Open security prompt", useKey)}<p className="field-help centered">If the prompt closes, you can try again or choose another method.</p></div>}
            {view === "recovery" && <form onSubmit={submitCode}><div className="field"><label htmlFor="recovery-code">Recovery code</label><input id="recovery-code" name="recovery-code" value={code} onChange={e => setCode(e.target.value)} autoComplete="off" spellCheck={false} autoCapitalize="characters" maxLength={48} required aria-invalid={!!error} aria-describedby="recovery-help" placeholder="Paste an unused recovery code" /><p className="field-help" id="recovery-help">Each code can be used once. Spaces and hyphens are accepted.</p></div>{primary("Verify recovery code")}<div className="quiet-info"><KeyRound aria-hidden="true" /><p>Your password is still required. A recovery code replaces only your second factor.</p></div></form>}
            {view === "codes" && <div><div className="recovery-codes" aria-label="Your recovery codes">{codes.map((c, i) => <div key={c}><span className="sr-only">Code {i + 1}: </span><code>{c}</code></div>)}</div><div className="code-actions"><Button variant="outline" onClick={downloadCodes}><Download aria-hidden="true" />Download codes</Button><Button variant="outline" onClick={() => copy(codes.join("\n"), "Recovery codes")}><Copy aria-hidden="true" />Copy all</Button></div><div className="quiet-info"><LockKeyhole aria-hidden="true" /><p>Save these in a password manager or another private place you can access if you lose your device.</p></div>{primary("I’ve saved my recovery codes", () => { setCodes([]); go("account"); })}</div>}
            {view === "account" && <div className="account-view"><div className="success-banner"><span className="success-icon"><ShieldCheck aria-hidden="true" /></span><div><strong>Two factors. Verified.</strong><p>{account.email}</p></div></div><h2>Your sign-in methods</h2><div className="account-factor"><LockKeyhole aria-hidden="true" /><span>Password</span><span className="factor-status"><Check aria-hidden="true" />Active</span></div><div className="account-factor"><Smartphone aria-hidden="true" /><span>Authenticator app</span>{account.hasTotp ? <span className="factor-status"><Check aria-hidden="true" />Active</span> : <Button variant="ghost" disabled={busy} onClick={() => choose("totp", true)}>Add method</Button>}</div><div className="account-factor"><Fingerprint aria-hidden="true" /><span>Passkey / security key</span>{account.hasKey ? <span className="factor-status"><Check aria-hidden="true" />Active</span> : <Button variant="ghost" disabled={busy} onClick={() => choose("key", true)}>Add method</Button>}</div><div className="account-factor"><KeyRound aria-hidden="true" /><span>Recovery codes</span><span className="factor-count">{account.recoveryRemaining ?? 0} remaining</span></div><p className="field-help">Adding a method requires verification within the last 5 minutes. Sign out and sign in again if prompted.</p><Button className="primary-action" onClick={signOut} disabled={busy}>Sign out of Accessway<ArrowRight aria-hidden="true" /></Button><p className="field-help centered">Your session lasts 30 minutes. You can extend it below.</p></div>}
            {!["password", "codes", "account"].includes(view) && <Button variant="ghost" className="back-button" disabled={busy} onClick={() => { if (adding) { setAdding(false); go("account"); } else if (view === "choose") signOut(); else go("choose"); }}><ArrowLeft aria-hidden="true" />{adding ? "Back to account" : view === "choose" ? "Back to password" : "Choose another method"}</Button>}
          </>}
          {account?.expiresAt && <Button variant="ghost" className="more-time-button" disabled={busy} onClick={() => run(async () => { const result = await api<{ expiresAt: number }>("extend", {}); setAccount(a => a ? { ...a, expiresAt: result.expiresAt } : a); setNotice("You have more time. Your current step is saved."); })}>Need more time? Extend this session</Button>}
          <div className="form-footer"><Keyboard aria-hidden="true" /><p>Use <kbd>Tab</kbd> to move and <kbd>Enter</kbd> to continue.</p></div>
        </div>
      </main>
    </div>
    <footer className="site-footer"><span>Accessway · Accessible authentication</span><span><ShieldCheck aria-hidden="true" />Your pace. Your preferences. Your privacy.</span></footer>
  </div>;
}
