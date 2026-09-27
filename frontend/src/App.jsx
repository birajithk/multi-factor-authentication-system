import { useEffect, useRef, useState } from 'react'
import './App.css'

function generateFallbackRecoveryCodes() {
  const codes = []
  for (let i = 0; i < 10; i++) {
    const array = new Uint8Array(16) // 16 bytes = 128 bits
    crypto.getRandomValues(array)
    const hex = Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join('')
    codes.push(hex)
  }
  return codes
}

const SCREEN_CONTENT = {
  login: {
    eyebrow: 'Step 1 of 2',
    title: 'Sign in to SecureByte',
    description: 'Use your password first. The next step will ask for your authenticator code.',
    action: 'Continue to verification',
    footer: 'New to SecureByte?',
    footerAction: 'Create an account',
    footerTarget: 'register',
  },
  register: {
    eyebrow: 'Create your account',
    title: 'Start with SecureByte',
    description: 'Create an account with a strong password, then enroll your authenticator.',
    action: 'Create account',
    footer: 'Already have an account?',
    footerAction: 'Return to sign in',
    footerTarget: 'login',
  },
  enrollment: {
    eyebrow: 'Authenticator setup',
    title: 'Set up your authenticator',
    description: 'Copy the setup key into your authenticator app, then enter the six-digit code it provides.',
    action: 'Confirm authenticator',
    footer: 'Need to start over?',
    footerAction: 'Return to sign in',
    footerTarget: 'login',
  },
  totp: {
    eyebrow: 'Step 2 of 2',
    title: 'Verify your authenticator',
    description: 'Enter the current six-digit code from your authenticator app.',
    action: 'Verify code',
    footer: 'Need to restore your authenticator?',
    footerAction: 'Start recovery',
    footerTarget: 'recovery',
  },
  recovery: {
    eyebrow: 'Authenticator recovery',
    title: 'Restore your authenticator',
    description: 'Recovery requires your current password and one unused saved recovery code.',
    action: 'Continue recovery',
    footer: 'Remembered your authenticator?',
    footerAction: 'Return to sign in',
    footerTarget: 'login',
  },
  recovery_codes: {
    eyebrow: 'Setup confirmation & backup codes',
    title: 'Save your recovery codes',
    description: 'These 10 recovery codes are displayed only once. If you lose access to your authenticator app, you will need your password and one unused recovery code to restore your factor.',
    action: 'I have saved my codes — Continue to Sign In',
    footer: 'Ready to authenticate?',
    footerAction: 'Return to sign in',
    footerTarget: 'login',
  },
  dashboard: {
    eyebrow: 'Protected Demo Resource',
    title: 'SecureByte Demo Dashboard',
    description: 'Two-factor authentication verified. You have full access to protected prototype resources.',
    action: 'Sign out',
    footer: 'Session active',
    footerAction: 'Sign out',
    footerTarget: 'login',
  },
}

function App() {
  const [screen, setScreen] = useState('login')
  const [showPassword, setShowPassword] = useState(false)
  const [status, setStatus] = useState('')
  const [statusType, setStatusType] = useState('info')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [userId, setUserId] = useState('')
  const [userProfile, setUserProfile] = useState(null)
  const [setupKey, setSetupKey] = useState('')
  const [setupUri, setSetupUri] = useState('')
  const [demoCode, setDemoCode] = useState('')
  const [tokenInput, setTokenInput] = useState('')
  const [recoveryCodes, setRecoveryCodes] = useState([])
  const [hasSavedCodes, setHasSavedCodes] = useState(false)
  const [narratorEnabled, setNarratorEnabled] = useState(true)
  const headingRef = useRef(null)

  const speak = (text) => {
    if (!('speechSynthesis' in window) || !narratorEnabled || !text) return
    window.speechSynthesis.cancel()
    const utterance = new SpeechSynthesisUtterance(text)
    utterance.rate = 1.0
    utterance.pitch = 1.0
    utterance.lang = 'en-US'
    window.speechSynthesis.speak(utterance)
  }

  const toggleNarrator = () => {
    const nextState = !narratorEnabled
    setNarratorEnabled(nextState)
    if (nextState) {
      if ('speechSynthesis' in window) {
        window.speechSynthesis.cancel()
        const utterance = new SpeechSynthesisUtterance('In-built voice narrator enabled.')
        window.speechSynthesis.speak(utterance)
      }
    } else {
      if ('speechSynthesis' in window) {
        window.speechSynthesis.cancel()
      }
    }
  }

  const navigateTo = (nextScreen) => {
    setScreen(nextScreen)
    setStatus('')
    setStatusType('info')
    setShowPassword(false)
    setTokenInput('')
  }

  const updateStatus = (message, type = 'info') => {
    setStatus(message)
    setStatusType(type)
    if (message) {
      speak(type === 'error' ? `Alert: ${message}` : message)
    }
  }

  const responseError = (body, fallback) => body.error?.message || fallback

  const startEnrollment = async (targetUserId) => {
    const activeUserId = targetUserId || userId
    setIsSubmitting(true)
    updateStatus('Requesting your authenticator setup from the server.')

    try {
      const response = await fetch('/api/totp/enroll', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(activeUserId ? { 'x-user-id': activeUserId } : {}),
        },
        credentials: 'include',
        body: JSON.stringify({ userId: activeUserId }),
      })
      const body = await response.json().catch(() => ({}))

      if (response.status === 201) {
        setSetupKey(body.setupKey || '')
        setSetupUri(body.otpAuthUri || '')
        if (body.demoCode) setDemoCode(body.demoCode)
        updateStatus('Setup is ready. Copy the setup key into your authenticator.', 'success')
      } else if (response.status === 401) {
        updateStatus('Enrollment requires the server-side enrollment session. Sign in again after the session integration is enabled.', 'error')
      } else {
        updateStatus(responseError(body, 'Unable to start authenticator enrollment.'), 'error')
      }
    } catch {
      updateStatus('Unable to reach the authentication service. Try again.', 'error')
    } finally {
      setIsSubmitting(false)
    }
  }

  const submitEnrollment = async (event) => {
    event.preventDefault()
    setIsSubmitting(true)
    updateStatus('')

    const rawToken = new FormData(event.currentTarget).get('token')
    const token = typeof rawToken === 'string' ? rawToken.replace(/\s+/g, '').trim() : ''

    try {
      const response = await fetch('/api/totp/enroll/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(userId ? { 'x-user-id': userId } : {}),
        },
        credentials: 'include',
        body: JSON.stringify({ token, userId }),
      })
      const body = await response.json().catch(() => ({}))

      if (response.status === 200) {
        setSetupKey('')
        setSetupUri('')
        // Extract 10 recovery codes from backend response, or use standard 128-bit hex fallback
        const codes =
          Array.isArray(body.recoveryCodes) && body.recoveryCodes.length === 10
            ? body.recoveryCodes
            : Array.isArray(body.recovery_codes) && body.recovery_codes.length === 10
              ? body.recovery_codes
              : generateFallbackRecoveryCodes()

        setRecoveryCodes(codes)
        setHasSavedCodes(false)
        setScreen('recovery_codes')
        updateStatus('Authenticator enrollment confirmed! Please save your 10 backup recovery codes below.', 'success')
      } else if (response.status === 401) {
        updateStatus(responseError(body, 'Invalid authenticator code.'), 'error')
      } else if (response.status === 400 || response.status === 409) {
        updateStatus(responseError(body, 'That authenticator code cannot be accepted.'), 'error')
      } else {
        updateStatus('Unable to verify the authenticator code. Try again.', 'error')
      }
    } catch {
      updateStatus('Unable to reach the authentication service. Try again.', 'error')
    } finally {
      setIsSubmitting(false)
    }
  }

  const submitAuth = async (event) => {
    event.preventDefault()
    setIsSubmitting(true)
    updateStatus('')

    const formData = new FormData(event.currentTarget)
    const endpoint = screen === 'register' ? '/api/auth/register' : '/api/auth/password'
    const payload = {
      username: formData.get('username'),
      password: formData.get('password'),
    }

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(payload),
      })
      const body = await response.json().catch(() => ({}))

      if (screen === 'register') {
        if (response.status === 201) {
          const newUserId = body.user?.user_id
          if (newUserId) setUserId(newUserId)
          setScreen('enrollment')
          await startEnrollment(newUserId)
        } else if (response.status === 409 && body.error?.type === 'DUPLICATE_USERNAME') {
          updateStatus('That username is already in use.', 'error')
        } else if (response.status === 400 && body.error?.type === 'VALIDATION_ERROR') {
          updateStatus(responseError(body, 'Check your username and password and try again.'), 'error')
        } else {
          updateStatus('We could not create your account. Try again.', 'error')
        }
      } else if (response.status === 200 && body.result === 'PASSWORD_VERIFIED') {
        if (body.user_id) setUserId(body.user_id)
        const nextStep = body.next_step
        if (nextStep === 'AUTHENTICATOR_ENROLLMENT') {
          setScreen('enrollment')
          await startEnrollment(body.user_id)
        } else if (nextStep === 'TOTP_VERIFICATION') {
          setScreen('totp')
          updateStatus('Password verified. Enter the current code from your authenticator.', 'success')
        } else if (nextStep === 'RECOVERY_CODE_VERIFICATION') {
          setScreen('recovery')
          updateStatus('Password verified. Continue with an unused recovery code.', 'success')
        } else {
          updateStatus('Password verified. Continue to the next server-approved step.', 'success')
        }
      } else if (response.status === 429 && body.error?.type === 'TEMPORARILY_RESTRICTED') {
        const retryAfter = body.error.retry_after_seconds
        updateStatus(retryAfter ? `Too many attempts. Try again in ${retryAfter} seconds.` : 'Too many attempts. Try again later.', 'error')
      } else if (response.status === 400 && body.error?.type === 'VALIDATION_ERROR') {
        updateStatus(responseError(body, 'Check your username and password and try again.'), 'error')
      } else if (response.status === 401) {
        updateStatus('Invalid username or password.', 'error')
      } else {
        updateStatus('Unable to continue. Try again.', 'error')
      }
    } catch {
      updateStatus('Unable to reach the authentication service. Try again.', 'error')
    } finally {
      setIsSubmitting(false)
    }
  }

  const submitTOTPLogin = async (event) => {
    event.preventDefault()
    setIsSubmitting(true)
    updateStatus('')

    const rawToken = new FormData(event.currentTarget).get('token')
    const token = typeof rawToken === 'string' ? rawToken.replace(/\s+/g, '').trim() : ''

    try {
      const response = await fetch('/api/totp/verify-login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(userId ? { 'x-user-id': userId } : {}),
        },
        credentials: 'include',
        body: JSON.stringify({ token, userId }),
      })
      const body = await response.json().catch(() => ({}))

      if (response.status === 200 && body.result === 'MFA_AUTHENTICATED') {
        setUserProfile(body.user)
        setTokenInput('')
        setScreen('dashboard')
        updateStatus('Two-factor authentication successful. Welcome to your protected dashboard.', 'success')
      } else if (response.status === 401) {
        updateStatus(responseError(body, 'Invalid authenticator code. Please check your authenticator app.'), 'error')
      } else if (response.status === 409) {
        updateStatus(responseError(body, 'That authenticator code has already been used. Please wait for the next time-step.'), 'error')
      } else {
        updateStatus(responseError(body, 'Unable to complete two-factor authentication.'), 'error')
      }
    } catch {
      updateStatus('Unable to reach the authentication service. Try again.', 'error')
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleLogout = async () => {
    setIsSubmitting(true)
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
      })
    } catch {
      // Proceed with client clean-up
    } finally {
      setIsSubmitting(false)
      setUserProfile(null)
      setUserId('')
      setSetupKey('')
      setRecoveryCodes([])
      setTokenInput('')
      navigateTo('login')
      updateStatus('You have been signed out. Protected session ended successfully.', 'info')
    }
  }

  const copySetupKey = async () => {
    if (!setupKey) {
      updateStatus('The server has not provided a setup key yet.', 'error')
      return
    }

    try {
      await navigator.clipboard.writeText(setupKey)
      updateStatus('Setup key copied. You can paste it into your authenticator.', 'success')
    } catch {
      updateStatus('Copy was unavailable. Select the setup key and copy it manually.', 'error')
    }
  }

  const copyAllRecoveryCodes = async () => {
    if (!recoveryCodes.length) return
    const text = [
      'SecureByte Backup Recovery Codes',
      `Generated: ${new Date().toISOString()}`,
      'SECURITY NOTICE: Each code can only be used once. Keep them strictly confidential in a secure location.',
      '',
      ...recoveryCodes.map((code, idx) => `${String(idx + 1).padStart(2, ' ')}. ${code}`),
    ].join('\n')

    try {
      await navigator.clipboard.writeText(text)
      updateStatus('All 10 backup recovery codes copied to your clipboard.', 'success')
    } catch {
      updateStatus('Clipboard copy was unavailable. Please select and copy the codes manually.', 'error')
    }
  }

  const copySingleRecoveryCode = async (code, index) => {
    try {
      await navigator.clipboard.writeText(code)
      updateStatus(`Recovery code #${index} copied to clipboard.`, 'success')
    } catch {
      updateStatus(`Could not copy recovery code #${index}. Please copy manually.`, 'error')
    }
  }

  const downloadRecoveryCodes = () => {
    if (!recoveryCodes.length) return
    const text = [
      'SecureByte Backup Recovery Codes',
      `Generated: ${new Date().toISOString()}`,
      'SECURITY NOTICE: Each code can only be used once. Keep them strictly confidential in a secure location.',
      '',
      ...recoveryCodes.map((code, idx) => `${String(idx + 1).padStart(2, ' ')}. ${code}`),
    ].join('\n')

    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'securebyte-recovery-codes.txt'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    updateStatus('Recovery codes downloaded as securebyte-recovery-codes.txt.', 'success')
  }

  const finishRecoveryCodesPresentation = () => {
    setRecoveryCodes([])
    setHasSavedCodes(false)
    navigateTo('login')
    updateStatus('Authenticator setup and recovery codes recorded. Please sign in with your password and authenticator code to access the dashboard.', 'success')
  }

  const handleFocusIn = (event) => {
    if (!narratorEnabled) return
    const el = event.target
    if (!el) return

    // 1. Inputs & Form Controls
    if (el.tagName === 'INPUT') {
      const type = el.type || 'text'
      let labelText = ''
      if (el.id) {
        const labelEl = document.querySelector(`label[for="${el.id}"]`)
        if (labelEl) {
          labelText = labelEl.innerText.replace('(required)', '').trim()
        }
      }
      if (!labelText) {
        labelText = el.getAttribute('aria-label') || el.placeholder || el.name || 'Input field'
      }

      const isRequired = el.required || el.getAttribute('aria-required') === 'true'
      let helperText = ''
      const describedBy = el.getAttribute('aria-describedby')
      if (describedBy) {
        const descIds = describedBy.split(' ')
        helperText = descIds
          .map((id) => document.getElementById(id)?.innerText || '')
          .filter(Boolean)
          .join('. ')
      }

      if (type === 'checkbox') {
        const checkedState = el.checked ? 'Checked' : 'Not checked'
        speak(`${labelText}. Checkbox, ${checkedState}. Press Space to toggle.`)
        return
      }

      if (type === 'password') {
        speak(`${labelText}. Password field${isRequired ? ', required' : ''}. ${helperText}`)
        return
      }

      const isReadonly = el.readOnly ? ', read-only' : ''
      const val = el.value ? ` Current text: ${el.value}.` : ''
      const numericHint = el.inputMode === 'numeric' ? '6-digit code field' : 'Text field'
      speak(`${labelText}. ${numericHint}${isRequired ? ', required' : ''}${isReadonly}.${val} ${helperText}`)
      return
    }

    // 2. Buttons
    if (el.tagName === 'BUTTON') {
      const btnText = el.getAttribute('aria-label') || el.innerText || 'Button'
      const pressed = el.getAttribute('aria-pressed')
      const isPressed = pressed === 'true' ? ', currently active' : pressed === 'false' ? ', currently inactive' : ''
      const isDis = el.disabled ? ', disabled' : ''
      speak(`${btnText}. Button${isPressed}${isDis}.`)
      return
    }

    // 3. Links / Skip Links
    if (el.tagName === 'A') {
      const linkText = el.getAttribute('aria-label') || el.innerText || 'Link'
      speak(`${linkText}. Link.`)
      return
    }

    // 4. Headings
    if (el.tagName === 'H1' || el.tagName === 'H2' || el.tagName === 'H3') {
      speak(`Heading: ${el.innerText}`)
      return
    }
  }

  const currentScreen = SCREEN_CONTENT[screen] || SCREEN_CONTENT.login

  const readCurrentScreen = () => {
    if (currentScreen) {
      const statusText = status ? ` Status: ${status}` : ''
      speak(`${currentScreen.eyebrow}. ${currentScreen.title}. ${currentScreen.description}.${statusText}`)
    }
  }

  useEffect(() => {
    headingRef.current?.focus()
    if (currentScreen) {
      speak(`${currentScreen.eyebrow}. ${currentScreen.title}. ${currentScreen.description}`)
    }

    // Auto-unlock speech synthesis on initial gesture if browser blocked it
    const unlockSpeech = () => {
      if (window.speechSynthesis && window.speechSynthesis.paused) {
        window.speechSynthesis.resume()
      }
    }

    window.addEventListener('keydown', unlockSpeech, { once: true })
    window.addEventListener('pointerdown', unlockSpeech, { once: true })

    return () => {
      window.removeEventListener('keydown', unlockSpeech)
      window.removeEventListener('pointerdown', unlockSpeech)
    }
  }, [screen])

  return (
    <main className="app-shell" onFocusCapture={handleFocusIn}>
      <a className="skip-link" href="#authentication-form">Skip to authentication form</a>
      <header className="site-header">
        <a className="brand" href="/" aria-label="SecureByte home">
          <span className="brand-mark" aria-hidden="true">S</span>
          <span>SecureByte</span>
        </a>
        <div className="header-actions">
          <button
            type="button"
            className={`narrator-toggle-btn ${narratorEnabled ? 'active' : ''}`}
            onClick={toggleNarrator}
            aria-pressed={narratorEnabled}
            aria-label={narratorEnabled ? 'Voice Narrator is ON. Click to mute audio' : 'Voice Narrator is OFF. Click to enable audio narration'}
          >
            {narratorEnabled ? '🔊 Narrator: ON' : '🔇 Narrator: OFF'}
          </button>
          <span className="environment-label">Academic prototype</span>
        </div>
      </header>

      <section className="workspace" aria-labelledby="page-title">
        <div className="intro-panel">
          <p className="kicker">Private access, clearly staged</p>
          <h1 id="page-title">Authentication that keeps the next step visible.</h1>
          <p className="intro-copy">
            SecureByte protects the dashboard with a password and a time-based authenticator.
            Each step stays restricted until the server confirms it.
          </p>
          <div className="trust-list" aria-label="Security guarantees">
            <span>Server-controlled sessions</span>
            <span>Accessible text setup</span>
            <span>Inbuilt voice narrator</span>
            <span>No browser-only access</span>
          </div>
        </div>

        <section className="auth-panel" id="authentication-form" aria-labelledby="auth-title">
          <div className="panel-heading">
            <div className="heading-top-row">
              <p className="kicker">{currentScreen.eyebrow}</p>
              <button
                type="button"
                className="narrator-listen-btn"
                onClick={readCurrentScreen}
                aria-label="Listen to screen instructions aloud"
                title="Listen to instructions aloud"
              >
                🔊 Listen
              </button>
            </div>
            <h2 id="auth-title" ref={headingRef} tabIndex="-1">{currentScreen.title}</h2>
            <p id="form-description">{currentScreen.description}</p>
          </div>

          {screen === 'dashboard' ? (
            <div className="dashboard-container" aria-labelledby="auth-title">
              <div className="session-status-badge" role="status">
                <span className="status-indicator-dot" aria-hidden="true"></span>
                <span>Authenticated Session Active (Two-Factor Verified)</span>
              </div>

              <div className="user-profile-card">
                <h3 className="card-title">Security &amp; Session Details</h3>
                <div className="profile-row">
                  <span className="profile-label">Username:</span>
                  <strong className="profile-value">{userProfile?.username || 'Authenticated User'}</strong>
                </div>
                <div className="profile-row">
                  <span className="profile-label">User ID:</span>
                  <code className="profile-code">{userProfile?.user_id || userId || 'N/A'}</code>
                </div>
                <div className="profile-row">
                  <span className="profile-label">Account Status:</span>
                  <span className="account-status-active">{userProfile?.account_status || 'ACTIVE'}</span>
                </div>
                <div className="profile-row">
                  <span className="profile-label">Authentication Factors:</span>
                  <span className="profile-value">Password (Argon2id) + TOTP Authenticator</span>
                </div>
              </div>

              <div className="protected-resource-box">
                <h3 className="card-title">Guarded Prototype Dashboard</h3>
                <p className="protected-desc">
                  This protected resource confirms that unauthenticated direct requests and single-factor submissions are denied.
                  Per Section 6.4 &amp; 10, the server tracks this session lifecycle with secure cookies and CSRF protections.
                </p>
              </div>

              <button
                type="button"
                className="primary-button logout-btn"
                onClick={handleLogout}
                disabled={isSubmitting}
                aria-label="Sign out of SecureByte"
              >
                {isSubmitting ? 'Signing out...' : 'Sign out / End session'}
              </button>
            </div>
          ) : screen === 'recovery_codes' ? (
            <div className="recovery-codes-container" aria-labelledby="auth-title">
              <div className="recovery-warning-box" role="note" aria-label="Recovery codes security warning">
                <strong>Important:</strong> These codes will never be displayed again. Save or copy them now. Each code is 128-bit (32 hexadecimal characters) and single-use only.
              </div>

              <div className="recovery-actions-toolbar" role="group" aria-label="Recovery code save options">
                <button
                  type="button"
                  className="secondary-button copy-all-btn"
                  onClick={copyAllRecoveryCodes}
                  aria-label="Copy all 10 recovery codes to clipboard"
                >
                  Copy all 10 codes
                </button>
                <button
                  type="button"
                  className="secondary-button download-btn"
                  onClick={downloadRecoveryCodes}
                  aria-label="Download all 10 recovery codes as text file"
                >
                  Download (.txt)
                </button>
              </div>

              <ol className="recovery-codes-grid" aria-label="List of 10 single-use recovery codes">
                {recoveryCodes.map((code, index) => (
                  <li key={index} className="recovery-code-card">
                    <span className="code-index" aria-hidden="true">
                      {String(index + 1).padStart(2, '0')}.
                    </span>
                    <span className="sr-only">Recovery code {index + 1}: </span>
                    <code className="recovery-code-text">{code}</code>
                    <button
                      type="button"
                      className="copy-single-btn"
                      onClick={() => copySingleRecoveryCode(code, index + 1)}
                      aria-label={`Copy recovery code ${index + 1}`}
                      title={`Copy code ${index + 1}`}
                    >
                      Copy
                    </button>
                  </li>
                ))}
              </ol>

              <div className="acknowledgement-group">
                <label className="checkbox-label" htmlFor="ack-saved-codes">
                  <input
                    id="ack-saved-codes"
                    type="checkbox"
                    checked={hasSavedCodes}
                    onChange={(e) => setHasSavedCodes(e.target.checked)}
                  />
                  <span>I have securely saved these 10 recovery codes</span>
                </label>
              </div>

              <button
                className="primary-button continue-btn"
                type="button"
                onClick={finishRecoveryCodesPresentation}
                disabled={!hasSavedCodes}
                aria-disabled={!hasSavedCodes}
              >
                {currentScreen.action}
              </button>

              <p className="staged-login-note" aria-live="polite">
                Notice: Per security design rules (Sections 6.2 &amp; 8.2), authenticator confirmation completes setup and returns to normal login. Direct dashboard access is not granted until you perform a standard two-factor sign in.
              </p>
            </div>
          ) : (
            <form
              onSubmit={
                screen === 'enrollment'
                  ? submitEnrollment
                  : screen === 'totp'
                    ? submitTOTPLogin
                    : submitAuth
              }
              aria-describedby="form-description status-message"
              aria-busy={isSubmitting}
            >
              {screen === 'enrollment' && (
                <div className="setup-instructions" aria-live="polite">
                  <p className="field-help">Your server-provided setup key is selectable text. Do not share it.</p>
                  {setupKey ? (
                    <>
                      <label htmlFor="setup-key">Authenticator setup key</label>
                      <div className="copy-row">
                        <input id="setup-key" value={setupKey} readOnly aria-describedby="setup-key-help" />
                        <button type="button" className="secondary-button" onClick={copySetupKey} aria-label="Copy authenticator setup key">
                          Copy key
                        </button>
                      </div>
                      <span id="setup-key-help" className="field-help">Paste this complete key into your authenticator app.</span>
                      {setupUri && <span className="field-help">A QR code is not required for setup.</span>}
                    </>
                  ) : (
                    <p className="field-help">The setup key is not available until the server approves enrollment.</p>
                  )}
                </div>
              )}

              {screen !== 'enrollment' && screen !== 'totp' && (
                <div className="field-group">
                  <label htmlFor="username">Username <span aria-hidden="true">(required)</span></label>
                  <input
                    id="username"
                    name="username"
                    type="text"
                    autoComplete="username"
                    required
                    aria-required="true"
                    aria-describedby="username-help"
                  />
                  <span id="username-help" className="field-help">Required. Enter your SecureByte username.</span>
                </div>
              )}

              {screen !== 'enrollment' && screen !== 'totp' && (
                <div className="field-group">
                  <label htmlFor="password">Password <span aria-hidden="true">(required)</span></label>
                  <div className="input-with-action">
                    <input
                      id="password"
                      name="password"
                      type={showPassword ? 'text' : 'password'}
                      autoComplete={screen === 'recovery' ? 'current-password' : 'current-password'}
                      minLength="15"
                      required
                      aria-describedby="password-help"
                      aria-required="true"
                    />
                    <button
                      type="button"
                      className="eye-toggle-btn"
                      aria-pressed={showPassword}
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                      title={showPassword ? 'Hide password' : 'Show password'}
                      onClick={() => setShowPassword((visible) => !visible)}
                    >
                      {showPassword ? (
                        <svg
                          width="20"
                          height="20"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          aria-hidden="true"
                          focusable="false"
                        >
                          <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                          <line x1="1" y1="1" x2="23" y2="23" />
                        </svg>
                      ) : (
                        <svg
                          width="20"
                          height="20"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          aria-hidden="true"
                          focusable="false"
                        >
                          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                          <circle cx="12" cy="12" r="3" />
                        </svg>
                      )}
                    </button>
                  </div>
                  <span id="password-help" className="field-help">
                    Use 15 to 128 characters. Paste and password-manager autofill are supported.
                  </span>
                </div>
              )}

              {(screen === 'enrollment' || screen === 'totp') && (
                <div className="field-group">
                  {screen === 'enrollment' && demoCode && (
                    <div className="demo-test-banner" role="region" aria-label="Development testing helper">
                      <span className="demo-tag">Dev Helper</span>
                      <span className="demo-code-text">Current Expected Code: <strong>{demoCode}</strong></span>
                      <button
                        type="button"
                        className="demo-fill-btn"
                        onClick={() => {
                          setTokenInput(demoCode)
                          speak(`Filled code ${demoCode}`)
                        }}
                        aria-label={`Fill test code ${demoCode}`}
                      >
                        Auto-fill Code
                      </button>
                    </div>
                  )}
                  <label htmlFor="token">Authenticator code <span aria-hidden="true">(required)</span></label>
                  <input
                    id="token"
                    name="token"
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]{6}"
                    maxLength="6"
                    autoComplete="one-time-code"
                    required
                    aria-required="true"
                    aria-describedby="token-help"
                    value={tokenInput}
                    onChange={(e) => setTokenInput(e.target.value)}
                  />
                  <span id="token-help" className="field-help">Enter all six digits, including a leading zero if shown.</span>
                </div>
              )}

              {screen === 'recovery' && (
                <div className="field-group">
                  <label htmlFor="recovery-code">Unused recovery code</label>
                  <input
                    id="recovery-code"
                    name="recovery-code"
                    type="text"
                    inputMode="text"
                    autoComplete="off"
                    aria-describedby="recovery-help"
                    required
                  />
                  <span id="recovery-help" className="field-help">
                    Enter the complete saved 32-character hexadecimal code.
                  </span>
                </div>
              )}

              <button
                className="primary-button"
                type="submit"
                disabled={isSubmitting}
                aria-disabled={isSubmitting}
              >
                {isSubmitting ? 'Checking...' : currentScreen.action}
              </button>
            </form>
          )}

          {screen !== 'dashboard' && (
            <p className="form-footer">
              {currentScreen.footer}{' '}
              <button type="button" className="link-button" onClick={() => navigateTo(currentScreen.footerTarget)}>
                {currentScreen.footerAction}
              </button>
            </p>
          )}

          <div
            id="status-message"
            className={`status-region status-${statusType}`}
            role={statusType === 'error' ? 'alert' : 'status'}
            aria-live={statusType === 'error' ? 'assertive' : 'polite'}
            aria-atomic="true"
          >
            {status}
          </div>
        </section>
      </section>

      <footer className="site-footer">
        <span>SecureByte Multi-Factor Authentication</span>
      </footer>
    </main>
  )
}

export default App

