import { useEffect, useRef, useState } from 'react'
import './App.css'

function App() {
  const [screen, setScreen] = useState('login')
  const [showPassword, setShowPassword] = useState(false)
  const [status, setStatus] = useState('')
  const [statusType, setStatusType] = useState('info')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [setupKey, setSetupKey] = useState('')
  const [setupUri, setSetupUri] = useState('')
  const headingRef = useRef(null)

  const navigateTo = (nextScreen) => {
    setScreen(nextScreen)
    setStatus('')
    setStatusType('info')
    setShowPassword(false)
  }

  useEffect(() => {
    headingRef.current?.focus()
  }, [screen])

  const updateStatus = (message, type = 'info') => {
    setStatus(message)
    setStatusType(type)
  }

  const responseError = (body, fallback) => body.error?.message || fallback

  const startEnrollment = async () => {
    setIsSubmitting(true)
    updateStatus('Requesting your authenticator setup from the server.')

    try {
      const response = await fetch('/api/totp/enroll', {
        method: 'POST',
        credentials: 'include',
      })
      const body = await response.json().catch(() => ({}))

      if (response.status === 201) {
        setSetupKey(body.setupKey || '')
        setSetupUri(body.otpAuthUri || '')
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

    const token = new FormData(event.currentTarget).get('token')

    try {
      const response = await fetch('/api/totp/enroll/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ token }),
      })
      const body = await response.json().catch(() => ({}))

      if (response.status === 200) {
        setSetupKey('')
        setSetupUri('')
        updateStatus('Authenticator enrollment complete. Return to sign in for normal two-factor authentication.', 'success')
        setScreen('login')
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
          setScreen('enrollment')
          await startEnrollment()
        } else if (response.status === 409 && body.error?.type === 'DUPLICATE_USERNAME') {
          updateStatus('That username is already in use.', 'error')
        } else if (response.status === 400 && body.error?.type === 'VALIDATION_ERROR') {
          updateStatus(responseError(body, 'Check your username and password and try again.'), 'error')
        } else {
          updateStatus('We could not create your account. Try again.', 'error')
        }
      } else if (response.status === 200 && body.result === 'PASSWORD_VERIFIED') {
        const nextStep = body.next_step
        if (nextStep === 'AUTHENTICATOR_ENROLLMENT') {
          setScreen('enrollment')
          await startEnrollment()
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

  const screenContent = {
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
  }

  const currentScreen = screenContent[screen]

  return (
    <main className="app-shell">
      <a className="skip-link" href="#authentication-form">Skip to authentication form</a>
      <header className="site-header">
        <a className="brand" href="/" aria-label="SecureByte home">
          <span className="brand-mark" aria-hidden="true">S</span>
          <span>SecureByte</span>
        </a>
        <span className="environment-label">Academic prototype</span>
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
            <span>No browser-only access</span>
          </div>
        </div>

        <section className="auth-panel" id="authentication-form" aria-labelledby="auth-title">
          <div className="panel-heading">
            <p className="kicker">{currentScreen.eyebrow}</p>
            <h2 id="auth-title" ref={headingRef} tabIndex="-1">{currentScreen.title}</h2>
            <p id="form-description">{currentScreen.description}</p>
          </div>

          <form
            onSubmit={screen === 'enrollment' ? submitEnrollment : submitAuth}
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

            {screen !== 'enrollment' && screen !== 'totp' && <div className="field-group">
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
            </div>}

            {screen !== 'enrollment' && screen !== 'totp' && <div className="field-group">
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
                  className="text-action"
                  aria-pressed={showPassword}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  onClick={() => setShowPassword((visible) => !visible)}
                >
                  {showPassword ? 'Hide password' : 'Show password'}
                </button>
              </div>
              <span id="password-help" className="field-help">
                Use 15 to 128 characters. Paste and password-manager autofill are supported.
              </span>
            </div>}

            {(screen === 'enrollment' || screen === 'totp') && (
              <div className="field-group">
                <label htmlFor="token">Authenticator code <span aria-hidden="true">(required)</span></label>
                <input id="token" name="token" type="text" inputMode="numeric" pattern="[0-9]{6}" maxLength="6" autoComplete="one-time-code" required aria-required="true" aria-describedby="token-help" />
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
                  Enter the complete saved code in the format agreed by the team.
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

          <p className="form-footer">
            {currentScreen.footer}{' '}
            <button type="button" className="link-button" onClick={() => navigateTo(currentScreen.footerTarget)}>
              {currentScreen.footerAction}
            </button>
          </p>

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
        <span></span>
        <span></span>
      </footer>
    </main>
  )
}

export default App
