import { useState } from 'react'
import './App.css'

function App() {
  const [screen, setScreen] = useState('login')
  const [showPassword, setShowPassword] = useState(false)
  const [status, setStatus] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)

  const navigateTo = (nextScreen) => {
    setScreen(nextScreen)
    setStatus('')
    setShowPassword(false)
  }

  const submitAuth = async (event) => {
    event.preventDefault()
    setIsSubmitting(true)
    setStatus('')

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
          setStatus('Account created. Continue with authenticator enrollment.')
        } else if (response.status === 409 && body.code === 'DUPLICATE_USERNAME') {
          setStatus('That username is already in use.')
        } else if (response.status === 400 && body.code === 'VALIDATION_ERROR') {
          setStatus(body.message || 'Check your username and password and try again.')
        } else {
          setStatus('We could not create your account. Try again.')
        }
      } else if (response.status === 200 && body.code === 'PASSWORD_VERIFIED') {
        const nextStep = body.next_step
        setStatus(nextStep ? `Password verified. Next step: ${nextStep}.` : 'Password verified. Continue to the next step.')
      } else if (response.status === 429 && body.code === 'TEMPORARILY_RESTRICTED') {
        const retryAfter = body.retry_after_seconds
        setStatus(retryAfter ? `Too many attempts. Try again in ${retryAfter} seconds.` : 'Too many attempts. Try again later.')
      } else if (response.status === 400 && body.code === 'VALIDATION_ERROR') {
        setStatus(body.message || 'Check your username and password and try again.')
      } else if (response.status === 401) {
        setStatus('Invalid username or password.')
      } else {
        setStatus('Unable to continue. Try again.')
      }
    } catch {
      setStatus('Unable to reach the authentication service. Try again.')
    } finally {
      setIsSubmitting(false)
    }
  }

  const copySetupKey = async () => {
    const setupKey = 'JBSWY3DPEHPK3PXP'

    try {
      await navigator.clipboard.writeText(setupKey)
      setStatus('Setup key copied. You can paste it into your authenticator.')
    } catch {
      setStatus('Copy was unavailable. Select the setup key and copy it manually.')
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

        <div className="auth-panel">
          <div className="panel-heading">
            <p className="kicker">{currentScreen.eyebrow}</p>
            <h2>{currentScreen.title}</h2>
            <p>{currentScreen.description}</p>
          </div>

          <form onSubmit={submitAuth}>
            <div className="field-group">
              <label htmlFor="username">Username</label>
              <input id="username" name="username" type="text" autoComplete="username" required />
            </div>

            <div className="field-group">
              <label htmlFor="password">Password</label>
              <div className="input-with-action">
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete={screen === 'recovery' ? 'current-password' : 'current-password'}
                  minLength="15"
                  required
                  aria-describedby="password-help"
                />
                <button
                  type="button"
                  className="text-action"
                  aria-pressed={showPassword}
                  onClick={() => setShowPassword((visible) => !visible)}
                >
                  {showPassword ? 'Hide' : 'Show'}
                </button>
              </div>
              <span id="password-help" className="field-help">
                Use 15 to 128 characters. Paste and password-manager autofill are supported.
              </span>
            </div>

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

            <button className="primary-button" type="submit" disabled={isSubmitting}>
              {isSubmitting ? 'Checking...' : currentScreen.action}
            </button>
          </form>

          <p className="form-footer">
            {currentScreen.footer}{' '}
            <button type="button" className="link-button" onClick={() => navigateTo(currentScreen.footerTarget)}>
              {currentScreen.footerAction}
            </button>
          </p>

          <div className="status-region" role="status" aria-live="polite">
            {status}
          </div>
        </div>
      </section>

      <section className="setup-preview" aria-labelledby="setup-title">
        <div>
          <p className="kicker">Next screen in the flow</p>
          <h2 id="setup-title">Authenticator setup stays copyable.</h2>
          <p>The text path remains available even when a QR code is not usable.</p>
        </div>
        <div className="setup-key-block">
          <label htmlFor="setup-key">Your setup key</label>
          <div className="copy-row">
            <input id="setup-key" value="JBSWY3DPEHPK3PXP" readOnly aria-describedby="setup-key-help" />
            <button type="button" className="secondary-button" onClick={copySetupKey}>Copy key</button>
          </div>
          <span id="setup-key-help" className="field-help">Selectable text for keyboard and screen-reader users.</span>
        </div>
      </section>

      <footer className="site-footer">
        <span></span>
        <span></span>
      </footer>
    </main>
  )
}

export default App
