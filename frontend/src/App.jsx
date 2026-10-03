import { useEffect, useState } from 'react'
import './App.css'

function App() {
  const [screen, setScreen] = useState('login')
  const [showPassword, setShowPassword] = useState(false)
  const [status, setStatus] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)

  const [setupKey, setSetupKey] = useState('')
  const [dashboard, setDashboard] = useState(null)

  const [sessionExpiresAt, setSessionExpiresAt] = useState(null)
  const [showSessionWarning, setShowSessionWarning] = useState(false)
  const [isExtendingSession, setIsExtendingSession] = useState(false)

  const navigateTo = (nextScreen) => {
    setScreen(nextScreen)
    setStatus('')
    setShowPassword(false)
  }

  // -------------------------------------------------------
  // Common API helper
  // -------------------------------------------------------

  const apiRequest = async (endpoint, options = {}) => {
    const response = await fetch(endpoint, {
      credentials: 'include',
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {}),
      },
    })

    const body = await response.json().catch(() => ({}))

    return {
      response,
      body,
    }
  }

  // -------------------------------------------------------
  // Session information
  // -------------------------------------------------------

  const loadSessionInfo = async () => {
    try {
      const { response, body } = await apiRequest(
        '/api/session',
        {
          method: 'GET',
        },
      )

      if (
        response.status === 200 &&
        body.success &&
        body.session?.expires_at
      ) {
        setSessionExpiresAt(body.session.expires_at)
        setShowSessionWarning(false)

        return true
      }

      setSessionExpiresAt(null)
      setShowSessionWarning(false)
      setDashboard(null)
      setScreen('login')

      setStatus(
        body.error?.message ||
          'Your session has expired. Sign in again.',
      )

      return false
    } catch {
      /*
       * Fail closed if the frontend cannot verify the
       * current authenticated session.
       */
      setSessionExpiresAt(null)
      setShowSessionWarning(false)
      setDashboard(null)
      setScreen('login')

      setStatus(
        'Unable to verify your session. Sign in again.',
      )

      return false
    }
  }

  // -------------------------------------------------------
  // Extend current full session
  // -------------------------------------------------------

  const extendCurrentSession = async () => {
    setIsExtendingSession(true)
    setStatus('')

    try {
      const { response, body } = await apiRequest(
        '/api/session/extend',
        {
          method: 'POST',
          body: JSON.stringify({}),
        },
      )

      if (
        response.status === 200 &&
        body.result === 'SESSION_EXTENDED' &&
        body.session?.expires_at
      ) {
        setSessionExpiresAt(body.session.expires_at)
        setShowSessionWarning(false)

        setStatus(
          'Your session has been extended.',
        )

        return
      }

      if (response.status === 401) {
        setDashboard(null)
        setSessionExpiresAt(null)
        setShowSessionWarning(false)
        setScreen('login')

        setStatus(
          body.error?.message ||
            'Your session expired. Sign in again.',
        )

        return
      }

      setStatus(
        body.error?.message ||
          'Your session could not be extended.',
      )
    } catch {
      setStatus(
        'Unable to extend your session.',
      )
    } finally {
      setIsExtendingSession(false)
    }
  }

  // -------------------------------------------------------
  // Registration / password authentication
  // -------------------------------------------------------

  const submitAuth = async (event) => {
    event.preventDefault()

    setIsSubmitting(true)
    setStatus('')

    const formData = new FormData(event.currentTarget)

    const username = formData.get('username')
    const password = formData.get('password')

    const endpoint =
      screen === 'register'
        ? '/api/auth/register'
        : '/api/auth/password'

    try {
      const { response, body } = await apiRequest(
        endpoint,
        {
          method: 'POST',
          body: JSON.stringify({
            username,
            password,
          }),
        },
      )

      // Registration
      if (screen === 'register') {
        if (
          response.status === 201 &&
          body.success
        ) {
          setStatus(
            'Account created. Starting authenticator setup.',
          )

          await startEnrollment()
          return
        }

        setStatus(
          body.error?.message ||
            'We could not create your account. Try again.',
        )

        return
      }

      // Password login
      if (
        response.status === 200 &&
        body.result === 'PASSWORD_VERIFIED'
      ) {
        if (
          body.next_step ===
          'AUTHENTICATOR_ENROLLMENT'
        ) {
          setStatus(
            'Password verified. Continue authenticator setup.',
          )

          await startEnrollment()
          return
        }

        if (
          body.next_step ===
          'TOTP_VERIFICATION'
        ) {
          setScreen('totp-login')

          setStatus(
            'Password verified. Enter your authenticator code.',
          )

          return
        }

        if (
          body.next_step ===
          'RECOVERY_CODE_VERIFICATION'
        ) {
          setScreen('recovery')

          setStatus(
            'Enter one unused recovery code to continue.',
          )

          return
        }
      }

      // Rate limit
      if (
        response.status === 429 &&
        body.error?.type ===
          'TEMPORARILY_RESTRICTED'
      ) {
        const retry =
          body.error?.retry_after_seconds

        setStatus(
          retry
            ? `Too many attempts. Try again in ${retry} seconds.`
            : 'Too many attempts. Try again later.',
        )

        return
      }

      setStatus(
        body.error?.message ||
          'Unable to continue. Try again.',
      )
    } catch {
      setStatus(
        'Unable to reach the authentication service. Try again.',
      )
    } finally {
      setIsSubmitting(false)
    }
  }

  // -------------------------------------------------------
  // Start normal authenticator enrollment
  // -------------------------------------------------------

  const startEnrollment = async () => {
    try {
      const { response, body } = await apiRequest(
        '/api/totp/enroll',
        {
          method: 'POST',
          body: JSON.stringify({}),
        },
      )

      if (
        response.status === 201 &&
        typeof body.setupKey === 'string'
      ) {
        setSetupKey(body.setupKey)
        setScreen('totp-enroll')

        setStatus(
          'Add this setup key to your authenticator, then enter the generated six-digit code.',
        )

        return
      }

      if (
        response.status === 401 &&
        body.error?.type ===
          'AUTHENTICATION_REQUIRED'
      ) {
        setSetupKey('')
        setScreen('login')

        setStatus(
          body.error?.message ||
            'Your enrollment session expired. Sign in again.',
        )

        return
      }

      setStatus(
        typeof body.error === 'string'
          ? body.error
          : body.error?.message ||
              'Unable to start authenticator enrollment.',
      )
    } catch {
      setStatus(
        'Unable to start authenticator enrollment.',
      )
    }
  }

  // -------------------------------------------------------
  // Verify normal authenticator enrollment
  // -------------------------------------------------------

  const verifyEnrollment = async (event) => {
    event.preventDefault()

    setIsSubmitting(true)
    setStatus('')

    const formData = new FormData(event.currentTarget)
    const token = formData.get('token')

    try {
      const { response, body } = await apiRequest(
        '/api/totp/enroll/verify',
        {
          method: 'POST',
          body: JSON.stringify({
            token,
          }),
        },
      )

      if (
        response.status === 200 &&
        body.user?.account_status === 'ACTIVE'
      ) {
        setSetupKey('')
        setScreen('login')

        setStatus(
          'Authenticator setup completed successfully. Sign in with your password.',
        )

        return
      }

      if (
        response.status === 401 &&
        body.error?.type ===
          'AUTHENTICATION_REQUIRED'
      ) {
        setSetupKey('')
        setScreen('login')

        setStatus(
          body.error?.message ||
            'Your enrollment session expired. Sign in again.',
        )

        return
      }

      setStatus(
        typeof body.error === 'string'
          ? body.error
          : body.error?.message ||
              'Invalid authenticator code.',
      )
    } catch {
      setStatus(
        'Unable to verify the authenticator.',
      )
    } finally {
      setIsSubmitting(false)
    }
  }

  // -------------------------------------------------------
  // Normal TOTP login
  // -------------------------------------------------------

  const verifyLoginTOTP = async (event) => {
    event.preventDefault()

    setIsSubmitting(true)
    setStatus('')

    const formData = new FormData(event.currentTarget)
    const token = formData.get('token')

    try {
      const { response, body } = await apiRequest(
        '/api/auth/totp',
        {
          method: 'POST',
          body: JSON.stringify({
            token,
          }),
        },
      )

      if (
        response.status === 200 &&
        body.result === 'AUTHENTICATED'
      ) {
        await loadDashboard()
        return
      }

      if (
        response.status === 401 &&
        body.error?.type ===
          'AUTHENTICATION_REQUIRED'
      ) {
        setScreen('login')

        setStatus(
          body.error?.message ||
            'Your sign-in session expired. Sign in again.',
        )

        return
      }

      if (
        response.status === 401 &&
        body.error?.type ===
          'AUTHENTICATION_FAILED'
      ) {
        setStatus(
          body.error?.message ||
            'Invalid verification code.',
        )

        return
      }

      if (
        response.status === 429 &&
        body.error?.type ===
          'TEMPORARILY_RESTRICTED'
      ) {
        const retry =
          body.error?.retry_after_seconds

        setStatus(
          retry
            ? `Too many attempts. Try again in ${retry} seconds.`
            : 'Too many attempts. Try again later.',
        )

        return
      }

      setStatus(
        body.error?.message ||
          'Verification could not be completed.',
      )
    } catch {
      setStatus(
        'Unable to reach the authentication service.',
      )
    } finally {
      setIsSubmitting(false)
    }
  }

  // -------------------------------------------------------
  // Recovery code verification
  // -------------------------------------------------------

  const submitRecoveryCode = async (event) => {
    event.preventDefault()

    setIsSubmitting(true)
    setStatus('')

    const formData = new FormData(event.currentTarget)
    const recoveryCode =
      formData.get('recoveryCode')

    try {
      const { response, body } = await apiRequest(
        '/api/recovery/consume',
        {
          method: 'POST',
          body: JSON.stringify({
            recoveryCode,
          }),
        },
      )

      if (
        response.status === 200 &&
        body.result === 'RECOVERY_AUTHORIZED'
      ) {
        setStatus(
          'Recovery code accepted. Starting replacement authenticator setup.',
        )

        await startRecoveryEnrollment()
        return
      }

      if (
        response.status === 401 &&
        body.error?.type ===
          'AUTHENTICATION_REQUIRED'
      ) {
        setScreen('login')

        setStatus(
          body.error?.message ||
            'Your sign-in session expired. Sign in again.',
        )

        return
      }

      if (
        response.status === 401 &&
        body.error?.type ===
          'AUTHENTICATION_FAILED'
      ) {
        setStatus(
          body.error?.message ||
            'Invalid or already used recovery code.',
        )

        return
      }

      if (
        response.status === 429 &&
        body.error?.type ===
          'TEMPORARILY_RESTRICTED'
      ) {
        const retry =
          body.error?.retry_after_seconds

        setStatus(
          retry
            ? `Too many attempts. Try again in ${retry} seconds.`
            : 'Too many attempts. Try again later.',
        )

        return
      }

      setStatus(
        body.error?.message ||
          'Recovery could not be completed.',
      )
    } catch {
      setStatus(
        'Unable to reach the recovery service.',
      )
    } finally {
      setIsSubmitting(false)
    }
  }

  // -------------------------------------------------------
  // Start replacement authenticator enrollment
  // -------------------------------------------------------

  const startRecoveryEnrollment = async () => {
    try {
      const { response, body } = await apiRequest(
        '/api/recovery/totp/enroll',
        {
          method: 'POST',
          body: JSON.stringify({}),
        },
      )

      if (
        response.status === 201 &&
        typeof body.setupKey === 'string'
      ) {
        setSetupKey(body.setupKey)

        setScreen(
          'recovery-totp-enroll',
        )

        setStatus(
          'Add this new setup key to your authenticator, then enter the generated six-digit code.',
        )

        return
      }

      if (
        response.status === 401 &&
        body.error?.type ===
          'AUTHENTICATION_REQUIRED'
      ) {
        setSetupKey('')
        setScreen('login')

        setStatus(
          body.error?.message ||
            'Your recovery session expired. Sign in again.',
        )

        return
      }

      setStatus(
        body.error?.message ||
          'Unable to start authenticator replacement.',
      )
    } catch {
      setStatus(
        'Unable to start authenticator replacement.',
      )
    }
  }

  // -------------------------------------------------------
  // Verify replacement authenticator
  // -------------------------------------------------------

  const verifyRecoveryEnrollment = async (
    event,
  ) => {
    event.preventDefault()

    setIsSubmitting(true)
    setStatus('')

    const formData =
      new FormData(event.currentTarget)

    const token = formData.get('token')

    try {
      const { response, body } = await apiRequest(
        '/api/recovery/totp/enroll/verify',
        {
          method: 'POST',
          body: JSON.stringify({
            token,
          }),
        },
      )

      if (
        response.status === 200 &&
        body.result ===
          'AUTHENTICATOR_REPLACED'
      ) {
        setSetupKey('')
        setScreen('login')

        setStatus(
          'Authenticator replacement completed. Sign in normally with your password and new authenticator.',
        )

        return
      }

      if (
        response.status === 401 &&
        body.error?.type ===
          'AUTHENTICATION_REQUIRED'
      ) {
        setSetupKey('')
        setScreen('login')

        setStatus(
          body.error?.message ||
            'Your recovery session expired. Sign in again.',
        )

        return
      }

      if (
        response.status === 401 &&
        body.error?.type ===
          'AUTHENTICATION_FAILED'
      ) {
        setStatus(
          body.error?.message ||
            'Invalid verification code.',
        )

        return
      }

      setStatus(
        body.error?.message ||
          'Authenticator replacement could not be completed.',
      )
    } catch {
      setStatus(
        'Unable to verify the replacement authenticator.',
      )
    } finally {
      setIsSubmitting(false)
    }
  }

  // -------------------------------------------------------
  // Dashboard
  // -------------------------------------------------------

  const loadDashboard = async () => {
    try {
      const { response, body } = await apiRequest(
        '/api/dashboard',
        {
          method: 'GET',
        },
      )

      if (
        response.status === 200 &&
        body.success
      ) {
        setDashboard(body.dashboard)
        setScreen('dashboard')
        setStatus(
          'Authentication successful.',
        )

        await loadSessionInfo()

        return
      }

      setDashboard(null)
      setSessionExpiresAt(null)
      setShowSessionWarning(false)
      setScreen('login')

      setStatus(
        body.error?.message ||
          'Your session is not valid. Sign in again.',
      )
    } catch {
      setDashboard(null)
      setSessionExpiresAt(null)
      setShowSessionWarning(false)
      setScreen('login')

      setStatus(
        'Unable to load the dashboard.',
      )
    }
  }

  // -------------------------------------------------------
  // Logout
  // -------------------------------------------------------

  const logout = async () => {
    setIsSubmitting(true)

    try {
      const { response, body } = await apiRequest(
        '/api/session/logout',
        {
          method: 'POST',
          body: JSON.stringify({}),
        },
      )

      if (
        !response.ok &&
        response.status !== 401
      ) {
        setStatus(
          body.error?.message ||
            'Logout could not be completed.',
        )

        return
      }

      setDashboard(null)
      setSetupKey('')
      setSessionExpiresAt(null)
      setShowSessionWarning(false)
      setScreen('login')

      setStatus(
        response.status === 401
          ? 'Your session has already expired. Sign in again.'
          : 'You have signed out.',
      )
    } catch {
      setStatus(
        'Unable to reach the authentication service.',
      )
    } finally {
      setIsSubmitting(false)
    }
  }

  // -------------------------------------------------------
  // Copy setup key
  // -------------------------------------------------------

  const copySetupKey = async () => {
    if (!setupKey) {
      return
    }

    try {
      await navigator.clipboard.writeText(
        setupKey,
      )

      setStatus(
        'Setup key copied. You can paste it into your authenticator.',
      )
    } catch {
      setStatus(
        'Copy was unavailable. Select the setup key and copy it manually.',
      )
    }
  }

  // -------------------------------------------------------
  // Full-session expiry timer
  // -------------------------------------------------------

  useEffect(() => {
    if (
      screen !== 'dashboard' ||
      !sessionExpiresAt
    ) {
      return undefined
    }

    const checkSessionTime = () => {
      const expiresAt =
        new Date(
          sessionExpiresAt,
        ).getTime()

      const remainingMilliseconds =
        expiresAt - Date.now()

      if (
        !Number.isFinite(expiresAt)
      ) {
        setDashboard(null)
        setSessionExpiresAt(null)
        setShowSessionWarning(false)
        setScreen('login')

        setStatus(
          'Unable to verify your session. Sign in again.',
        )

        return
      }

      // Session expired.
      if (
        remainingMilliseconds <= 0
      ) {
        setShowSessionWarning(false)
        setSessionExpiresAt(null)
        setDashboard(null)
        setScreen('login')

        setStatus(
          'Your session expired. Sign in again.',
        )

        return
      }

      // Show warning during final 2 minutes.
      const warningThreshold =
        2 * 60 * 1000

      setShowSessionWarning(
        remainingMilliseconds <=
          warningThreshold,
      )
    }

    checkSessionTime()

    const intervalId =
      window.setInterval(
        checkSessionTime,
        1000,
      )

    return () => {
      window.clearInterval(
        intervalId,
      )
    }
  }, [
    screen,
    sessionExpiresAt,
  ])

  // -------------------------------------------------------
  // Recovery-code screen
  // -------------------------------------------------------

  if (screen === 'recovery') {
    return (
      <main className="app-shell">
        <header className="site-header">
          <span className="brand">
            <span
              className="brand-mark"
              aria-hidden="true"
            >
              S
            </span>

            <span>SecureByte</span>
          </span>

          <span className="environment-label">
            Academic prototype
          </span>
        </header>

        <section
          className="workspace"
          aria-labelledby="page-title"
        >
          <div className="intro-panel">
            <p className="kicker">
              Authenticator recovery
            </p>

            <h1 id="page-title">
              Use one saved recovery code.
            </h1>

            <p className="intro-copy">
              Your password has already been
              verified. Enter one unused recovery
              code to continue with authenticator
              replacement.
            </p>
          </div>

          <div className="auth-panel">
            <div className="panel-heading">
              <h2>Recovery code</h2>

              <p>
                Each recovery code can be used only
                once.
              </p>
            </div>

            <form
              onSubmit={submitRecoveryCode}
            >
              <div className="field-group">
                <label htmlFor="recovery-code">
                  Recovery code
                </label>

                <input
                  id="recovery-code"
                  name="recoveryCode"
                  type="text"
                  autoComplete="off"
                  required
                  autoFocus
                />
              </div>

              <button
                className="primary-button"
                type="submit"
                disabled={isSubmitting}
              >
                {isSubmitting
                  ? 'Checking...'
                  : 'Continue recovery'}
              </button>
            </form>

            <p className="form-footer">
              <button
                type="button"
                className="link-button"
                onClick={() =>
                  navigateTo('login')
                }
              >
                Return to sign in
              </button>
            </p>

            <div
              className="status-region"
              role="status"
              aria-live="polite"
            >
              {status}
            </div>
          </div>
        </section>
      </main>
    )
  }

  // -------------------------------------------------------
  // Recovery replacement TOTP screen
  // -------------------------------------------------------

  if (
    screen ===
    'recovery-totp-enroll'
  ) {
    return (
      <main className="app-shell">
        <header className="site-header">
          <span className="brand">
            <span
              className="brand-mark"
              aria-hidden="true"
            >
              S
            </span>

            <span>SecureByte</span>
          </span>

          <span className="environment-label">
            Academic prototype
          </span>
        </header>

        <section
          className="workspace"
          aria-labelledby="page-title"
        >
          <div className="intro-panel">
            <p className="kicker">
              Authenticator replacement
            </p>

            <h1 id="page-title">
              Configure your new authenticator.
            </h1>

            <p className="intro-copy">
              Add the setup key below to your
              authenticator. Then enter the
              six-digit code generated by the new
              authenticator.
            </p>
          </div>

          <div className="auth-panel">
            <div className="panel-heading">
              <h2>New setup key</h2>

              <p>
                The previous authenticator is no
                longer valid.
              </p>
            </div>

            <div className="field-group">
              <label htmlFor="recovery-setup-key">
                Your new setup key
              </label>

              <div className="copy-row">
                <input
                  id="recovery-setup-key"
                  value={setupKey}
                  readOnly
                />

                <button
                  type="button"
                  className="secondary-button"
                  onClick={copySetupKey}
                >
                  Copy key
                </button>
              </div>
            </div>

            <form
              onSubmit={
                verifyRecoveryEnrollment
              }
            >
              <div className="field-group">
                <label htmlFor="recovery-token">
                  Six-digit authenticator code
                </label>

                <input
                  id="recovery-token"
                  name="token"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6}"
                  maxLength="6"
                  required
                  autoFocus
                />
              </div>

              <button
                className="primary-button"
                type="submit"
                disabled={isSubmitting}
              >
                {isSubmitting
                  ? 'Checking...'
                  : 'Verify new authenticator'}
              </button>
            </form>

            <div
              className="status-region"
              role="status"
              aria-live="polite"
            >
              {status}
            </div>
          </div>
        </section>
      </main>
    )
  }

  // -------------------------------------------------------
  // Normal TOTP enrollment screen
  // -------------------------------------------------------

  if (screen === 'totp-enroll') {
    return (
      <main className="app-shell">
        <header className="site-header">
          <span className="brand">
            <span
              className="brand-mark"
              aria-hidden="true"
            >
              S
            </span>

            <span>SecureByte</span>
          </span>

          <span className="environment-label">
            Academic prototype
          </span>
        </header>

        <section
          className="workspace"
          aria-labelledby="page-title"
        >
          <div className="intro-panel">
            <p className="kicker">
              Authenticator enrollment
            </p>

            <h1 id="page-title">
              Connect your authenticator.
            </h1>

            <p className="intro-copy">
              Copy the setup key into your
              authenticator application. Then enter
              the six-digit code it generates.
            </p>
          </div>

          <div className="auth-panel">
            <div className="panel-heading">
              <p className="kicker">
                Authenticator setup
              </p>

              <h2>Setup key</h2>

              <p>
                QR scanning is optional. You can use
                this text key instead.
              </p>
            </div>

            <div className="field-group">
              <label htmlFor="setup-key">
                Your setup key
              </label>

              <div className="copy-row">
                <input
                  id="setup-key"
                  value={setupKey}
                  readOnly
                  aria-describedby="setup-key-help"
                />

                <button
                  type="button"
                  className="secondary-button"
                  onClick={copySetupKey}
                >
                  Copy key
                </button>
              </div>

              <span
                id="setup-key-help"
                className="field-help"
              >
                Selectable text for keyboard and
                screen-reader users.
              </span>
            </div>

            <form
              onSubmit={verifyEnrollment}
            >
              <div className="field-group">
                <label htmlFor="enrollment-token">
                  Six-digit authenticator code
                </label>

                <input
                  id="enrollment-token"
                  name="token"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6}"
                  maxLength="6"
                  required
                  autoFocus
                />
              </div>

              <button
                className="primary-button"
                type="submit"
                disabled={isSubmitting}
              >
                {isSubmitting
                  ? 'Checking...'
                  : 'Verify authenticator'}
              </button>
            </form>

            <div
              className="status-region"
              role="status"
              aria-live="polite"
            >
              {status}
            </div>
          </div>
        </section>
      </main>
    )
  }

  // -------------------------------------------------------
  // Normal login TOTP screen
  // -------------------------------------------------------

  if (screen === 'totp-login') {
    return (
      <main className="app-shell">
        <header className="site-header">
          <span className="brand">
            <span
              className="brand-mark"
              aria-hidden="true"
            >
              S
            </span>

            <span>SecureByte</span>
          </span>

          <span className="environment-label">
            Academic prototype
          </span>
        </header>

        <section
          className="workspace"
          aria-labelledby="page-title"
        >
          <div className="intro-panel">
            <p className="kicker">
              Step 2 of 2
            </p>

            <h1 id="page-title">
              Verify your authenticator.
            </h1>

            <p className="intro-copy">
              Enter the current six-digit code from
              your authenticator application.
            </p>
          </div>

          <div className="auth-panel">
            <div className="panel-heading">
              <h2>Authenticator code</h2>

              <p>
                Enter or paste the complete
                six-digit code.
              </p>
            </div>

            <form
              onSubmit={verifyLoginTOTP}
            >
              <div className="field-group">
                <label htmlFor="login-token">
                  Six-digit code
                </label>

                <input
                  id="login-token"
                  name="token"
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6}"
                  maxLength="6"
                  required
                  autoFocus
                />
              </div>

              <button
                className="primary-button"
                type="submit"
                disabled={isSubmitting}
              >
                {isSubmitting
                  ? 'Verifying...'
                  : 'Verify and sign in'}
              </button>
            </form>

            <p className="form-footer">
              Cannot use your authenticator?{' '}

              <button
                type="button"
                className="link-button"
                onClick={() => {
                  setStatus(
                    'Enter one unused recovery code.',
                  )

                  setScreen('recovery')
                }}
              >
                Use a recovery code instead
              </button>
            </p>

            <div
              className="status-region"
              role="status"
              aria-live="polite"
            >
              {status}
            </div>
          </div>
        </section>
      </main>
    )
  }

  // -------------------------------------------------------
  // Dashboard
  // -------------------------------------------------------

  if (screen === 'dashboard') {
    return (
      <main className="app-shell">
        <header className="site-header">
          <span className="brand">
            <span
              className="brand-mark"
              aria-hidden="true"
            >
              S
            </span>

            <span>SecureByte</span>
          </span>

          <button
            type="button"
            className="secondary-button"
            onClick={logout}
            disabled={isSubmitting}
          >
            {isSubmitting
              ? 'Signing out...'
              : 'Logout'}
          </button>
        </header>

        <section
          className="workspace"
          aria-labelledby="page-title"
        >
          <div className="intro-panel">
            <p className="kicker">
              Protected application
            </p>

            <h1 id="page-title">
              Welcome, {dashboard?.username}.
            </h1>

            <p className="intro-copy">
              {dashboard?.message}
            </p>
          </div>

          <div className="auth-panel">
            <div className="panel-heading">
              <h2>
                Authentication complete
              </h2>

              <p>
                Password and authenticator
                verification have both succeeded.
              </p>
            </div>

            {showSessionWarning && (
              <div
                className="session-warning"
                role="alert"
                aria-live="assertive"
              >
                <p>
                  Your session will expire soon.
                </p>

                <button
                  type="button"
                  className="primary-button"
                  onClick={
                    extendCurrentSession
                  }
                  disabled={
                    isExtendingSession
                  }
                >
                  {isExtendingSession
                    ? 'Extending...'
                    : 'Continue session'}
                </button>
              </div>
            )}

            <div
              className="status-region"
              role="status"
              aria-live="polite"
            >
              {status}
            </div>
          </div>
        </section>
      </main>
    )
  }

  // -------------------------------------------------------
  // Login / registration
  // -------------------------------------------------------

  const screenContent = {
    login: {
      eyebrow: 'Step 1 of 2',
      title: 'Sign in to SecureByte',
      description:
        'Use your password first. The next step will ask for your authenticator code.',
      action:
        'Continue to verification',
      footer:
        'New to SecureByte?',
      footerAction:
        'Create an account',
      footerTarget:
        'register',
    },

    register: {
      eyebrow:
        'Create your account',
      title:
        'Start with SecureByte',
      description:
        'Create an account with a strong password, then enroll your authenticator.',
      action:
        'Create account',
      footer:
        'Already have an account?',
      footerAction:
        'Return to sign in',
      footerTarget:
        'login',
    },
  }

  const currentScreen =
    screenContent[screen] ||
    screenContent.login

  return (
    <main className="app-shell">
      <header className="site-header">
        <span className="brand">
          <span
            className="brand-mark"
            aria-hidden="true"
          >
            S
          </span>

          <span>SecureByte</span>
        </span>

        <span className="environment-label">
          Academic prototype
        </span>
      </header>

      <section
        className="workspace"
        aria-labelledby="page-title"
      >
        <div className="intro-panel">
          <p className="kicker">
            Private access, clearly staged
          </p>

          <h1 id="page-title">
            Authentication that keeps the
            next step visible.
          </h1>

          <p className="intro-copy">
            SecureByte protects the dashboard
            with a password and a time-based
            authenticator. Each step stays
            restricted until the server
            confirms it.
          </p>

          <div
            className="trust-list"
            aria-label="Security guarantees"
          >
            <span>
              Server-controlled sessions
            </span>

            <span>
              Accessible text setup
            </span>

            <span>
              No browser-only access
            </span>
          </div>
        </div>

        <div className="auth-panel">
          <div className="panel-heading">
            <p className="kicker">
              {currentScreen.eyebrow}
            </p>

            <h2>
              {currentScreen.title}
            </h2>

            <p>
              {currentScreen.description}
            </p>
          </div>

          <form onSubmit={submitAuth}>
            <div className="field-group">
              <label htmlFor="username">
                Username
              </label>

              <input
                id="username"
                name="username"
                type="text"
                autoComplete="username"
                required
              />
            </div>

            <div className="field-group">
              <label htmlFor="password">
                Password
              </label>

              <div className="input-with-action">
                <input
                  id="password"
                  name="password"
                  type={
                    showPassword
                      ? 'text'
                      : 'password'
                  }
                  autoComplete={
                    screen === 'register'
                      ? 'new-password'
                      : 'current-password'
                  }
                  minLength="15"
                  maxLength="128"
                  required
                  aria-describedby="password-help"
                />

                <button
                  type="button"
                  className="text-action"
                  aria-pressed={
                    showPassword
                  }
                  onClick={() =>
                    setShowPassword(
                      (visible) =>
                        !visible,
                    )
                  }
                >
                  {showPassword
                    ? 'Hide'
                    : 'Show'}
                </button>
              </div>

              <span
                id="password-help"
                className="field-help"
              >
                Use 15 to 128 characters.
                Paste and password-manager
                autofill are supported.
              </span>
            </div>

            <button
              className="primary-button"
              type="submit"
              disabled={isSubmitting}
            >
              {isSubmitting
                ? 'Checking...'
                : currentScreen.action}
            </button>
          </form>

          <p className="form-footer">
            {currentScreen.footer}{' '}

            <button
              type="button"
              className="link-button"
              onClick={() =>
                navigateTo(
                  currentScreen.footerTarget,
                )
              }
            >
              {currentScreen.footerAction}
            </button>
          </p>

          <div
            className="status-region"
            role="status"
            aria-live="polite"
          >
            {status}
          </div>
        </div>
      </section>

      <footer className="site-footer">
        <span>SecureByte</span>

        <span>
          Multi-factor authentication prototype
        </span>
      </footer>
    </main>
  )
}

export default App