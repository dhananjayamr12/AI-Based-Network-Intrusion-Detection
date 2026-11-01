import React, { useState } from "react";
import "./AdminLogin.css";

function AdminLogin({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");

  function handleSubmit(event) {
  event.preventDefault();

  const ADMIN_USERNAME = "dhanumr";
  const ADMIN_PASSWORD = "dmr@1214";

  if (
    username.trim() === ADMIN_USERNAME &&
    password === ADMIN_PASSWORD
  ) {
    setError("");
    onLogin();
  } else {
    setError("You are not our admin. Go, man! 😎");
    setPassword("");
  }
}

  return (
    <main className="login-page">
      <section className="login-brand-panel">
        <div className="login-brand-content">
          <div className="login-shield">🛡</div>

          <h1>Sentinel AI</h1>

          <p className="login-brand-subtitle">
            Network Security Intelligence
          </p>

          <div className="login-security-graphic">
            <div className="security-ring ring-one"></div>
            <div className="security-ring ring-two"></div>
            <div className="security-center">AI</div>
          </div>

          <h2>Protect. Monitor. Detect.</h2>

          <p className="login-brand-description">
            A centralized platform for network monitoring
            and AI-assisted traffic classification.
          </p>

          <div className="login-feature-list">
            <span>✓ Network Monitoring</span>
            <span>✓ AI Traffic Classification</span>
            <span>✓ Security Dashboard</span>
          </div>
        </div>

        <p className="login-brand-footer">
          SENTINEL AI · NETWORK SECURITY PLATFORM
        </p>
      </section>

      <section className="login-form-panel">
        <div className="login-form-container">
          <div className="login-form-icon">🔐</div>

          <p className="login-eyebrow">ADMINISTRATOR ACCESS</p>

          <h2>Welcome back</h2>

          <p className="login-description">
            Sign in to access your security dashboard.
          </p>

          <form onSubmit={handleSubmit}>
            <div className="login-input-group">
              <label htmlFor="admin-username">
                Username
              </label>

              <input
                id="admin-username"
                type="text"
                placeholder="Enter your username"
                value={username}
                onChange={(event) =>
                  setUsername(event.target.value)
                }
                autoComplete="username"
              />
            </div>

            <div className="login-input-group">
              <label htmlFor="admin-password">
                Password
              </label>

              <div className="password-input-wrapper">
                <input
                  id="admin-password"
                  type={showPassword ? "text" : "password"}
                  placeholder="Enter your password"
                  value={password}
                  onChange={(event) =>
                    setPassword(event.target.value)
                  }
                  autoComplete="current-password"
                />

                <button
                  type="button"
                  className="password-toggle"
                  onClick={() =>
                    setShowPassword((previous) => !previous)
                  }
                  aria-label={
                    showPassword
                      ? "Hide password"
                      : "Show password"
                  }
                >
                  {showPassword ? "Hide" : "Show"}
                </button>
              </div>
            </div>

            {error && (
              <div className="login-error" role="alert">
                {error}
              </div>
            )}

            <button
              type="submit"
              className="login-submit-button"
            >
              Sign In to Dashboard
              <span>→</span>
            </button>
          </form>

          <div className="login-security-note">
            <span>🔒</span>
            <p>
              Authorized administrators only.
              <br />
              Access is subject to authentication.
            </p>
          </div>

          <p className="login-version">
            Sentinel AI · Development Version 1.0
          </p>
        </div>
      </section>
    </main>
  );
}

export default AdminLogin;