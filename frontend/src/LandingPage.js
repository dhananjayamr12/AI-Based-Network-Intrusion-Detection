import React from "react";
import "./LandingPage.css";

function LandingPage({ onLogin, onRegister }) {
  return (
    <div className="landing-page">

      {/* NAVIGATION */}
      <nav className="landing-navbar">
        <div className="landing-brand">
          <span className="landing-logo">🛡</span>
          <div>
            <h2>Sentinel AI</h2>
            <p>NETWORK SECURITY PLATFORM</p>
          </div>
        </div>

        <div className="landing-nav-links">
          <a href="#home">Home</a>
          <a href="#features">Features</a>
          <a href="#about">About</a>
          <a href="#contact">Contact</a>
        </div>

        <div className="landing-nav-actions">
          <button onClick={onLogin} className="landing-login">
            Login
          </button>
          <button onClick={onRegister} className="landing-register">
            Get Started
          </button>
        </div>
      </nav>

      {/* HERO SECTION */}
      <section className="landing-hero" id="home">

        <div className="hero-content">

          <div className="hero-badge">
            ● AI-POWERED NETWORK PROTECTION
          </div>

          <h1>
            Smarter Networks,
            <span> Safer Tomorrow.</span>
          </h1>

          <p>
            Protect your digital infrastructure with intelligent
            network monitoring, AI-powered intrusion detection
            and real-time security insights.
          </p>

          <div className="hero-buttons">
            <button onClick={onRegister} className="hero-primary">
              Get Started →
            </button>

            <a href="#features" className="hero-secondary">
              Explore Features
            </a>
          </div>

          <div className="hero-highlights">
            <div>
              <strong>24/7</strong>
              <span>Network Monitoring</span>
            </div>

            <div>
              <strong>AI</strong>
              <span>Threat Detection</span>
            </div>

            <div>
              <strong>LIVE</strong>
              <span>Security Insights</span>
            </div>
          </div>

        </div>

        <div className="hero-visual">
          <div className="security-orbit">
            <div className="orbit-ring"></div>
            <div className="orbit-ring orbit-ring-two"></div>

            <div className="security-shield">
              🛡️
              <span>SECURE</span>
            </div>

            <div className="orbit-node node-one">AI</div>
            <div className="orbit-node node-two">✓</div>
            <div className="orbit-node node-three">●</div>
          </div>

          <div className="hero-status-card">
            <span className="status-dot"></span>
            Security Monitoring Active
          </div>
        </div>

      </section>

      {/* FEATURES */}
      <section className="landing-features" id="features">

        <div className="landing-section-heading">
          <span>OUR CAPABILITIES</span>
          <h2>Intelligent Security. Complete Visibility.</h2>
          <p>
            Everything you need to monitor, detect and analyze
            network security threats.
          </p>
        </div>

        <div className="feature-grid">

          <div className="feature-card">
            <div className="feature-icon">📡</div>
            <h3>Real-Time Monitoring</h3>
            <p>
              Monitor network activity and traffic statistics
              through a centralized dashboard.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">🤖</div>
            <h3>AI-Powered Detection</h3>
            <p>
              Analyze network-flow features using machine
              learning for experimental intrusion classification.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">🚨</div>
            <h3>Threat Detection</h3>
            <p>
              Review potential security events, severity
              classifications and investigation status.
            </p>
          </div>

          <div className="feature-card">
            <div className="feature-icon">📊</div>
            <h3>Reports & Analytics</h3>
            <p>
              Understand prediction history and security
              activity through analytical reports.
            </p>
          </div>

        </div>
      </section>

      {/* ABOUT */}
      <section className="landing-about" id="about">
        <div>
          <span className="section-label">ABOUT SENTINEL AI</span>

          <h2>
            Security Intelligence
            <span> Built for Better Visibility.</span>
          </h2>

          <p>
            Sentinel AI is an AI-based network intrusion detection
            and real-time monitoring platform designed to analyze
            network-flow information, identify potential threats
            and present security insights through a centralized
            dashboard.
          </p>
        </div>
      </section>

      {/* CONTACT */}
      <section className="landing-contact" id="contact">
        <h2>Ready to Explore Sentinel AI?</h2>

        <p>
          Start exploring intelligent network monitoring
          and security analytics.
        </p>

        <button onClick={onRegister}>
          Get Started →
        </button>
      </section>

      {/* FOOTER */}
      <footer className="landing-footer">
        <div className="landing-brand">
          <span className="landing-logo">🛡</span>
          <h2>Sentinel AI</h2>
        </div>

        <p>
          AI-Based Network Intrusion Detection and
          Real-Time Monitoring Platform.
        </p>

        <span>© 2026 Sentinel AI. All rights reserved.</span>
      </footer>

    </div>
  );
}

export default LandingPage;