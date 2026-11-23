import React, { useState } from "react";
import "./RegistrationPage.css";

function RegistrationPage({ onRegister, onLogin, onBack }) {
  const [form, setForm] = useState({
    name: "",
    email: "",
    username: "",
    password: "",
    confirmPassword: "",
  });

  const [error, setError] = useState("");

  function handleChange(e) {
    setForm({ ...form, [e.target.name]: e.target.value });
  }

  function handleSubmit(e) {
    e.preventDefault();
    setError("");

    if (Object.values(form).some((value) => !value.trim())) {
      setError("Please complete all fields.");
      return;
    }

    if (!/^\S+@\S+\.\S+$/.test(form.email)) {
      setError("Enter a valid email address.");
      return;
    }

    if (form.password.length < 8) {
      setError("Password must contain at least 8 characters.");
      return;
    }

    if (form.password !== form.confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    onRegister({
      name: form.name,
      email: form.email,
      username: form.username,
      password: form.password,
    });
  }

  return (
    <main className="registration-page">
      <section className="registration-card">
        <button className="registration-back" onClick={onBack}>
          ← Back to Home
        </button>

        <div className="registration-logo">🛡️</div>

        <h1>Create Your Account</h1>
        <p>Join Sentinel AI Network Security Platform</p>

        <form onSubmit={handleSubmit}>
          <label>Full Name</label>
          <input
            name="name"
            placeholder="Enter your full name"
            value={form.name}
            onChange={handleChange}
          />

          <label>Email Address</label>
          <input
            name="email"
            type="email"
            placeholder="Enter your email"
            value={form.email}
            onChange={handleChange}
          />

          <label>Username</label>
          <input
            name="username"
            placeholder="Choose a username"
            value={form.username}
            onChange={handleChange}
          />

          <label>Password</label>
          <input
            name="password"
            type="password"
            placeholder="Minimum 8 characters"
            value={form.password}
            onChange={handleChange}
          />

          <label>Confirm Password</label>
          <input
            name="confirmPassword"
            type="password"
            placeholder="Re-enter your password"
            value={form.confirmPassword}
            onChange={handleChange}
          />

          {error && <div className="registration-error">{error}</div>}

          <button type="submit" className="registration-submit">
            Create Account →
          </button>
        </form>

        <div className="registration-login">
          Already have an account?
          <button onClick={onLogin}>Sign In</button>
        </div>
      </section>
    </main>
  );
}

export default RegistrationPage;