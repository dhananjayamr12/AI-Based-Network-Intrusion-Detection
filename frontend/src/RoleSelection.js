import React, { useState } from "react";
import "./RoleSelection.css";

function RoleSelection({ user, onContinue, onBack }) {
  const [selectedRole, setSelectedRole] = useState(null);

  const roles = [
    {
      id: "admin",
      icon: "🛡️",
      title: "Administrator",
      description:
        "Manage users, network monitoring, intrusion detection, alerts and reports.",
      permissions: [
        "Complete dashboard access",
        "User management",
        "Security event management",
        "System configuration",
      ],
    },
    {
      id: "analyst",
      icon: "🔍",
      title: "Security Analyst",
      description:
        "Monitor network activity, investigate threats and analyse suspicious IP addresses.",
      permissions: [
        "Network monitoring",
        "Intrusion investigation",
        "IP analysis",
        "Alert management",
      ],
    },
    {
      id: "viewer",
      icon: "📊",
      title: "Viewer",
      description:
        "View security dashboards, network statistics and analytical reports.",
      permissions: [
        "Dashboard access",
        "View security alerts",
        "View network statistics",
        "View reports",
      ],
    },
  ];

  const handleContinue = () => {
    if (!selectedRole) return;

    onContinue(selectedRole, {
      ...user,
      role: selectedRole,
    });
  };

  return (
    <main className="role-page">
      <section className="role-container">

        <button
          type="button"
          className="role-back"
          onClick={onBack}
        >
          ← Back
        </button>

        <div className="role-logo">🛡️</div>

        <h1>Select Your Role</h1>

        <p>
          Welcome, {user?.name || user?.username || "User"}.
          Choose your platform experience.
        </p>

        <div className="role-options">

          {roles.map((role) => (
            <button
              type="button"
              key={role.id}
              className={`role-option ${
                selectedRole === role.id ? "selected" : ""
              }`}
              onClick={() => setSelectedRole(role.id)}
              aria-pressed={selectedRole === role.id}
            >

              <span className="role-icon">
                {role.icon}
              </span>

              <span className="role-information">

                <strong>{role.title}</strong>

                <small>{role.description}</small>

                <span className="role-permissions">
                  {role.permissions.map((permission) => (
                    <span key={permission}>
                      ✓ {permission}
                    </span>
                  ))}
                </span>

              </span>

              <span className="role-radio">
                {selectedRole === role.id ? "●" : "○"}
              </span>

            </button>
          ))}

        </div>

        <button
          type="button"
          className="role-continue"
          onClick={handleContinue}
          disabled={!selectedRole}
        >
          Continue to Platform →
        </button>

        <p className="role-security-note">
          Role selection is currently part of the prototype.
          Backend authorization will determine actual permissions.
        </p>

      </section>
    </main>
  );
}

export default RoleSelection;