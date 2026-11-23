import React, { useEffect, useState } from "react";
import AdminLogin from "./AdminLogin";
import LandingPage from "./LandingPage";
import RegistrationPage from "./RegistrationPage";
import RoleSelection from "./RoleSelection";
import IPAnalysis from "./IPAnalysis";
import ReportsAnalytics from "./ReportsAnalytics";
import {
  IntrusionDetection,
  NetworkMonitoring,
  SecurityAlerts,
} from "./ModulePages";
import "./App.css";

import {
  ResponsiveContainer,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  PieChart,
  Pie,
  Cell,
} from "recharts";

const API_URL = "http://127.0.0.1:8000";

function App() {
  const [apiStatus, setApiStatus] = useState("Checking...");
  const [modelLoaded, setModelLoaded] = useState(false);
  const [prediction, setPrediction] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [predictionHistory, setPredictionHistory] = useState([]);
const [securityEvents, setSecurityEvents] = useState([]);
 const [totalPredictions, setTotalPredictions] = useState(0);
 const [totalAttacks, setTotalAttacks] = useState(0);
 const [predictionTrend, setPredictionTrend] = useState([]);
 const [totalDetectionEvents, setTotalDetectionEvents] = useState(0);
 const [theme, setTheme] = useState("dark");

function toggleTheme() {
  const newTheme = theme === "dark" ? "light" : "dark";

  setTheme(newTheme);
  localStorage.setItem("sentinel-theme", newTheme);
}
// Live network monitoring state
const [networkStats, setNetworkStats] = useState(null);
const [networkStatus, setNetworkStatus] = useState("Connecting...");
const [networkError, setNetworkError] = useState("");
// PCAP analysis state
const [pcapResult, setPcapResult] = useState(null);
const [pcapLoading, setPcapLoading] = useState(false);
const [pcapError, setPcapError] = useState("");
const [isLoggedIn, setIsLoggedIn] = useState(false);
const [currentPage, setCurrentPage] = useState("landing");
const [registeredUser, setRegisteredUser] = useState(null);
const [currentUser, setCurrentUser] = useState(null);
const [selectedRole, setSelectedRole] = useState("admin");
const [activeModule, setActiveModule] = useState("dashboard");
function handleLogout() {
  setIsLoggedIn(false);
  setCurrentPage("landing");
  setCurrentUser(null);
  setSelectedRole("admin");
  setActiveModule("dashboard");
  setPrediction(null);
  setError("");
}
const [networkRates, setNetworkRates] = useState({
  downloadKBps: 0,
  uploadKBps: 0,
  incomingPacketsPerSec: 0,
  outgoingPacketsPerSec: 0,
});
const totalNormal = totalPredictions - totalAttacks;

const chartData = [
  {
    name: "Normal",
    count: totalNormal,
  },
  {
    name: "Attacks",
    count: totalAttacks,
  },
  {
    name: "Total",
    count: totalPredictions,
  },
];
const [trafficInput, setTrafficInput] = useState({
  duration: "0.5",
  src_bytes: "200",
  dst_bytes: "500",
  packets: "500",
  failed_connections: "15",
});

useEffect(() => {
  document.body.setAttribute("data-theme", theme);
}, [theme]);
// Load dashboard data when the component starts
useEffect(() => {
  checkAPI();
  fetchNetworkStats();
  fetchPredictionHistory();
  fetchDashboardStats();
  fetchSecurityEvents();

  // Refresh network statistics every 3 seconds
  const networkInterval = setInterval(() => {
    fetchNetworkStats();
  }, 3000);

  return () => {
    clearInterval(networkInterval);
  };
}, []);


// Fetch persistent prediction history from PostgreSQL
async function fetchPredictionHistory() {
  try {
    const response = await fetch(`${API_URL}/predictions?limit=20`);

    if (!response.ok) {
      throw new Error("Unable to fetch prediction history");
    }

    const data = await response.json();

   const history = data.predictions.map((record) => ({
  id: record.prediction_id,
  traffic_id: record.traffic_id,
  timestamp: new Date(record.created_at).toLocaleString(),
  prediction:
    record.predicted_label === "ATTACK"
      ? "ATTACK (synthetic)"
      : "NORMAL (synthetic)",
  prediction_code: record.predicted_label === "ATTACK" ? 1 : 0,
  attack_probability: record.attack_probability,
  normal_probability: record.normal_probability,
  src_bytes: record.src_bytes,
  dst_bytes: record.dst_bytes,
  packets: record.packets,
}));

    setPredictionHistory(history);

    // Prepare chronological prediction trend data
    const sortedPredictions = [...data.predictions].reverse();

    const trendData = sortedPredictions.map((item) => ({
      time: new Date(item.created_at).toLocaleString("en-IN", {
        day: "2-digit",
        month: "short",
        hour: "2-digit",
        minute: "2-digit",
      }),
      attack: item.predicted_label === "ATTACK" ? 1 : 0,
      normal: item.predicted_label === "NORMAL" ? 1 : 0,
    }));

    setPredictionTrend(trendData);

  } catch (err) {
    console.error("Prediction history error:", err);
  }
}



// Fetch dashboard statistics from PostgreSQL
async function fetchDashboardStats() {
  try {
    const response = await fetch(`${API_URL}/dashboard/stats`);

    if (!response.ok) {
      throw new Error("Unable to fetch dashboard statistics");
    }

    const data = await response.json();
    const stats = data.statistics;

    setTotalPredictions(data.statistics.total_predictions || 0);
setTotalAttacks(data.statistics.attack_predictions || 0);
setTotalDetectionEvents(data.statistics.total_detection_events || 0);
  } catch (err) {
    console.error("Dashboard statistics error:", err);
  }
}


// Fetch security events from PostgreSQL
async function fetchSecurityEvents() {
  try {
    const response = await fetch(`${API_URL}/security/events?limit=20`);

    if (!response.ok) {
      throw new Error("Unable to fetch security events");
    }

    const data = await response.json();

    setSecurityEvents(data.events);
  } catch (err) {
    console.error("Security events error:", err);
  }
}
// Update security event status in PostgreSQL
async function updateSecurityEventStatus(eventId, newStatus) {
  try {
    const response = await fetch(
      `${API_URL}/security/events/${eventId}?status=${encodeURIComponent(newStatus)}`,
      {
        method: "PATCH",
      }
    );

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Unable to update security event");
    }

    // Refresh security events after successful update
    await fetchSecurityEvents();

    console.log("Security event updated:", data.message);

  } catch (err) {
    console.error("Status update error:", err);
    alert(err.message);
  }
}
  // Check FastAPI backend and AI model status
  async function checkAPI() {
    try {
      const response = await fetch(`${API_URL}/health`);

      if (!response.ok) {
        throw new Error("API health check failed");
      }

      const data = await response.json();

      setApiStatus("Connected");
      setModelLoaded(data.model_loaded);
    } catch (err) {
      setApiStatus("Disconnected");
      setModelLoaded(false);
    }
  }

  // Fetch actual network interface statistics
  async function fetchNetworkStats() {
    try {
      const response = await fetch(`${API_URL}/network/stats`);

      if (!response.ok) {
        throw new Error("Unable to fetch network statistics");
      }

      const data = await response.json();

      // Select the actual Wi-Fi interface
      const wifi = data.interfaces.find(
        (item) => item.interface.toLowerCase() === "wi-fi"
      );

      if (!wifi) {
        throw new Error("Wi-Fi interface not found");
      }

      const currentTime = Date.now();

      setNetworkStats((previous) => {
        // Calculate speeds using two successive readings
        if (previous && previous.wifi) {
          const elapsedSeconds =
            (currentTime - previous.sampleTime) / 1000;

          if (elapsedSeconds > 0) {
            setNetworkRates({
              downloadKBps:
                Math.max(
                  0,
                  wifi.bytes_received -
                    previous.wifi.bytes_received
                ) /
                elapsedSeconds /
                1024,

              uploadKBps:
                Math.max(
                  0,
                  wifi.bytes_sent - previous.wifi.bytes_sent
                ) /
                elapsedSeconds /
                1024,

              incomingPacketsPerSec:
                Math.max(
                  0,
                  wifi.packets_received -
                    previous.wifi.packets_received
                ) / elapsedSeconds,

              outgoingPacketsPerSec:
                Math.max(
                  0,
                  wifi.packets_sent - previous.wifi.packets_sent
                ) / elapsedSeconds,
            });
          }
        }


        // Store the current reading for the next calculation
        return {
          wifi,
          sampleTime: currentTime,
        };
      });

      setNetworkStatus("Monitoring");
      setNetworkError("");
    } catch (err) {
      setNetworkStatus("Unavailable");
      setNetworkError(err.message);
    }
  }

  // Upload and analyze offline PCAP files
  // Upload and analyze offline PCAP files
  async function analyzePcap(file) {
    setPcapLoading(true);
    setPcapError("");
    setPcapResult(null);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch(`${API_URL}/pcap/analyze`, {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "PCAP analysis failed.");
      }

      setPcapResult(data);
    } catch (err) {
      setPcapError(err.message);
    } finally {
      setPcapLoading(false);
    }
  }

  // Submit traffic features to the experimental AI model
  async function testPrediction() {
    setLoading(true);
    setError("");
    setPrediction(null);

    try {
      const response = await fetch(`${API_URL}/predict`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          duration: Number(trafficInput.duration),
          src_bytes: Number(trafficInput.src_bytes),
          dst_bytes: Number(trafficInput.dst_bytes),
          packets: Number(trafficInput.packets),
          failed_connections: Number(
            trafficInput.failed_connections
          ),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Prediction request failed"
        );
      }

      setPrediction(data);

      // Refresh prediction history from PostgreSQL
 await fetchPredictionHistory();

     // Refresh statistics from PostgreSQL
 await fetchDashboardStats();
 await fetchSecurityEvents();
    } catch (err) {
      setError(
        "Unable to obtain a prediction. Check that the FastAPI server is running."
      );
    } finally {
      setLoading(false);
    }
  }
  const isAttack =
    prediction?.prediction_code === 1;

 // LANDING PAGE
if (!isLoggedIn && currentPage === "landing") {
  return (
    <LandingPage
      onLogin={() => setCurrentPage("login")}
      onRegister={() => setCurrentPage("register")}
    />
  );
}

// REGISTRATION PAGE
if (!isLoggedIn && currentPage === "register") {
  return (
    <RegistrationPage
      onRegister={(user) => {
        setRegisteredUser(user);
        setCurrentUser(user);
        setCurrentPage("role-selection");
      }}
      onLogin={() => setCurrentPage("login")}
      onBack={() => setCurrentPage("landing")}
    />
  );
}

// LOGIN PAGE
if (!isLoggedIn && currentPage === "login") {
  return (
    <AdminLogin
      onLogin={() => {
        const adminUser = {
          name: "Administrator",
          username: "dhanumr",
        };

        setCurrentUser(adminUser);
        setCurrentPage("role-selection");
      }}
    />
  );
}

// ROLE SELECTION PAGE
if (!isLoggedIn && currentPage === "role-selection") {
  return (
    <RoleSelection
      user={currentUser || registeredUser}
      onBack={() => {
        setCurrentPage(
          registeredUser ? "register" : "login"
        );
      }}
      onContinue={(role, user) => {
        setSelectedRole(role);
        setCurrentUser(user);
    setIsLoggedIn(true);
setCurrentPage("dashboard");
setActiveModule("dashboard");
      }}
    />
  );
}

// FALLBACK
if (!isLoggedIn) {
  return (
    <LandingPage
      onLogin={() => setCurrentPage("login")}
      onRegister={() => setCurrentPage("register")}
    />
  );
}

const predictionDistribution = [
  {
    name: "Normal",
    value: totalPredictions - totalAttacks,
  },
  {
    name: "Attack",
    value: totalAttacks,
  },
];

const severityData = [
  { name: "Critical", value: securityEvents.filter(e => e.severity === "CRITICAL").length },
  { name: "High", value: securityEvents.filter(e => e.severity === "HIGH").length },
  { name: "Medium", value: securityEvents.filter(e => e.severity === "MEDIUM").length },
  { name: "Low", value: securityEvents.filter(e => e.severity === "LOW").length },
  { name: "Unclassified", value: securityEvents.filter(e => !e.severity || e.severity === "UNCLASSIFIED").length },
];

return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">🛡</div>
          <div>
            <h2>Sentinel AI</h2>
            <p>Network Security</p>
          </div>
        </div>

        <div className="nav-label">MAIN MENU</div>

<div
  className={`nav-item ${activeModule === "dashboard" ? "active" : ""}`}
  onClick={() => setActiveModule("dashboard")}
>
  ▦ Dashboard
</div>

<div
  className={`nav-item ${activeModule === "intrusion" ? "active" : ""}`}
  onClick={() => setActiveModule("intrusion")}
>
  ◉ Intrusion Detection
</div>

<div
  className={`nav-item ${activeModule === "monitoring" ? "active" : ""}`}
  onClick={() => setActiveModule("monitoring")}
>
  ⌁ Network Monitoring
</div>

<div
  className={`nav-item ${activeModule === "alerts" ? "active" : ""}`}
  onClick={() => setActiveModule("alerts")}
>
  ⚑ Security Alerts
</div>

<div
  className={`nav-item ${activeModule === "ip-analysis" ? "active" : ""}`}
  onClick={() => setActiveModule("ip-analysis")}
>
  🌐 IP Analysis
</div>

<div
  className={`nav-item ${activeModule === "reports" ? "active" : ""}`}
  onClick={() => setActiveModule("reports")}
>
  📊 Reports & Analytics
</div>

        <div className="sidebar-bottom">
          <div className="status-dot" />
          <div>
            <strong>Development Mode</strong>
            <p>Synthetic data environment</p>
          </div>
        </div>
      </aside>
<div className="sidebar-logout">
  <button
    type="button"
    className="logout-button"
    onClick={handleLogout}
  >
    <span>↪</span> Logout
  </button>
</div>

      <main className="main-content">
  {activeModule === "ip-analysis" ? (
    <IPAnalysis />
  ) : activeModule === "reports" ? (
    <ReportsAnalytics />
  ) : activeModule === "intrusion" ? (
    <IntrusionDetection
      predictionHistory={predictionHistory}
    />
  ) : activeModule === "monitoring" ? (
    <NetworkMonitoring
  networkStats={networkStats?.wifi}
  networkRates={networkRates}
  networkStatus={networkStatus}
  networkError={networkError}
  onAnalyzePcap={analyzePcap}
  pcapResult={pcapResult}
  pcapLoading={pcapLoading}
  pcapError={pcapError}
/>
  ) : activeModule === "alerts" ? (
    <SecurityAlerts
      securityEvents={securityEvents}
      onUpdateEventStatus={updateSecurityEventStatus}
      role={selectedRole}
    />
  ) : (
    <>
        <header className="topbar">
          <div>
            <p className="eyebrow">SECURITY OPERATIONS CENTER</p>
            <h1>Network Security Dashboard</h1>
            <p className="subtitle">
              AI-powered network traffic classification and monitoring
            </p>
          </div>
          <button
  className="theme-toggle"
  onClick={toggleTheme}
  type="button"
>
  {theme === "dark" ? "☀️ Light Mode" : "🌙 Dark Mode"}
</button>

          <button className="refresh-button" onClick={checkAPI}>
            ↻ Refresh Status
          </button>
        </header>
        <section className="network-monitor-section">
          <div className="section-heading">
            <div>
              <p className="eyebrow">LIVE NETWORK MONITOR</p>
              <h2>Wi-Fi Traffic Activity</h2>
              <p className="subtitle">
                Actual system network counters · Refreshes every 3 seconds
              </p>
            </div>

            <span
              className={`network-status-badge ${
                networkStatus === "Monitoring" ? "online" : "offline"
              }`}
            >
              ● {networkStatus}
            </span>
          </div>

          {networkError && (
            <p className="network-error">{networkError}</p>
          )}

          <div className="network-monitor-grid">
            <div className="network-monitor-card">
              <span className="network-monitor-label">↓ Download Speed</span>
              <h3>{networkRates.downloadKBps.toFixed(2)} <small>KB/s</small></h3>
            </div>

            <div className="network-monitor-card">
              <span className="network-monitor-label">↑ Upload Speed</span>
              <h3>{networkRates.uploadKBps.toFixed(2)} <small>KB/s</small></h3>
            </div>

            <div className="network-monitor-card">
              <span className="network-monitor-label">Incoming Packets</span>
              <h3>{networkRates.incomingPacketsPerSec.toFixed(0)} <small>packets/s</small></h3>
            </div>

            <div className="network-monitor-card">
              <span className="network-monitor-label">Outgoing Packets</span>
              <h3>{networkRates.outgoingPacketsPerSec.toFixed(0)} <small>packets/s</small></h3>
            </div>
          </div>

          <p className="network-monitor-note">
            These figures represent Wi-Fi interface activity. They do not
            independently indicate an attack or represent AI detection results.
          </p>
        </section>
        <section className="notice">
          <span>ⓘ</span>
          <p>
            <strong>Development environment:</strong> The current model uses
            synthetic traffic records. Predictions are experimental and have
            not been validated on real network traffic.
          </p>
        </section>

        {/* DASHBOARD STATISTICS */}
<section className="stats-grid">

<div className="stat-card">
  <div className="stat-top">
    <span>TOTAL DETECTION EVENTS</span>
    <span className="stat-icon orange">🚨</span>
  </div>
  <h2>{totalDetectionEvents}</h2>
  <p>Detection events stored in PostgreSQL</p>
</div>


  {/* Total Predictions */}
  <div className="stat-card">
    <div className="stat-top">
      <span>TOTAL PREDICTIONS</span>
      <span className="stat-icon blue">📊</span>
    </div>
    <h2>{totalPredictions}</h2>
    <p>Total predictions stored in PostgreSQL</p>
  </div>

  {/* Attack Classifications */}
  <div className="stat-card">
    <div className="stat-top">
      <span>ATTACK CLASSIFICATIONS</span>
      <span className="stat-icon orange">⚠</span>
    </div>
    <h2>{totalAttacks}</h2>
    <p>Records classified as potential attacks</p>
  </div>

  {/* Normal Classifications */}
  <div className="stat-card">
    <div className="stat-top">
      <span>NORMAL CLASSIFICATIONS</span>
      <span className="stat-icon green">✓</span>
    </div>
    <h2>{totalPredictions - totalAttacks}</h2>
    <p>Records classified as normal</p>
  </div>

  {/* Recent History */}
  <div className="stat-card">
    <div className="stat-top">
      <span>RECENT HISTORY</span>
      <span className="stat-icon purple">◷</span>
    </div>
    <h2>{predictionHistory.length} / 20</h2>
    <p>Latest prediction records retrieved from PostgreSQL</p>
  </div>

</section>
{/* PREDICTION ANALYTICS */}
<section className="panel analytics-panel">
  <div className="panel-heading">
    <div>
      <h2>Attack vs Normal Distribution</h2>
      <p>Prediction classification breakdown from PostgreSQL</p>
    </div>
    <span className="live-badge">LIVE DATA</span>
  </div>

  {totalPredictions === 0 ? (
    <div className="empty-history">
      <p>No prediction data available yet.</p>
    </div>
  ) : (
    <div style={{ width: "100%", height: "320px" }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={predictionDistribution}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            outerRadius={110}
            label={({ name, value }) => `${name}: ${value}`}
          >
            <Cell fill="#22c55e" />
            <Cell fill="#ef4444" />
          </Pie>
          <Tooltip />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )}
</section>

{/* PREDICTION TRENDS */}
<section className="panel analytics-panel">
  <div className="panel-heading">
    <div>
      <h2>Prediction Trends</h2>
      <p>Historical attack and normal classifications</p>
    </div>
    <span className="live-badge">DATABASE HISTORY</span>
  </div>

  {predictionTrend.length === 0 ? (
    <div className="empty-history">
      <p>No prediction history available.</p>
    </div>
  ) : (
    <div style={{ width: "100%", height: "320px" }}>
      <ResponsiveContainer width="100%" height="100%">
  <LineChart data={predictionTrend}>
    <CartesianGrid
      strokeDasharray="3 3"
      stroke="#334155"
    />

    <XAxis
      dataKey="time"
      stroke="#94a3b8"
      tick={{ fontSize: 11 }}
    />

    <YAxis
      allowDecimals={false}
      domain={[0, 1]}
      stroke="#94a3b8"
    />

    <Tooltip
      contentStyle={{
        backgroundColor: "#172338",
        border: "1px solid #334155",
        borderRadius: "8px",
        color: "#ffffff",
      }}
    />

    <Legend />

    <Line
      type="monotone"
      dataKey="normal"
      name="Normal Traffic"
      stroke="#22c55e"
      strokeWidth={3}
      dot={{ r: 4 }}
      activeDot={{ r: 7 }}
    />

    <Line
      type="monotone"
      dataKey="attack"
      name="Attack Classifications"
      stroke="#ef4444"
      strokeWidth={3}
      dot={{ r: 4 }}
      activeDot={{ r: 7 }}
    />
  </LineChart>
</ResponsiveContainer>
    </div>
  )}
</section>

{/* DETECTION SEVERITY ANALYTICS */}
<section className="panel analytics-panel">
  <div className="panel-heading">
    <div>
      <h2>Detection Severity Analytics</h2>
      <p>Distribution of security events by severity</p>
    </div>
    <span className="live-badge">POSTGRESQL DATA</span>
  </div>

  {securityEvents.length === 0 ? (
    <div className="empty-history">
      <p>No security events available.</p>
    </div>
  ) : (
    <div style={{ width: "100%", height: "340px" }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={severityData}>
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis dataKey="name" stroke="#94a3b8" />
          <YAxis allowDecimals={false} stroke="#94a3b8" />
          <Tooltip />
          <Legend />
          <Bar dataKey="value" name="Security Events">
            {severityData.map((entry, index) => {
              const severityColors = {
                Critical: "#ef4444",
                High: "#f97316",
                Medium: "#eab308",
                Low: "#3b82f6",
                Unclassified: "#94a3b8",
              };

              return (
                <Cell
                  key={`severity-${index}`}
                  fill={severityColors[entry.name]}
                />
              );
            })}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )}
</section>

        <section className="content-grid">
          <section className="stats-grid activity-stats">
         <div className="stat-card">
    <div className="stat-top">
      <span>TOTAL PREDICTIONS</span>
      <span className="stat-icon blue">↗</span>
    </div>
    <h2>{totalPredictions}</h2>
    <p>Predictions during this session</p>
  </div>

  <div className="stat-card">
    <div className="stat-top">
      <span>ATTACK CLASSIFICATIONS</span>
      <span className="stat-icon orange">⚠</span>
    </div>
    <h2>{totalAttacks}</h2>
    <p>Synthetic records classified as attacks</p>
  </div>

  <div className="stat-card">
    <div className="stat-top">
      <span>NORMAL CLASSIFICATIONS</span>
      <span className="stat-icon green">✓</span>
    </div>
    <h2>{totalPredictions - totalAttacks}</h2>
    <p>Records classified as normal</p>
  </div>

  <div className="stat-card">
    <div className="stat-top">
      <span>RECENT HISTORY</span>
      <span className="stat-icon purple">◷</span>
    </div>
    <h2>{predictionHistory.length} / 10</h2>
    <p>Recent results retained in memory</p>
  </div>
</section>
          <div className="panel prediction-panel">
            <div className="panel-heading">
              <div>
                <h2>AI Traffic Analysis</h2>
                <p>Run a test against the trained model</p>
              </div>
              <span className="live-badge">MODEL API</span>
            </div>

            <h3>Network Traffic Classification</h3>

<p className="description">
  Enter network traffic features and submit them to the trained Random Forest
  model for experimental classification.
</p>

<div className="traffic-form">
  <div className="form-field">
    <label htmlFor="duration">Connection Duration</label>
    <input
      id="duration"
      type="number"
      min="0"
      step="0.1"
      value={trafficInput.duration}
      onChange={(e) =>
        setTrafficInput({
          ...trafficInput,
          duration: e.target.value,
        })
      }
    />
  </div>

  <div className="form-field">
    <label htmlFor="src_bytes">Source Bytes</label>
    <input
      id="src_bytes"
      type="number"
      min="0"
      step="1"
      value={trafficInput.src_bytes}
      onChange={(e) =>
        setTrafficInput({
          ...trafficInput,
          src_bytes: e.target.value,
        })
      }
    />
  </div>

  <div className="form-field">
    <label htmlFor="dst_bytes">Destination Bytes</label>
    <input
      id="dst_bytes"
      type="number"
      min="0"
      step="1"
      value={trafficInput.dst_bytes}
      onChange={(e) =>
        setTrafficInput({
          ...trafficInput,
          dst_bytes: e.target.value,
        })
      }
    />
  </div>

  <div className="form-field">
    <label htmlFor="packets">Packet Count</label>
    <input
      id="packets"
      type="number"
      min="0"
      step="1"
      value={trafficInput.packets}
      onChange={(e) =>
        setTrafficInput({
          ...trafficInput,
          packets: e.target.value,
        })
      }
    />
  </div>

  <div className="form-field">
    <label htmlFor="failed_connections">Failed Connections</label>
    <input
      id="failed_connections"
      type="number"
      min="0"
      step="1"
      value={trafficInput.failed_connections}
      onChange={(e) =>
        setTrafficInput({
          ...trafficInput,
          failed_connections: e.target.value,
        })
      }
    />
  </div>
</div>
            <p className="description">
              Submit a predefined synthetic network record to the Random Forest
              model and inspect its classification result.
            </p>
            <button
              className="primary-button"
              onClick={testPrediction}
              disabled={loading || !modelLoaded}
            >
              {loading ? "Analyzing Traffic..." : "▶ Run AI Prediction"}
            </button>
            {error && <div className="error-box">{error}</div>}
            {prediction && (
              <div
                className={`result-box ${
                  isAttack ? "attack-result" : "normal-result"
                }`}
              >
                <div className="result-heading">
                  {isAttack ? "⚠" : "✓"} {prediction.prediction}
                </div>

                <p>
                  Attack probability:{" "}
                  {(prediction.attack_probability * 100).toFixed(1)}%
                </p>

                <p>
                  Normal probability:{" "}
                  {(prediction.normal_probability * 100).toFixed(1)}%
                </p>

                <small>
                  This is a synthetic-data experiment, not a verified real-world
                  security alert.
                </small>
              </div>
            )}
          </div>

          <div className="panel system-panel">
            <div className="panel-heading">
              <div>
                <h2>System Health</h2>
                <p>Current service availability</p>
              </div>
              <span className="health-icon">♥</span>
            </div>

            <div className="health-row">
              <div>
                <strong>Frontend</strong>
                <p>React development server</p>
              </div>
              <span className="health-status">Running</span>
            </div>

            <div className="health-row">
              <div>
                <strong>Backend API</strong>
                <p>127.0.0.1:8000</p>
              </div>
              <span
                className={
                  apiStatus === "Connected"
                    ? "health-status"
                    : "health-status offline"
                }
              >
                {apiStatus}
              </span>
            </div>

            <div className="health-row">
              <div>
                <strong>ML Model</strong>
                <p>Random Forest</p>
              </div>
              <span
                className={
                  modelLoaded ? "health-status" : "health-status offline"
                }
              >
                {modelLoaded ? "Loaded" : "Unavailable"}
              </span>
            </div>

            <button className="secondary-button" onClick={checkAPI}>
              Check Services
            </button>
          </div>
        </section>

<section className="panel history-panel">
<section className="panel chart-panel">
  <div className="panel-heading">
    <div>
      <h2>Traffic Analysis Overview</h2>
      <p>Summary of model classifications during this session</p>
    </div>
    <span className="live-badge">SESSION DATA</span>
  </div>

  <div className="chart-container">
    <ResponsiveContainer width="100%" height={300}>
      <BarChart
        data={chartData}
        margin={{ top: 10, right: 20, left: 0, bottom: 10 }}
      >
        <CartesianGrid strokeDasharray="3 3" stroke="#273449" />

        <XAxis
          dataKey="name"
          stroke="#94a3b8"
        />

        <YAxis
          allowDecimals={false}
          stroke="#94a3b8"
        />

        <Tooltip
          contentStyle={{
            backgroundColor: "#111827",
            border: "1px solid #334155",
            borderRadius: "8px",
            color: "#ffffff",
          }}
        />

        <Legend />

        <Bar
          dataKey="count"
          name="Classification Count"
          fill="#38bdf8"
          radius={[6, 6, 0, 0]}
        />
      </BarChart>
    </ResponsiveContainer>
  </div>

  <p className="chart-disclaimer">
    Counts reflect predictions made in this browser session. They do not
    represent live network traffic statistics.
  </p>
</section>
  <div className="panel-heading">
    <div>
      <h2>Prediction History & Security Alerts</h2>
      <p>Recent classifications from the synthetic-data model</p>
    </div>

    <span className="live-badge">
      {predictionHistory.length} RECORDS
    </span>
  </div>

  {predictionHistory.length === 0 ? (
    <div className="empty-history">
      <span>◷</span>
      <h3>No predictions recorded yet</h3>
      <p>
        Run an AI prediction above to populate the history.
      </p>
    </div>
  ) : (
    <div className="table-wrapper">
      <table className="history-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Classification</th>
            <th>Attack Probability</th>
            <th>Status</th>
          </tr>
        </thead>

        <tbody>
          {predictionHistory.map((record) => (
            <tr key={record.id}>
              <td>{record.timestamp}</td>

              <td>
                <span
                  className={
                    record.prediction_code === 1
                      ? "alert-label attack-label"
                      : "alert-label normal-label"
                  }
                >
                  {record.prediction}
                </span>
              </td>

              <td>
                {(record.attack_probability * 100).toFixed(1)}%
              </td>

              <td>
                {record.prediction_code === 1
                  ? "Synthetic alert"
                  : "Normal classification"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )}

  <p className="history-disclaimer">
    These entries represent model predictions on synthetic test records.
    They are not confirmed real-world security incidents.
  </p>
  {/* SECURITY ALERTS SECTION */}
<div className="security-alerts-section">

  <div className="panel-heading">
    <div>
      <h2>Security Alerts</h2>
      <p>Detection events retrieved from PostgreSQL</p>
    </div>

    <span className="live-badge">
      {securityEvents.length} EVENTS
    </span>
  </div>

  {securityEvents.length === 0 ? (
    <div className="empty-history">
      <span>🛡️</span>
      <h3>No security events recorded</h3>
      <p>
        Security events will appear here when the model
        classifies a prediction as ATTACK.
      </p>
    </div>
  ) : (
    <div className="table-wrapper">
      <table className="history-table">

        <thead>
          <tr>
            <th>Event ID</th>
            <th>Classification</th>
            <th>Severity</th>
            <th>Description</th>
            <th>Status</th>
            <th>Timestamp</th>
          </tr>
        </thead>

        <tbody>
          {securityEvents.map((event) => (
            <tr key={event.event_id}>

              <td>#{event.event_id}</td>

              <td>
                <span className="alert-label attack-label">
                  {event.predicted_label || "ATTACK"}
                </span>
              </td>

              <td>
                <span className="severity-badge">
                  {event.severity || "UNCLASSIFIED"}
                </span>
              </td>

              <td>
                {event.description || "No description available"}
              </td>

            <td>
  <select
    className="status-select"
    value={event.status || "OPEN"}
    onChange={(e) =>
      updateSecurityEventStatus(
        event.event_id,
        e.target.value
      )
    }
  >
    <option value="OPEN">OPEN</option>
    <option value="INVESTIGATING">INVESTIGATING</option>
    <option value="RESOLVED">RESOLVED</option>
  </select>
</td>
              <td>
                {new Date(event.created_at).toLocaleString()}
              </td>

            </tr>
          ))}
        </tbody>

      </table>
    </div>
  )}

</div>
</section>
                <footer className="footer">
          <span>Sentinel AI · Network Intrusion Detection Platform</span>
          <span>Experimental prototype · Synthetic data</span>
        </footer>
      </>
)}
      </main>
    </div>
  );
}

export default App;