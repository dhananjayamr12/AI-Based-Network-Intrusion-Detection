import React, { useState } from "react";
import "./IPAnalysis.css";

const API_URL = "http://127.0.0.1:8000";

function IPAnalysis() {
  const [ipAddress, setIpAddress] = useState("");
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function analyzeIP(event) {
    event.preventDefault();

    const ip = ipAddress.trim();

    if (!ip) {
      setError("Please enter an IP address.");
      return;
    }

    setLoading(true);
    setError("");
    setAnalysis(null);

    try {
      const response = await fetch(
        `${API_URL}/ip-analysis/${encodeURIComponent(ip)}`
      );

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.detail || "IP analysis failed.");
      }

      setAnalysis(result.data);
    } catch (err) {
      setError(err.message || "Unable to connect to the API.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="ip-analysis-page">

      <div className="ip-page-heading">
        <div>
          <p className="ip-eyebrow">NETWORK SECURITY INTELLIGENCE</p>
          <h1>IP Address Analysis</h1>
          <p>Investigate IP addresses and their associated network activity.</p>
        </div>

        <span className="ip-live-badge">● API CONNECTED</span>
      </div>

      <section className="ip-search-panel">

        <div className="ip-search-title">
          <h2>IP Investigation</h2>
          <p>Enter an IPv4 or IPv6 address to investigate.</p>
        </div>

        <form onSubmit={analyzeIP} className="ip-search-form">

          <input
            type="text"
            placeholder="Example: 192.168.1.10"
            value={ipAddress}
            onChange={(e) => setIpAddress(e.target.value)}
          />

          <button type="submit" disabled={loading}>
            {loading ? "Analyzing..." : "🔍 Analyze IP"}
          </button>

        </form>

        {error && (
          <div className="ip-error">{error}</div>
        )}

      </section>

      {analysis && (
        <>
          <section className="ip-statistics">

            <div className="ip-stat-card">
              <span>Total Traffic Records</span>
              <h2>{analysis.total_traffic_records}</h2>
            </div>

            <div className="ip-stat-card">
              <span>Total Predictions</span>
              <h2>{analysis.total_predictions}</h2>
            </div>

            <div className="ip-stat-card">
              <span>Attack Predictions</span>
              <h2 className="ip-attack-number">
                {analysis.attack_predictions}
              </h2>
            </div>

            <div className="ip-stat-card">
              <span>Normal Predictions</span>
              <h2 className="ip-normal-number">
                {analysis.normal_predictions}
              </h2>
            </div>

            <div className="ip-stat-card">
              <span>Detection Events</span>
              <h2>{analysis.total_detection_events}</h2>
            </div>

          </section>

          <section className="ip-details-panel">

            <h2>Investigation Summary</h2>

            <div className="ip-detail-row">
              <span>Investigated IP</span>
              <strong>{analysis.ip_address}</strong>
            </div>

            <div className="ip-detail-row">
              <span>Traffic Records</span>
              <strong>{analysis.total_traffic_records}</strong>
            </div>

            <div className="ip-detail-row">
              <span>Associated Security Events</span>
              <strong>{analysis.total_detection_events}</strong>
            </div>

            <p className="ip-disclaimer">
              Results represent stored traffic and experimental ML
              classifications. They do not establish malicious IP reputation.
            </p>

          </section>

          <section className="ip-history-panel">

            <div className="ip-history-heading">
              <h2>Traffic Investigation History</h2>
              <span>{analysis.records.length} RECORDS</span>
            </div>

            {analysis.records.length === 0 ? (

              <div className="ip-empty-state">
                <div>🔍</div>
                <h3>No Traffic Records Found</h3>
                <p>
                  No stored network traffic matches this IP address.
                  Submit a prediction containing this IP to create a record.
                </p>
              </div>

            ) : (

              <div className="ip-table-wrapper">

                <table className="ip-history-table">

                  <thead>
                    <tr>
                      <th>Source IP</th>
                      <th>Destination IP</th>
                      <th>Packets</th>
                      <th>Classification</th>
                      <th>Attack Probability</th>
                      <th>Severity</th>
                      <th>Status</th>
                      <th>Timestamp</th>
                    </tr>
                  </thead>

                  <tbody>
                    {analysis.records.map((record) => (

                      <tr key={record.traffic_id}>

                        <td>{record.source_ip || "—"}</td>
                        <td>{record.destination_ip || "—"}</td>
                        <td>{record.packets}</td>

                        <td>
                          <span className={
                            record.predicted_label === "ATTACK"
                              ? "ip-attack-label"
                              : "ip-normal-label"
                          }>
                            {record.predicted_label || "NOT ANALYZED"}
                          </span>
                        </td>

                        <td>
                          {record.attack_probability != null
                            ? `${(record.attack_probability * 100).toFixed(2)}%`
                            : "—"}
                        </td>

                        <td>{record.severity || "—"}</td>
                        <td>{record.status || "—"}</td>

                        <td>
                          {record.created_at
                            ? new Date(record.created_at).toLocaleString()
                            : "—"}
                        </td>

                      </tr>

                    ))}
                  </tbody>

                </table>

              </div>

            )}

          </section>
        </>
      )}

    </div>
  );
}

export default IPAnalysis;