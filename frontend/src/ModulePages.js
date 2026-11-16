import React from "react";

function StatCard({ title, value, description }) {
  return (
    <div className="module-stat-card">
      <h4>{title}</h4>
      <h2>{value ?? 0}</h2>
      <small>{description}</small>
    </div>
  );
}

function IntrusionDetection({ predictionHistory = [] }) {
  const attacks = predictionHistory.filter(
    (item) => String(item.prediction || item.label || "")
      .toLowerCase()
      .includes("attack")
  );

  return (
    <section className="module-page">
      <h1>Intrusion Detection</h1>
      <p>Review AI-based network traffic detection results.</p>

      <div className="module-stats">
        <StatCard
          title="Total Predictions"
          value={predictionHistory.length}
          description="Recorded predictions"
        />
        <StatCard
          title="Detected Attacks"
          value={attacks.length}
          description="Attack-labelled predictions"
        />
        <StatCard
          title="Normal Traffic"
          value={predictionHistory.length - attacks.length}
          description="Other recorded predictions"
        />
      </div>

      <div className="module-panel">
        <h3>Recent Detection Results</h3>

        {predictionHistory.length === 0 ? (
          <p>No prediction records available.</p>
        ) : (
          <div className="module-table-wrapper">
  <table className="module-table">
    <thead>
      <tr>
        <th>Prediction ID</th>
        <th>Traffic ID</th>
        <th>Source Bytes</th>
        <th>Destination Bytes</th>
        <th>Packets</th>
        <th>Result</th>
      </tr>
    </thead>

    <tbody>
      {predictionHistory.slice(0, 15).map((item, index) => (
        <tr key={item.id || index}>
          <td>{item.id}</td>
          <td>{item.traffic_id ?? "N/A"}</td>
          <td>{item.src_bytes ?? 0}</td>
          <td>{item.dst_bytes ?? 0}</td>
          <td>{item.packets ?? 0}</td>
          <td>{item.prediction}</td>
        </tr>
      ))}
    </tbody>
  </table>
</div>
        )}
      </div>
    </section>
  );
}

function NetworkMonitoring({
  networkStats,
  networkRates,
  networkStatus,
  networkError,
}) {
  return (
    <section className="module-page">
      <h1>Network Monitoring</h1>
      <p>Monitor the network interface statistics reported by this system.</p>

      <div className="module-stats">
        <StatCard
          title="Upload Rate"
          value={`${(networkRates?.uploadKBps ?? 0).toFixed(2)} KB/s`}
          description="Reported outgoing traffic rate"
        />
        <StatCard
          title="Download Rate"
          value={`${networkRates?.download ?? 0} KB/s`}
          description="Reported incoming traffic rate"
        />
        <StatCard
          title="Connection Status"
          value={networkStatus || "Unknown"}
          description="Monitoring service status"
        />
      </div>

      {networkError && (
        <div className="module-warning">{networkError}</div>
      )}

      <div className="module-panel">
        <h3>Network Interface Statistics</h3>
        <p><strong>Interface:</strong> {networkStats?.interface || "Wi-Fi"}</p>
<p><strong>Bytes Sent:</strong> {networkStats?.bytes_sent ?? 0}</p>
<p><strong>Bytes Received:</strong> {networkStats?.bytes_received ?? 0}</p>
<p><strong>Packets Sent:</strong> {networkStats?.packets_sent ?? 0}</p>
<p><strong>Packets Received:</strong> {networkStats?.packets_received ?? 0}</p>
      </div>

      <div className="module-warning">
        This page displays operating-system network interface counters.
        It does not yet represent packet-level inspection or live attack
        capture.
      </div>
    </section>
  );
}

function SecurityAlerts({
  securityEvents = [],
  onUpdateEventStatus,
  role,
}) {
  const canUpdate = role === "admin" || role === "analyst";

  const getStatus = (status) =>
    String(status || "OPEN").toUpperCase();

  return (
    <section className="module-page">
      <h1>Security Alerts</h1>
      <p>Review and manage recorded security detection events.</p>

      <div className="module-stats">
        <StatCard
          title="Total Alerts"
          value={securityEvents.length}
          description="Recorded security events"
        />

        <StatCard
          title="Open Alerts"
          value={securityEvents.filter(
            (event) => getStatus(event.status) === "OPEN"
          ).length}
          description="Require investigation"
        />

        <StatCard
          title="Resolved Alerts"
          value={securityEvents.filter(
            (event) => getStatus(event.status) === "RESOLVED"
          ).length}
          description="Marked as resolved"
        />
      </div>

      <div className="module-panel">
        <h3>Security Event Records</h3>

        {securityEvents.length === 0 ? (
          <p>No security alerts available.</p>
        ) : (
          <div className="module-table-wrapper">
            <table className="module-table">
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>Prediction ID</th>
                  <th>Detection</th>
                  <th>Severity</th>
                  <th>Attack Probability</th>
                  <th>Status</th>
                </tr>
              </thead>

              <tbody>
                {securityEvents.map((event) => (
                  <tr key={event.event_id}>
                    <td>{event.event_id}</td>
                    <td>{event.prediction_id}</td>
                    <td>{event.predicted_label}</td>
                    <td>{event.severity}</td>
                    <td>
                      {(
                        Number(event.attack_probability || 0) * 100
                      ).toFixed(2)}%
                    </td>
                    <td>
                      {canUpdate ? (
                        <select
                          value={getStatus(event.status)}
                          onChange={(e) =>
                            onUpdateEventStatus(
                              event.event_id,
                              e.target.value
                            )
                          }
                        >
                          <option value="OPEN">Open</option>
                          <option value="INVESTIGATING">
                            Investigating
                          </option>
                          <option value="RESOLVED">Resolved</option>
                        </select>
                      ) : (
                        getStatus(event.status)
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {!canUpdate && (
        <p className="module-note">
          Viewer access: read-only.
        </p>
      )}
    </section>
  );
}


export { IntrusionDetection, NetworkMonitoring, SecurityAlerts };