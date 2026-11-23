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
  onAnalyzePcap,
  pcapResult,
  pcapLoading,
  pcapError,
}) {
  const [selectedFile, setSelectedFile] = React.useState(null);

  function handleUpload() {
    if (!selectedFile) {
      alert("Please select a PCAP or PCAPNG file.");
      return;
    }

    onAnalyzePcap(selectedFile);
  }

  return (
    <section className="module-page">
      <h1>Network Monitoring</h1>
      <p>Monitor network interface statistics and analyze offline network captures.</p>

      {/* SYSTEM NETWORK STATISTICS */}
      <div className="module-stats">
        <StatCard
          title="Upload Rate"
          value={`${(networkRates?.uploadKBps ?? 0).toFixed(2)} KB/s`}
          description="Outgoing network traffic"
        />

        <StatCard
          title="Download Rate"
          value={`${networkRates?.downloadKBps ?? 0} KB/s`}
          description="Incoming network traffic"
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

      {/* PCAP UPLOAD SECTION */}
      <div className="module-panel">
        <h3>Offline PCAP Analysis</h3>

        <p>
          Upload a PCAP or PCAPNG file to extract TCP and UDP network flows
          and save the extracted traffic records in PostgreSQL.
        </p>

        <div style={{ marginTop: "20px" }}>
          <input
            type="file"
            accept=".pcap,.pcapng"
            onChange={(event) =>
              setSelectedFile(event.target.files?.[0] || null)
            }
          />

          {selectedFile && (
            <p style={{ marginTop: "10px" }}>
              Selected file: <strong>{selectedFile.name}</strong>
            </p>
          )}

          <button
            type="button"
            onClick={handleUpload}
            disabled={!selectedFile || pcapLoading}
            style={{ marginTop: "15px" }}
            className="primary-button"
          >
            {pcapLoading ? "Analyzing PCAP..." : "Upload and Analyze PCAP"}
          </button>
        </div>

        {pcapError && (
          <div className="module-warning" style={{ marginTop: "15px" }}>
            {pcapError}
          </div>
        )}
      </div>

      {/* PCAP ANALYSIS SUMMARY */}
      {pcapResult && (
        <>
          <div className="module-stats">
            <StatCard
              title="Extracted Flows"
              value={pcapResult.total_flows}
              description="TCP and UDP flows"
            />

            <StatCard
              title="Total Packets"
              value={pcapResult.total_packets}
              description="Packets analyzed"
            />

            <StatCard
              title="Database Records"
              value={pcapResult.database_saved}
              description="Records saved in PostgreSQL"
            />
          </div>

          <div className="module-panel">
            <h3>PCAP Analysis Results</h3>

            <p>
              <strong>Filename:</strong> {pcapResult.filename}
            </p>

            <p>
              <strong>Analysis Status:</strong> {pcapResult.status}
            </p>

            <p>
              <strong>Data Source:</strong> {pcapResult.data_source}
            </p>

            <p>
              <strong>Database Storage:</strong>{" "}
              {pcapResult.database_saved} records saved successfully
            </p>
          </div>

          <div className="module-panel">
            <h3>Extracted Network Flows</h3>

            {pcapResult.flows?.length > 0 ? (
              <div className="module-table-wrapper">
                <table className="module-table">
                  <thead>
                    <tr>
                      <th>Traffic ID</th>
                      <th>Source IP</th>
                      <th>Destination IP</th>
                      <th>Protocol</th>
                      <th>Source Port</th>
                      <th>Destination Port</th>
                      <th>Source Bytes</th>
                      <th>Destination Bytes</th>
                      <th>Packets</th>
                    </tr>
                  </thead>

                  <tbody>
                    {pcapResult.flows.map((flow, index) => (
                      <tr key={pcapResult.saved_records?.[index]?.traffic_id || index}>
                        <td>
                          {pcapResult.saved_records?.[index]?.traffic_id ?? "N/A"}
                        </td>

                        <td>{flow.source_ip}</td>
                        <td>{flow.destination_ip}</td>
                        <td>{flow.protocol}</td>
                        <td>{flow.source_port}</td>
                        <td>{flow.destination_port}</td>
                        <td>{flow.src_bytes}</td>
                        <td>{flow.dst_bytes}</td>
                        <td>{flow.packets}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p>No network flows were extracted from this file.</p>
            )}
          </div>

          <div className="module-warning">
            {pcapResult.note}
          </div>
        </>
      )}

      <div className="module-warning">
        System network statistics represent operating-system interface
        counters. PCAP analysis represents traffic contained in the uploaded
        offline capture. Neither should be interpreted as a verified
        real-time intrusion detection result.
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