from scapy.all import PcapReader, IP, IPv6, TCP, UDP


def extract_flows(pcap_file):
    """
    Extract bidirectional network flows from an offline PCAP file.

    Supports IPv4, IPv6, TCP and UDP.
    """

    flows = {}

    with PcapReader(pcap_file) as packets:

        for packet in packets:

            # Extract IP information
            if IP in packet:
                ip_layer = packet[IP]

            elif IPv6 in packet:
                ip_layer = packet[IPv6]

            else:
                continue

            source_ip = ip_layer.src
            destination_ip = ip_layer.dst

            # Identify transport protocol
            if TCP in packet:
                transport = packet[TCP]
                protocol = "TCP"

            elif UDP in packet:
                transport = packet[UDP]
                protocol = "UDP"

            else:
                continue

            source_port = int(transport.sport)
            destination_port = int(transport.dport)

            source_endpoint = (source_ip, source_port)
            destination_endpoint = (destination_ip, destination_port)

            # Create a direction-independent flow key
            endpoints = sorted([
                source_endpoint,
                destination_endpoint
            ])

            flow_key = (
                protocol,
                endpoints[0],
                endpoints[1]
            )

            timestamp = float(packet.time)

            # Count network-layer bytes consistently
            packet_size = len(ip_layer)

            # Create a new flow
            if flow_key not in flows:

                flows[flow_key] = {
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "source_port": source_port,
                    "destination_port": destination_port,
                    "protocol": protocol,

                    "start_time": timestamp,
                    "end_time": timestamp,

                    "src_bytes": 0,
                    "dst_bytes": 0,
                    "packets": 0,

                    "tcp_syn_packets": 0,
                    "tcp_ack_packets": 0,
                    "tcp_fin_packets": 0,
                    "tcp_rst_packets": 0
                }

            flow = flows[flow_key]

            # Update timestamps
            flow["start_time"] = min(
                flow["start_time"],
                timestamp
            )

            flow["end_time"] = max(
                flow["end_time"],
                timestamp
            )

            flow["packets"] += 1

            # Track packet direction
            if (
                source_endpoint == (
                    flow["source_ip"],
                    flow["source_port"]
                )
            ):
                flow["src_bytes"] += packet_size

            else:
                flow["dst_bytes"] += packet_size

            # Extract TCP flags
            if protocol == "TCP":

                flags = int(transport.flags)

                if flags & 0x02:
                    flow["tcp_syn_packets"] += 1

                if flags & 0x10:
                    flow["tcp_ack_packets"] += 1

                if flags & 0x01:
                    flow["tcp_fin_packets"] += 1

                if flags & 0x04:
                    flow["tcp_rst_packets"] += 1

    # Prepare output
    results = []

    for flow in flows.values():

        results.append({
            "source_ip": flow["source_ip"],
            "destination_ip": flow["destination_ip"],

            "source_port": flow["source_port"],
            "destination_port": flow["destination_port"],

            "protocol": flow["protocol"],

            "duration": max(
                0,
                flow["end_time"] - flow["start_time"]
            ),

            "src_bytes": flow["src_bytes"],
            "dst_bytes": flow["dst_bytes"],

            "packets": flow["packets"],

            "tcp_syn_packets": flow["tcp_syn_packets"],
            "tcp_ack_packets": flow["tcp_ack_packets"],
            "tcp_fin_packets": flow["tcp_fin_packets"],
            "tcp_rst_packets": flow["tcp_rst_packets"],

            "failed_connections": None
        })

    return results