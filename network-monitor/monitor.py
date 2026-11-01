import time
import psutil
from datetime import datetime


def get_network_stats():
    """Collect actual network interface counters."""

    stats = psutil.net_io_counters(pernic=True)
    interfaces = []

    for name, counters in stats.items():
        interfaces.append({
            "interface": name,
            "bytes_sent": counters.bytes_sent,
            "bytes_received": counters.bytes_recv,
            "packets_sent": counters.packets_sent,
            "packets_received": counters.packets_recv,
            "errors_in": counters.errin,
            "errors_out": counters.errout,
            "drops_in": counters.dropin,
            "drops_out": counters.dropout,
        })

    return {
        "timestamp": datetime.now().astimezone().isoformat(),
        "interfaces": interfaces,
    }


def monitor_network():
    print("=" * 55)
    print("       SENTINEL AI - LIVE NETWORK MONITOR")
    print("=" * 55)
    print("Reading actual Windows network counters.")
    print("Press Ctrl+C to stop.\n")

    previous_stats = psutil.net_io_counters(pernic=True)

    try:
        while True:
            time.sleep(3)

            current_stats = psutil.net_io_counters(pernic=True)

            print("\033[2J\033[H", end="")
            print("=" * 55)
            print("       SENTINEL AI - LIVE NETWORK MONITOR")
            print("=" * 55)
            print(f"Time: {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S')}")
            print("Refresh interval: 3 seconds\n")

            active_count = 0

            for name, current in current_stats.items():
                previous = previous_stats.get(name)

                if previous is None:
                    continue

                received_bytes = max(
                    0, current.bytes_recv - previous.bytes_recv
                )
                sent_bytes = max(
                    0, current.bytes_sent - previous.bytes_sent
                )
                received_packets = max(
                    0, current.packets_recv - previous.packets_recv
                )
                sent_packets = max(
                    0, current.packets_sent - previous.packets_sent
                )

                download_kbps = received_bytes / 3 / 1024
                upload_kbps = sent_bytes / 3 / 1024

                # Display interfaces that have traffic or are Wi-Fi.
                if (
                    received_bytes > 0
                    or sent_bytes > 0
                    or "wi-fi" in name.lower()
                ):
                    active_count += 1

                    print(f"Interface: {name}")
                    print(f"  Download: {download_kbps:.2f} KB/s")
                    print(f"  Upload:   {upload_kbps:.2f} KB/s")
                    print(f"  Incoming packets/s: {received_packets / 3:.2f}")
                    print(f"  Outgoing packets/s: {sent_packets / 3:.2f}")
                    print(f"  Total received: {current.bytes_recv:,} bytes")
                    print(f"  Total sent:     {current.bytes_sent:,} bytes")
                    print("-" * 55)

            if active_count == 0:
                print("No network activity detected during this interval.")

            previous_stats = current_stats

    except KeyboardInterrupt:
        print("\nNetwork monitoring stopped.")


if __name__ == "__main__":
    monitor_network()