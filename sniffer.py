import time
import threading
from collections import defaultdict
from scapy.all import sniff, IP
import database as db

WINDOW_DURATION = 10.0  # Process chunks every 10 seconds
flow_lock = threading.Lock()


def factory():
    return [0, 0]


flow_table = defaultdict(factory)


def process_packet(packet):
    """Filters for IPv4 packets and updates the flow matrix in real time."""
    if IP in packet:
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            pkt_size = len(packet)

            flow_key = (src_ip, dst_ip, proto)

            with flow_lock:
                flow_table[flow_key][0] += 1
                flow_table[flow_key][1] += pkt_size
        except Exception:
            pass


def flush_flows_worker():
    """Asynchronously flushes the captured flows straight into SQLite."""
    global flow_table

    while True:
        time.sleep(WINDOW_DURATION)

        with flow_lock:
            if not flow_table:
                continue
            local_flows = flow_table
            flow_table = defaultdict(factory)

        current_time = time.time()
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(current_time))
        print(f"[*] Aggregated {len(local_flows)} unique paths. Writing to database...")

        for flow_key, metrics in local_flows.items():
            src_ip, dst_ip, proto = flow_key
            pkt_count, byte_count = metrics
            avg_pkt_size = byte_count / pkt_count if pkt_count > 0 else 0

            # Log directly to SQLite database
            db.log_flow(timestamp, src_ip, dst_ip, proto, pkt_count, byte_count, round(avg_pkt_size, 2))


def start_sniffing(interface=None):
    db.init_db()  # Guarantee tables exist before writing

    worker = threading.Thread(target=flush_flows_worker, daemon=True)
    worker.start()

    print(f"[*] Sniffer active. Ingesting live traffic records...")
    sniff(iface=interface, prn=process_packet, store=0)


if __name__ == "__main__":
    try:
        start_sniffing(interface=None)
    except KeyboardInterrupt:
        print("\n[*] Sniffer pipeline stopped cleanly.")