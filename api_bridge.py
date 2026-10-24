#!/usr/bin/env python3
"""HTTP static host, UDP/Scapy ingest, ML pipeline, and SSE feed for the dashboard."""

import os
import sys
import time
import json
import socket
import threading
import argparse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

# Pipeline components
from features import RollingFeatureExtractor
from ml_engine import IsolationForestEngine
from forensics import ForensicManager

try:
    from scapy.all import sniff, IP, UDP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not available. Sniffer will use UDP socket receiver fallback.")


# Global Event Stream Queues for SSE
sse_clients = set()
sse_lock = threading.Lock()

# Instances
feature_extractor = RollingFeatureExtractor(window_size=25)
ml_engine = IsolationForestEngine()
forensics = ForensicManager()

# Global metrics
system_metrics = {
    "total_captured": 0,
    "total_anomalies": 0,
    "last_packet_time": time.time(),
    "backend_status": "ONLINE"
}


def broadcast_sse(event_data: dict):
    """Sends JSON event payload to all connected Web Dashboard SSE listeners."""
    msg = f"data: {json.dumps(event_data)}\n\n".encode('utf-8')
    with sse_lock:
        to_remove = set()
        for client in sse_clients:
            try:
                client.wfile.write(msg)
                client.wfile.flush()
            except Exception:
                to_remove.add(client)
        for client in to_remove:
            sse_clients.discard(client)


def handle_captured_packet(pkt):
    """Core pipeline handler for every packet captured by Scapy."""
    system_metrics["total_captured"] += 1
    system_metrics["last_packet_time"] = time.time()

    # Record to forensics ring buffer
    forensics.record_raw_packet(pkt)

    if not (pkt.haslayer(IP) and pkt.haslayer(UDP)):
        return

    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst
    udp_sport = pkt[UDP].sport
    udp_dport = pkt[UDP].dport
    raw_payload = pkt[Raw].load if pkt.haslayer(Raw) else b""

    # 1. Feature Extraction
    features, record = feature_extractor.ingest_packet(
        timestamp=time.time(),
        src_ip=ip_src,
        dst_ip=ip_dst,
        src_port=udp_sport,
        dst_port=udp_dport,
        payload_bytes=raw_payload
    )

    # 2. Machine Learning Inference
    ml_result = ml_engine.predict(features)
    
    # Check attack signatures
    is_attack = ml_result["is_anomaly"] or record.is_malformed
    attack_type = None

    if record.is_malformed:
        attack_type = "MALFORMED_FUZZING"
    elif features.get("packet_rate_pps", 0) > 20.0 or features.get("iat_min", 1.0) < 0.05:
        attack_type = "UDP_FLOOD"
    elif record.temp is not None and (record.temp > 50.0 or record.temp < 0.0):
        attack_type = "SENSOR_SPOOF"
    elif is_attack:
        attack_type = "ZERO_DAY_ANOMALY"

    if is_attack:
        system_metrics["total_anomalies"] += 1
        # 3. Forensics & PCAP Dump
        forensics.trigger_incident_capture(
            attack_type=attack_type or "ANOMALY",
            record=record,
            features=features,
            ml_result=ml_result
        )

    # 4. Forensic CSV Log
    forensics.log_telemetry_entry(record, features, ml_result)

    # 5. Broadcast to Web Dashboard
    live_event = {
        "type": "PACKET_EVENT",
        "seq": system_metrics["total_captured"],
        "timestamp": time.time(),
        "src_ip": ip_src,
        "src_port": udp_sport,
        "dst_ip": ip_dst,
        "dst_port": udp_dport,
        "temp": record.temp,
        "humidity": record.humidity,
        "payload_len": record.payload_len,
        "raw_payload_preview": raw_payload[:64].decode('utf-8', errors='replace'),
        "features": features,
        "ml": ml_result,
        "is_attack": is_attack,
        "attack_type": attack_type
    }
    broadcast_sse(live_event)


def start_scapy_sniffer(sniff_port: int, iface: str = None):
    """Background thread running Scapy sniffer."""
    bpf = f"udp and port {sniff_port}"
    print(f"[*] [SNIFFER THREAD] Sniffing BPF '{bpf}' on interface '{iface or 'default'}'...")
    try:
        sniff(iface=iface, filter=bpf, prn=handle_captured_packet, store=0)
    except Exception as e:
        print(f"[!] Scapy sniffer error: {e}")


class NIDSServerHandler(SimpleHTTPRequestHandler):
    """Custom HTTP handler serving dashboard and real-time SSE stream."""
    
    def do_GET(self):
        parsed = urlparse(self.path)

        # Server-Sent Events endpoint for live dashboard stream
        if parsed.path == "/api/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            with sse_lock:
                sse_clients.add(self)
            try:
                while True:
                    time.sleep(1)
            except Exception:
                with sse_lock:
                    sse_clients.discard(self)
            return

        # REST Status Endpoint
        elif parsed.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            status_data = {
                "metrics": system_metrics,
                "ml_calibrated": ml_engine.is_calibrated,
                "ml_status": "ONLINE" if ml_engine.is_calibrated else "CALIBRATING"
            }
            self.wfile.write(json.dumps(status_data).encode('utf-8'))
            return

        # Default static file serving (HTML, CSS, JS)
        super().do_GET()


def run_backend(http_port: int = 8080, sniff_port: int = 5005, iface: str = None):
    # Start Scapy Sniffer in daemon thread
    if SCAPY_AVAILABLE:
        sniffer_thread = threading.Thread(
            target=start_scapy_sniffer,
            args=(sniff_port, iface),
            daemon=True
        )
        sniffer_thread.start()

    server_address = ('', http_port)
    httpd = ThreadingHTTPServer(server_address, NIDSServerHandler)
    print("=" * 78)
    print(f"  NET-GUARD: Unified Backend & SOC Dashboard Server")
    print("=" * 78)
    print(f"[*] Dashboard URL    : http://localhost:{http_port}/index.html")
    print(f"[*] Real-time Stream : http://localhost:{http_port}/api/stream (SSE)")
    print(f"[*] Sniffing Ingest  : UDP Port {sniff_port}")
    print("=" * 78)
    print("[*] Server active. Press Ctrl+C to terminate.\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down NET-GUARD server...")
        httpd.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NET-GUARD Unified Backend Server")
    parser.add_argument("--port", type=int, default=8080, help="HTTP dashboard port (default: 8080)")
    parser.add_argument("--sniff-port", type=int, default=5005, help="UDP Sniffing port (default: 5005)")
    parser.add_argument("--iface", default=None, help="Network interface name")
    args = parser.parse_args()

    run_backend(http_port=args.port, sniff_port=args.sniff_port, iface=args.iface)
