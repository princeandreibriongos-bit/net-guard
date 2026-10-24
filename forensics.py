#!/usr/bin/env python3
"""JSONL/CSV logging and optional PCAP ring-buffer dumps on high-severity events."""

import os
import csv
import json
import time
from collections import deque
from datetime import datetime
from typing import List, Dict, Any, Optional

try:
    from scapy.all import wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class ForensicManager:
    def __init__(
        self,
        captures_dir: str = "captures",
        logs_dir: str = "logs",
        pcap_ring_size: int = 150
    ):
        self.captures_dir = captures_dir
        self.logs_dir = logs_dir
        self.pcap_ring_size = pcap_ring_size
        
        self.packet_ring_buffer: deque = deque(maxlen=pcap_ring_size)
        self.last_pcap_dump_time = 0.0
        self.cooldown_sec = 3.0  # Avoid writing 100 pcaps for single flood burst

        os.makedirs(self.captures_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)
        
        self.alerts_file = os.path.join(self.logs_dir, "alerts.jsonl")
        self.csv_file = os.path.join(self.logs_dir, "telemetry.csv")
        self._init_csv()

    def _init_csv(self) -> None:
        if not os.path.exists(self.csv_file):
            with open(self.csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
                    "iat_ms", "entropy", "temp", "humidity", "anomaly_score", "threat_level"
                ])

    def record_raw_packet(self, scapy_pkt) -> None:
        """Pushes raw scapy packet to rolling ring buffer for potential capture."""
        self.packet_ring_buffer.append(scapy_pkt)

    def log_telemetry_entry(
        self,
        record: Any,
        features: Dict[str, float],
        ml_result: Dict[str, Any]
    ) -> None:
        """Appends record to flat CSV."""
        try:
            with open(self.csv_file, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.now().isoformat(),
                    record.src_ip,
                    record.src_port,
                    record.dst_ip,
                    record.dst_port,
                    round(features.get("iat_mean", 0) * 1000, 2),
                    features.get("shannon_entropy", 0),
                    record.temp if record.temp is not None else "",
                    record.humidity if record.humidity is not None else "",
                    ml_result.get("anomaly_score", 0),
                    ml_result.get("threat_level", "NORMAL")
                ])
        except Exception as e:
            print(f"[!] CSV logging error: {e}")

    def trigger_incident_capture(
        self,
        attack_type: str,
        record: Any,
        features: Dict[str, float],
        ml_result: Dict[str, Any]
    ) -> Optional[str]:
        """
        Dumps the rolling packet buffer to a timestamped .pcap and logs alert to JSONL.
        """
        now = time.time()
        pcap_filename = None

        # Check cooldown to prevent excessive disk I/O during heavy floods
        if now - self.last_pcap_dump_time >= self.cooldown_sec and SCAPY_AVAILABLE and len(self.packet_ring_buffer) > 0:
            self.last_pcap_dump_time = now
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_filename = os.path.join(self.captures_dir, f"incident_{timestamp_str}_{attack_type.lower()}.pcap")
            
            try:
                # Dump current ring buffer packets to pcap
                pkts_to_dump = list(self.packet_ring_buffer)
                wrpcap(pcap_filename, pkts_to_dump)
                print(f"\033[95m[+] [FORENSICS] Incident PCAP saved: {pcap_filename} ({len(pkts_to_dump)} packets)\033[0m")
            except Exception as e:
                print(f"[!] Failed writing PCAP: {e}")
                pcap_filename = None

        # Append structured JSONL Alert
        alert_entry = {
            "timestamp": datetime.now().isoformat(),
            "epoch": now,
            "threat_level": ml_result.get("threat_level", "CRITICAL"),
            "anomaly_score": ml_result.get("anomaly_score", 0.99),
            "attack_type": attack_type,
            "source": f"{record.src_ip}:{record.src_port}",
            "destination": f"{record.dst_ip}:{record.dst_port}",
            "payload_length": record.payload_len,
            "shannon_entropy": features.get("shannon_entropy"),
            "explanations": ml_result.get("top_explanations", []),
            "pcap_file": pcap_filename
        }

        try:
            with open(self.alerts_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert_entry) + "\n")
        except Exception as e:
            print(f"[!] Alerts JSONL error: {e}")

        return pcap_filename
