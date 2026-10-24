#!/usr/bin/env python3
"""Passive UDP telemetry sniffer with JSON parsing and simple heuristic alerts."""

import time
import json
import argparse
import sys
from typing import Optional

try:
    from scapy.all import sniff, IP, UDP, Raw
except ImportError:
    print("[!] Scapy is not installed. Please run: pip install scapy")
    sys.exit(1)


# ==============================================================================
# CONFIGURATION
# ==============================================================================
DEFAULT_LISTEN_PORT = 5005
DEFAULT_INTERFACE = None  # None = Scapy auto-selects default interface (Loopback on 127.0.0.1)

# Detection Thresholds for baseline rule checks
MAX_ACCEPTABLE_TEMP = 60.0    # °C (DHT11 operating ceiling)
MIN_ACCEPTABLE_TEMP = -10.0   # °C
MAX_ACCEPTABLE_HUMIDITY = 100.0
MIN_ACCEPTABLE_HUMIDITY = 0.0


# ==============================================================================
# PACKET PARSER & INSPECTION ENGINE
# ==============================================================================
class NIDSListener:
    def __init__(self, port: int = DEFAULT_LISTEN_PORT, interface: Optional[str] = DEFAULT_INTERFACE):
        self.port = port
        self.interface = interface
        self.packet_count = 0
        self.anomaly_count = 0
        self.last_packet_time = time.time()

    def handle_packet(self, pkt) -> None:
        """
        Callback invoked by Scapy for every intercepted packet matching the BPF filter.
        """
        self.packet_count += 1
        current_time = time.time()
        inter_arrival_time = current_time - self.last_packet_time
        self.last_packet_time = current_time

        # Extract Network & Transport Layer Info
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP)):
            return

        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        udp_sport = pkt[UDP].sport
        udp_dport = pkt[UDP].dport

        # Extract Raw Telemetry Payload
        if not pkt.haslayer(Raw):
            return

        raw_payload = pkt[Raw].load

        # Telemetry Analysis & Anomaly Screening
        try:
            payload_str = raw_payload.decode('utf-8')
            data = json.loads(payload_str)
            
            # Check for Sensor Out-of-Bounds Anomalies
            if "temp" in data and "humidity" in data:
                temp = data["temp"]
                humidity = data["humidity"]
                
                if not (MIN_ACCEPTABLE_TEMP <= temp <= MAX_ACCEPTABLE_TEMP) or not (MIN_ACCEPTABLE_HUMIDITY <= humidity <= MAX_ACCEPTABLE_HUMIDITY):
                    self.anomaly_count += 1
                    print(f"\033[91m[ALERT: SENSOR TAMPERING] Out-of-bounds reading from {ip_src}:{udp_sport} | Temp: {temp}°C | Humidity: {humidity}%\033[0m")
                    return

                # Normal Valid Telemetry Log
                print(f"[NIDS CAPTURE] #{self.packet_count:04d} | Src: {ip_src}:{udp_sport} -> Dst: {ip_dst}:{udp_dport} | "
                      f"Node: {data.get('device_id', 'UNKNOWN')} | Seq: {data.get('seq', -1):04d} | "
                      f"T: {temp:5.2f}°C | H: {humidity:5.2f}% | IAT: {inter_arrival_time*1000:6.1f}ms")
            
            elif "attack_type" in data:
                self.anomaly_count += 1
                print(f"\033[93m[ALERT: FLOOD TRAFFIC] Detected {data['attack_type']} burst packet #{data.get('burst_id')} from {ip_src}\033[0m")

            else:
                print(f"[NIDS RAW JSON] #{self.packet_count:04d} | Src: {ip_src} | Payload: {payload_str[:60]}...")

        except (UnicodeDecodeError, json.JSONDecodeError):
            # Payload is malformed or binary fuzzing data
            self.anomaly_count += 1
            sample_hex = raw_payload[:24].hex()
            print(f"\033[91m[ALERT: MALFORMED PAYLOAD] Non-compliant / binary payload from {ip_src}:{udp_sport} (len={len(raw_payload)}) | Hex: {sample_hex}\033[0m")

    def start_listening(self) -> None:
        """
        Launches Scapy's passive packet sniffer.
        BPF (Berkeley Packet Filter): 'udp and port <PORT>'
        """
        bpf_filter = f"udp and port {self.port}"
        print("=" * 78)
        print("  NET-GUARD: Passive Network Intrusion Detection Sniffer")
        print("=" * 78)
        print(f"[*] BPF Filter       : {bpf_filter}")
        print(f"[*] Sniff Interface  : {self.interface or 'Default Loopback/All'}")
        print(f"[*] Ingestion Port   : {self.port}")
        print("=" * 78)
        print("[*] Passive listener active. Intercepting telemetry traffic...\n")

        try:
            sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=self.handle_packet,
                store=0
            )
        except KeyboardInterrupt:
            print("\n" + "=" * 78)
            print(f"[*] Sniffer halted. Total captured: {self.packet_count} | Anomalies flagged: {self.anomaly_count}")
            print("=" * 78)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NET-GUARD Passive NIDS Listener")
    parser.add_argument("--port", type=int, default=DEFAULT_LISTEN_PORT, help=f"UDP Port to sniff (default: {DEFAULT_LISTEN_PORT})")
    parser.add_argument("--iface", default=DEFAULT_INTERFACE, help="Network interface to sniff on (e.g. eth0, Wi-Fi, Npcap Loopback Adapter)")
    
    args = parser.parse_args()
    listener = NIDSListener(port=args.port, interface=args.iface)
    listener.start_listening()
