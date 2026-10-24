#!/usr/bin/env python3
"""Scapy-based UDP telemetry generator and attack scenarios for lab testing."""

import time
import json
import random
import argparse
import sys
from typing import Dict, Any

# Scapy packet crafting modules
try:
    from scapy.all import IP, UDP, Raw, send
except ImportError:
    print("[!] Scapy is not installed. Please run: pip install scapy")
    sys.exit(1)


# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================
DEFAULT_TARGET_IP = "127.0.0.1"      # Target interface (Loopback for simulation)
DEFAULT_TARGET_PORT = 5005          # UDP Ingestion Port for NET-GUARD NIDS
DEFAULT_NODE_ID = "esp32-node-01"   # Edge node identifier
DEFAULT_INTERVAL = 2.0              # Seconds between normal telemetry packets

# Baseline DHT11 Environmental Ranges (Normal baseline for IoT edge)
TEMP_BASELINE_MIN = 21.0
TEMP_BASELINE_MAX = 27.0
HUMIDITY_BASELINE_MIN = 45.0
HUMIDITY_BASELINE_MAX = 65.0


# ==============================================================================
# PACKET CRAFTING UTILITIES (SCAPY)
# ==============================================================================
def craft_udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload_bytes: bytes):
    """
    Low-Level Network Layer Encapsulation using Scapy:
    
    1. IP Layer (Layer 3 - Network):
       - src: Source IP address of the virtual edge node.
       - dst: Destination IP address (NIDS listener or subnet broadcast).
       - ttl: Time-To-Live (standard default 64).
       - proto: Protocol number (17 for UDP). Scapy auto-populates this from UDP layer.
    
    2. UDP Layer (Layer 4 - Transport):
       - sport: Source port (dynamically chosen ephemeral port).
       - dport: Destination port (NET-GUARD listening service port).
       - len & chksum: Automatically computed by Scapy upon transmission.
    
    3. Raw Payload (Layer 7 - Application / Telemetry):
       - Encapsulates serialized sensor measurements into the UDP datagram payload.
    """
    packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / Raw(load=payload_bytes)
    return packet


# ==============================================================================
# VIRTUAL ESP32 TELEMETRY GENERATOR
# ==============================================================================
class VirtualESP32Node:
    def __init__(self, node_id: str = DEFAULT_NODE_ID, target_ip: str = DEFAULT_TARGET_IP, target_port: int = DEFAULT_TARGET_PORT):
        self.node_id = node_id
        self.target_ip = target_ip
        self.target_port = target_port
        self.source_ip = "127.0.0.1" if target_ip == "127.0.0.1" else "192.168.1.50"
        self.source_port = random.randint(49152, 65535)  # Ephemeral port
        self.sequence_num = 0

        # Simulated state drift for realistic sensor modeling
        self.current_temp = random.uniform(TEMP_BASELINE_MIN, TEMP_BASELINE_MAX)
        self.current_humidity = random.uniform(HUMIDITY_BASELINE_MIN, HUMIDITY_BASELINE_MAX)

    def read_virtual_dht11(self) -> Dict[str, float]:
        """
        Simulates DHT11 environmental sensor reading with realistic slight drift.
        """
        temp_delta = random.uniform(-0.3, 0.3)
        hum_delta = random.uniform(-0.5, 0.5)

        self.current_temp = max(TEMP_BASELINE_MIN, min(TEMP_BASELINE_MAX, self.current_temp + temp_delta))
        self.current_humidity = max(HUMIDITY_BASELINE_MIN, min(HUMIDITY_BASELINE_MAX, self.current_humidity + hum_delta))

        return {
            "temperature_c": round(self.current_temp, 2),
            "humidity_pct": round(self.current_humidity, 2)
        }

    def generate_normal_payload(self) -> str:
        """
        Constructs standard JSON-encoded telemetry payload matching the ESP32 firmware specs.
        """
        self.sequence_num += 1
        sensor_data = self.read_virtual_dht11()

        payload_dict: Dict[str, Any] = {
            "device_id": self.node_id,
            "seq": self.sequence_num,
            "timestamp": round(time.time(), 3),
            "sensor": "DHT11",
            "temp": sensor_data["temperature_c"],
            "humidity": sensor_data["humidity_pct"],
            "status": "HEALTHY"
        }
        return json.dumps(payload_dict)

    def send_telemetry_packet(self, payload_str: str) -> None:
        """
        Crafts and transmits the packet over the network interface via Scapy.
        """
        payload_bytes = payload_str.encode('utf-8')
        pkt = craft_udp_packet(
            src_ip=self.source_ip,
            dst_ip=self.target_ip,
            src_port=self.source_port,
            dst_port=self.target_port,
            payload_bytes=payload_bytes
        )
        
        # verbose=0 suppresses Scapy's default stdout "Sent 1 packets." per packet
        send(pkt, verbose=0)


# ==============================================================================
# VIRTUAL ATTACKER / ANOMALY INJECTION SUITE
# ==============================================================================
class VirtualAttacker:
    def __init__(self, target_ip: str = DEFAULT_TARGET_IP, target_port: int = DEFAULT_TARGET_PORT):
        self.target_ip = target_ip
        self.target_port = target_port

    def attack_udp_flood(self, count: int = 150, burst_interval_sec: float = 0.005) -> None:
        """
        [ANOMALY TYPE 1: Volumetric DoS / UDP Flood]
        Rapidly fires high-frequency UDP packets to overwhelm network buffers or edge parsers.
        Simulates a compromised IoT device acting as a botnet node or targeted DoS attacker.
        """
        print(f"\n[!] >>> [ATTACK INJECTION] Triggering High-Rate UDP Flood ({count} packets at {burst_interval_sec}s interval)...")
        spoofed_src = f"192.168.1.{random.randint(100, 200)}"
        
        for i in range(count):
            flood_payload = json.dumps({
                "attack_type": "UDP_FLOOD_BURST",
                "burst_id": i,
                "padding": "X" * random.randint(64, 512),
                "timestamp": time.time()
            }).encode('utf-8')

            pkt = craft_udp_packet(
                src_ip=spoofed_src,
                dst_ip=self.target_ip,
                src_port=random.randint(1024, 65535),
                dst_port=self.target_port,
                payload_bytes=flood_payload
            )
            send(pkt, verbose=0)
            time.sleep(burst_interval_sec)
            
        print("[!] >>> [ATTACK COMPLETED] UDP Flood finished.\n")

    def attack_malformed_payload(self, count: int = 5) -> None:
        """
        [ANOMALY TYPE 2: Malformed / Corrupted Fuzzing Payloads]
        Sends invalid JSON, non-UTF8 binary blobs, or oversized junk packets to test parser
        resilience and trigger protocol violation alerts.
        """
        print(f"\n[!] >>> [ATTACK INJECTION] Injecting {count} Malformed / Fuzzing Payloads...")
        
        malformed_samples = [
            b"\x00\xff\xfe\xba\xbe" * 20,                          # Binary garbage / heap fuzzing
            b'{"device_id": "esp32-node-01", "temp": NaN, "hum": ', # Broken truncated JSON
            b"GET /admin HTTP/1.1\r\nHost: edge-node\r\n\r\n",     # Mismatched protocol injection
            b"A" * 1024,                                           # Large buffer string
            b'{"device_id": "\x1b[31;1mINJECTED\x1b[0m", "seq": -999}' # Format escape attempt
        ]

        for i in range(count):
            sample = random.choice(malformed_samples)
            pkt = craft_udp_packet(
                src_ip="192.168.1.99",
                dst_ip=self.target_ip,
                src_port=random.randint(49152, 65535),
                dst_port=self.target_port,
                payload_bytes=sample
            )
            send(pkt, verbose=0)
            time.sleep(0.2)

        print("[!] >>> [ATTACK COMPLETED] Malformed payload injection finished.\n")

    def attack_sensor_spoof(self, count: int = 5) -> None:
        """
        [ANOMALY TYPE 3: Data Integrity / Out-of-Bounds Sensor Tampering]
        Sends syntactically valid JSON telemetry, but with physically impossible
        environmental values (e.g. 180°C, 999% humidity, or sudden catastrophic drops).
        Simulates physical sensor tampering or malicious telemetry injection.
        """
        print(f"\n[!] >>> [ATTACK INJECTION] Injecting {count} Spoofed / Out-of-Bounds Sensor Measurements...")
        
        spoofed_readings = [
            {"temp": 185.5, "humidity": 12.0, "status": "CRITICAL_OVERHEAT"},
            {"temp": -45.0, "humidity": 99.9, "status": "EXTREME_COLD"},
            {"temp": 500.0, "humidity": 999.0, "status": "IMPOSSIBLE_READING"},
            {"temp": 25.0, "humidity": -80.0, "status": "NEGATIVE_HUMIDITY"},
        ]

        for i in range(count):
            spoof_data = random.choice(spoofed_readings)
            payload = json.dumps({
                "device_id": "esp32-node-spoofed",
                "seq": 9000 + i,
                "timestamp": round(time.time(), 3),
                "sensor": "DHT11",
                "temp": spoof_data["temp"],
                "humidity": spoof_data["humidity"],
                "status": spoof_data["status"]
            }).encode('utf-8')

            pkt = craft_udp_packet(
                src_ip="192.168.1.150",
                dst_ip=self.target_ip,
                src_port=55123,
                dst_port=self.target_port,
                payload_bytes=payload
            )
            send(pkt, verbose=0)
            time.sleep(0.5)

        print("[!] >>> [ATTACK COMPLETED] Sensor spoofing injection finished.\n")


# ==============================================================================
# MAIN SIMULATION RUNNER
# ==============================================================================
def run_simulation(target_ip: str, target_port: int, interval: float, attack_prob: float):
    print("=" * 78)
    print("  NET-GUARD: Virtual ESP32 Edge Node & Telemetry Generator")
    print("=" * 78)
    print(f"[*] Target Interface : {target_ip}:{target_port} (UDP)")
    print(f"[*] Normal Cadence   : Every {interval}s")
    print(f"[*] Anomaly Chance   : {attack_prob * 100:.1f}% per cycle")
    print("=" * 78)
    print("[*] Starting telemetry transmission. Press Ctrl+C to terminate.\n")

    node = VirtualESP32Node(node_id=DEFAULT_NODE_ID, target_ip=target_ip, target_port=target_port)
    attacker = VirtualAttacker(target_ip=target_ip, target_port=target_port)

    cycle = 0
    try:
        while True:
            cycle += 1
            
            # Check if an attack should be simulated in this cycle
            if attack_prob > 0 and random.random() < attack_prob and cycle > 3:
                attack_type = random.choice(["flood", "malformed", "spoof"])
                if attack_type == "flood":
                    attacker.attack_udp_flood(count=random.randint(60, 120), burst_interval_sec=0.005)
                elif attack_type == "malformed":
                    attacker.attack_malformed_payload(count=random.randint(3, 6))
                elif attack_type == "spoof":
                    attacker.attack_sensor_spoof(count=random.randint(3, 5))
            else:
                # Standard Normal Edge Telemetry Packet
                payload = node.generate_normal_payload()
                node.send_telemetry_packet(payload)
                
                # Pretty CLI Log for operator monitoring
                data = json.loads(payload)
                print(f"[TX] Cycle #{cycle:04d} | Seq: {data['seq']:04d} | Node: {data['device_id']} | "
                      f"Temp: {data['temp']:5.2f} °C | Hum: {data['humidity']:5.2f} % | IP: {target_ip}:{target_port}")

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[!] Simulation terminated by user.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NET-GUARD Virtual ESP32 Edge Node & Attack Simulator")
    parser.add_argument("--target-ip", default=DEFAULT_TARGET_IP, help=f"Destination IP (default: {DEFAULT_TARGET_IP})")
    parser.add_argument("--port", type=int, default=DEFAULT_TARGET_PORT, help=f"UDP Port (default: {DEFAULT_TARGET_PORT})")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL, help=f"Transmission interval in sec (default: {DEFAULT_INTERVAL})")
    parser.add_argument("--attack-prob", type=float, default=0.15, help="Probability of anomaly injection per cycle (default: 0.15)")
    parser.add_argument("--attack-now", choices=["flood", "malformed", "spoof"], default=None, help="Trigger a single attack immediately and exit")
    
    args = parser.parse_args()

    if args.attack_now:
        attacker_inst = VirtualAttacker(target_ip=args.target_ip, target_port=args.port)
        if args.attack_now == "flood":
            attacker_inst.attack_udp_flood()
        elif args.attack_now == "malformed":
            attacker_inst.attack_malformed_payload()
        elif args.attack_now == "spoof":
            attacker_inst.attack_sensor_spoof()
    else:
        run_simulation(args.target_ip, args.port, args.interval, args.attack_prob)
