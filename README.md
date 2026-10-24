# net-guard

Passive network intrusion detection for small IoT deployments. ESP32 nodes send DHT11 readings over UDP; a host sniffs that traffic (loopback in simulation, SPAN mirror on hardware), extracts windowed features, and flags anomalies with an Isolation Forest model. A static dashboard consumes live metrics over Server-Sent Events.

## Requirements

- Python 3.10+
- Windows: [Npcap](https://npcap.com/) if you use Scapy capture on loopback
- Dependencies: `pip install -r requirements.txt`

## Run (simulation)

Terminal 1 — telemetry + optional attack modes:

```bash
python sim_edge_node.py --mode normal
```

Terminal 2 — API, sniffer, ML, and static UI:

```bash
python api_bridge.py --port 8080 --sniff-port 5005
```

Open `http://127.0.0.1:8080/`.

Terminal 3 (optional) — standalone listener without the dashboard:

```bash
python nids_listener.py
```

Smoke test:

```bash
python test_pipeline.py
```

## Layout

| Path | Role |
|------|------|
| `sim_edge_node.py` | UDP telemetry generator and attack simulation |
| `nids_listener.py` | Passive sniffer and heuristic checks |
| `features.py` | Rolling-window feature extraction |
| `ml_engine.py` | Isolation Forest scoring and calibration |
| `forensics.py` | Alert logs and optional PCAP dumps |
| `api_bridge.py` | HTTP server and SSE stream for the UI |
| `firmware/esp32_dht11_udp.ino` | ESP32 + DHT11 firmware for lab hardware |
| `index.html`, `js/`, `css/` | Dashboard |

## Hardware

Target topology: ESP32 → managed switch with port mirroring (e.g. TP-Link TL-SG105E) → NIDS host on the mirror port. Point the sniffer at the mirror interface and match UDP port `5005` (see firmware and `sim_edge_node.py` for payload format).

## License

No license file yet — treat as private academic work unless you add one.
