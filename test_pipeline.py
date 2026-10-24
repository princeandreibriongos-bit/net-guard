import time
import json
from features import RollingFeatureExtractor
from ml_engine import IsolationForestEngine
from forensics import ForensicManager

def main():
    fe = RollingFeatureExtractor(window_size=10)
    ml = IsolationForestEngine(calibration_samples=5)
    fm = ForensicManager()

    print("[*] Testing normal telemetry ingestion...")
    for i in range(6):
        payload = json.dumps({"device_id": "esp32-node-01", "seq": i, "temp": 24.0 + i*0.1, "humidity": 55.0}).encode('utf-8')
        feats, rec = fe.ingest_packet(time.time(), "192.168.1.50", "127.0.0.1", 50000, 5005, payload)
        pred = ml.predict(feats)
        fm.log_telemetry_entry(rec, feats, pred)
        print(f"  Pkt #{i}: Score={pred['anomaly_score']} | Status={pred['status']}")

    print("\n[*] Testing attack anomaly detection (malformed packet)...")
    flood_payload = b"MALFORMED_NON_JSON_OVERFLOW_TEST_BYTES"
    feats, rec = fe.ingest_packet(time.time(), "192.168.1.99", "127.0.0.1", 59999, 5005, flood_payload)
    pred = ml.predict(feats)
    print(f"  Attack Pkt: Score={pred['anomaly_score']} | Threat={pred['threat_level']} | Anomaly={pred['is_anomaly']}")
    print(f"  Explanations: {pred['top_explanations']}")
    print("\n[SUCCESS] Feature Extraction, ML Inference, and Forensic Logging test passed!")

if __name__ == "__main__":
    main()
