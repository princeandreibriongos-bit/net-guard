#!/usr/bin/env python3
"""Sliding-window stats and sensor gradients from parsed UDP telemetry packets."""

import math
import json
import time
from collections import deque
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any

try:
    import numpy as np
except ImportError:
    np = None


# Feature vector column definitions
FEATURE_NAMES = [
    "iat_mean",
    "iat_std",
    "iat_min",
    "packet_rate_pps",
    "payload_len_mean",
    "payload_len_std",
    "shannon_entropy",
    "temp_gradient",
    "humidity_gradient",
    "malformed_ratio"
]


def calculate_shannon_entropy(payload_bytes: bytes) -> float:
    """
    Computes Shannon Entropy: H(X) = - sum(P(x) * log2(P(x)))
    Returns a value between 0.0 (identical repeated bytes) and 8.0 (pure random byte distribution).
    """
    if not payload_bytes:
        return 0.0

    length = len(payload_bytes)
    freq_map: Dict[int, int] = {}
    for byte in payload_bytes:
        freq_map[byte] = freq_map.get(byte, 0) + 1

    entropy = 0.0
    for count in freq_map.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


@dataclass
class PacketRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload_len: int
    payload_bytes: bytes
    entropy: float
    parsed_json: Optional[Dict[str, Any]] = None
    is_malformed: bool = False
    temp: Optional[float] = None
    humidity: Optional[float] = None
    seq: Optional[int] = None


class RollingFeatureExtractor:
    """
    Maintains a sliding ring buffer of recent packet records to compute
    rolling statistical features for the unsupervised ML engine.
    """
    def __init__(self, window_size: int = 20, max_time_window_sec: float = 15.0):
        self.window_size = window_size
        self.max_time_window_sec = max_time_window_sec
        self.buffer: deque[PacketRecord] = deque(maxlen=window_size)
        self.last_valid_temp: Optional[float] = None
        self.last_valid_humidity: Optional[float] = None
        self.last_sensor_time: Optional[float] = None

    def ingest_packet(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        payload_bytes: bytes
    ) -> Tuple[Dict[str, float], PacketRecord]:
        """
        Parses a raw packet, calculates its properties, pushes it to the rolling window,
        and returns the current feature vector and packet record.
        """
        entropy = calculate_shannon_entropy(payload_bytes)
        payload_len = len(payload_bytes)
        
        # Deep packet inspection attempt on payload
        parsed_json = None
        is_malformed = False
        temp_val = None
        hum_val = None
        seq_val = None

        try:
            payload_str = payload_bytes.decode('utf-8')
            parsed = json.loads(payload_str)
            if isinstance(parsed, dict):
                parsed_json = parsed
                temp_val = parsed.get("temp")
                hum_val = parsed.get("humidity")
                seq_val = parsed.get("seq")
            else:
                is_malformed = True
        except Exception:
            is_malformed = True

        record = PacketRecord(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            payload_len=payload_len,
            payload_bytes=payload_bytes,
            entropy=entropy,
            parsed_json=parsed_json,
            is_malformed=is_malformed,
            temp=temp_val,
            humidity=hum_val,
            seq=seq_val
        )

        self.buffer.append(record)

        # Compute rolling window metrics
        features = self._compute_features(record)
        return features, record

    def _compute_features(self, current: PacketRecord) -> Dict[str, float]:
        """
        Computes the 10-dimensional feature dictionary from the current sliding buffer.
        """
        n = len(self.buffer)
        
        # 1. Inter-Arrival Times (IAT)
        if n > 1:
            timestamps = [p.timestamp for p in self.buffer]
            iats = [timestamps[i] - timestamps[i - 1] for i in range(1, n)]
            
            # Prevent negative or zero zero-divisions
            iats = [max(0.0001, iat) for iat in iats]
            iat_mean = float(sum(iats) / len(iats))
            iat_variance = sum((x - iat_mean) ** 2 for x in iats) / len(iats)
            iat_std = float(math.sqrt(iat_variance))
            iat_min = float(min(iats))
            
            total_duration = max(0.001, timestamps[-1] - timestamps[0])
            packet_rate_pps = float(n / total_duration)
        else:
            iat_mean = 2.0
            iat_std = 0.0
            iat_min = 2.0
            packet_rate_pps = 0.5

        # 2. Payload Length Statistics
        payload_lens = [p.payload_len for p in self.buffer]
        payload_len_mean = float(sum(payload_lens) / n)
        payload_len_var = sum((x - payload_len_mean) ** 2 for x in payload_lens) / n
        payload_len_std = float(math.sqrt(payload_len_var))

        # 3. Shannon Entropy
        shannon_entropy = current.entropy

        # 4. Sensor Rate of Change (Gradients)
        temp_gradient = 0.0
        humidity_gradient = 0.0

        if current.temp is not None and self.last_valid_temp is not None and self.last_sensor_time is not None:
            dt = max(0.1, current.timestamp - self.last_sensor_time)
            temp_gradient = abs(current.temp - self.last_valid_temp) / dt
            if current.humidity is not None and self.last_valid_humidity is not None:
                humidity_gradient = abs(current.humidity - self.last_valid_humidity) / dt

        if current.temp is not None and not current.is_malformed:
            self.last_valid_temp = current.temp
            self.last_valid_humidity = current.humidity
            self.last_sensor_time = current.timestamp

        # 5. Malformed Packet Proportion
        malformed_count = sum(1 for p in self.buffer if p.is_malformed)
        malformed_ratio = float(malformed_count / n)

        feature_dict = {
            "iat_mean": round(iat_mean, 5),
            "iat_std": round(iat_std, 5),
            "iat_min": round(iat_min, 5),
            "packet_rate_pps": round(packet_rate_pps, 2),
            "payload_len_mean": round(payload_len_mean, 2),
            "payload_len_std": round(payload_len_std, 2),
            "shannon_entropy": round(shannon_entropy, 4),
            "temp_gradient": round(temp_gradient, 4),
            "humidity_gradient": round(humidity_gradient, 4),
            "malformed_ratio": round(malformed_ratio, 4)
        }

        return feature_dict

    def to_numpy_array(self, feature_dict: Dict[str, float]):
        """Converts feature dict to ordered NumPy vector."""
        if np is None:
            return [feature_dict[name] for name in FEATURE_NAMES]
        return np.array([feature_dict[name] for name in FEATURE_NAMES], dtype=np.float32).reshape(1, -1)
