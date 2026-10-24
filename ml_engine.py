#!/usr/bin/env python3
"""Isolation Forest anomaly scoring with warmup calibration and optional checkpoint save/load."""

import os
import math
import pickle
import time
from typing import Dict, List, Tuple, Optional, Any
from features import FEATURE_NAMES

# ML Library Imports
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    np = None


DEFAULT_MODEL_PATH = "models/isolation_forest.pkl"
DEFAULT_CALIBRATION_SAMPLES = 40
ANOMALY_THRESHOLD = 0.65


class IsolationForestEngine:
    def __init__(
        self,
        calibration_samples: int = DEFAULT_CALIBRATION_SAMPLES,
        threshold: float = ANOMALY_THRESHOLD,
        model_path: str = DEFAULT_MODEL_PATH
    ):
        self.calibration_samples = calibration_samples
        self.threshold = threshold
        self.model_path = model_path
        
        self.is_calibrated = False
        self.calibration_buffer: List[List[float]] = []
        
        self.scaler = None
        self.model = None
        self.baseline_stats: Dict[str, Dict[str, float]] = {}

        if SKLEARN_AVAILABLE:
            self.scaler = StandardScaler()
            self.model = IsolationForest(
                n_estimators=100,
                max_samples='auto',
                contamination=0.04,  # Expected outlier ratio in raw training
                random_state=42
            )

        # Attempt loading pre-trained checkpoint if available
        if os.path.exists(self.model_path):
            self.load_model(self.model_path)

    def predict(self, feature_dict: Dict[str, float]) -> Dict[str, Any]:
        """
        Evaluates a feature vector and returns inference results, anomaly scores,
        threat classifications, and explainability breakdowns.
        """
        raw_vector = [feature_dict[name] for name in FEATURE_NAMES]

        # Phase 1: Model Calibration (Warmup on early baseline telemetry)
        if not self.is_calibrated:
            self.calibration_buffer.append(raw_vector)
            progress = len(self.calibration_buffer)
            
            if progress >= self.calibration_samples:
                if SKLEARN_AVAILABLE:
                    self._fit_baseline()
                else:
                    self._fit_heuristic_baseline()
            
            return {
                "status": f"CALIBRATING ({progress}/{self.calibration_samples})",
                "progress": f"{progress}/{self.calibration_samples}",
                "anomaly_score": 0.15,
                "is_anomaly": False,
                "threat_level": "CALIBRATING",
                "top_explanations": []
            }

        # Phase 2: Real-time ML Inference
        if SKLEARN_AVAILABLE and self.model is not None:
            X = np.array(raw_vector, dtype=np.float32).reshape(1, -1)
            X_scaled = self.scaler.transform(X)
            
            # IsolationForest score_samples returns negative anomaly score (-0.5 is anomalous, > -0.3 is normal)
            raw_score = self.model.score_samples(X_scaled)[0]
            # Normalize to 0.0 - 1.0 (Higher = more anomalous)
            # Scikit-learn offset is approx -0.5 for decision boundary
            normalized_score = float(1.0 / (1.0 + np.exp( (raw_score + 0.38) * 8.0 )))
            normalized_score = round(max(0.01, min(0.99, normalized_score)), 3)
        else:
            # Fallback heuristic scorer if sklearn is unavailable
            normalized_score = self._heuristic_score(feature_dict)

        is_anomaly = normalized_score >= self.threshold
        threat_level = "CRITICAL" if normalized_score >= 0.75 else ("ELEVATED" if is_anomaly else "NORMAL")

        # Phase 3: Explainability (Z-score deviation from learned baseline)
        explanations = self._explain_anomaly(feature_dict) if is_anomaly else []

        return {
            "status": "ONLINE",
            "anomaly_score": normalized_score,
            "is_anomaly": is_anomaly,
            "threat_level": threat_level,
            "top_explanations": explanations
        }

    def _fit_baseline(self) -> None:
        """Trains StandardScaler and Isolation Forest on warmup buffer."""
        X_train = np.array(self.calibration_buffer, dtype=np.float32)
        X_scaled = self.scaler.fit_transform(X_train)
        self.model.fit(X_scaled)
        
        # Calculate baseline means and standard deviations for explainability
        means = np.mean(X_train, axis=0)
        stds = np.std(X_train, axis=0)
        for idx, name in enumerate(FEATURE_NAMES):
            self.baseline_stats[name] = {
                "mean": float(means[idx]),
                "std": float(max(1e-4, stds[idx]))
            }

        self.is_calibrated = True
        print(f"\n[+] [ML ENGINE] Isolation Forest successfully trained on {len(self.calibration_buffer)} baseline samples.")
        
        # Save model checkpoint
        self.save_model(self.model_path)

    def _fit_heuristic_baseline(self) -> None:
        """Fallback baseline statistics fitting when scikit-learn is not installed."""
        num_samples = len(self.calibration_buffer)
        num_features = len(FEATURE_NAMES)
        
        for idx, name in enumerate(FEATURE_NAMES):
            vals = [self.calibration_buffer[i][idx] for i in range(num_samples)]
            mean_val = sum(vals) / num_samples
            var_val = sum((x - mean_val) ** 2 for x in vals) / num_samples
            std_val = max(1e-4, math.sqrt(var_val))
            self.baseline_stats[name] = {"mean": float(mean_val), "std": float(std_val)}

        self.is_calibrated = True
        print(f"\n[+] [ML ENGINE] Heuristic baseline calibrated on {num_samples} samples.")

    def _explain_anomaly(self, feature_dict: Dict[str, float]) -> List[Dict[str, Any]]:
        """Identifies which features exhibited the most severe deviations."""
        deviations = []
        for name in FEATURE_NAMES:
            val = feature_dict[name]
            stats = self.baseline_stats.get(name, {"mean": 0.0, "std": 1.0})
            z_score = (val - stats["mean"]) / stats["std"]
            
            if abs(z_score) > 1.8 or (name == "malformed_ratio" and val > 0):
                deviations.append({
                    "feature": name,
                    "value": val,
                    "baseline_mean": round(stats["mean"], 3),
                    "z_score": round(z_score, 2),
                    "description": self._get_feature_alert_msg(name, val, z_score)
                })

        deviations.sort(key=lambda x: abs(x["z_score"]), reverse=True)
        return deviations[:3]

    def _get_feature_alert_msg(self, name: str, val: float, z_score: float) -> str:
        if name in ["iat_mean", "iat_min"] and z_score < 0:
            return f"Severe drop in packet interval ({val*1000:.1f}ms vs baseline) -> High rate flood"
        if name == "packet_rate_pps" and z_score > 0:
            return f"Throughput surged to {val} packets/sec -> Volumetric DoS"
        if name == "shannon_entropy":
            return f"Byte randomness shifted ({val} bits) -> Non-standard or fuzzed payload"
        if name == "temp_gradient" and val > 1.0:
            return f"Physical temperature rate of change ({val}°C/s) exceeds thermal limits"
        if name == "malformed_ratio" and val > 0:
            return "Corrupted / Non-JSON payload detected in window"
        return f"Feature {name} deviated with Z-score {z_score:+.1f}"

    def _heuristic_score(self, f: Dict[str, float]) -> float:
        score = 0.15
        if f["iat_min"] < 0.1: score += 0.55
        if f["packet_rate_pps"] > 20.0: score += 0.45
        if f["malformed_ratio"] > 0: score += 0.60
        if f["temp_gradient"] > 2.0: score += 0.50
        if f["shannon_entropy"] > 6.8 or f["shannon_entropy"] < 2.0: score += 0.30
        return round(min(0.99, score), 3)

    def save_model(self, path: str) -> None:
        """Serializes trained model and baseline statistics."""
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                pickle.dump({
                    "scaler": self.scaler,
                    "model": self.model,
                    "baseline_stats": self.baseline_stats,
                    "is_calibrated": self.is_calibrated
                }, f)
            print(f"[+] [ML ENGINE] Checkpoint saved to: {path}")
        except Exception as e:
            print(f"[!] Failed to save ML checkpoint: {e}")

    def load_model(self, path: str) -> bool:
        """Loads serialized model weights."""
        try:
            with open(path, "rb") as f:
                data = pickle.load(f)
                self.scaler = data.get("scaler")
                self.model = data.get("model")
                self.baseline_stats = data.get("baseline_stats", {})
                self.is_calibrated = data.get("is_calibrated", False)
            print(f"[+] [ML ENGINE] Checkpoint loaded from: {path}")
            return True
        except Exception as e:
            print(f"[*] Starting fresh ML training: {e}")
            return False
