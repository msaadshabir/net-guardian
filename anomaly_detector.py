# anomaly_detector.py
import os
import json
import pickle
from sklearn.ensemble import IsolationForest
from datetime import datetime

class NetworkAnomalyDetector:
    def __init__(self, model_file="anomaly_model.pkl"):
        self.model_file = model_file
        # contamination=0.1 means "expect 10% of scans to be anomalies"
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False
        self._load_model()

    def _load_model(self):
        """Load trained model if it exists"""
        if os.path.exists(self.model_file):
            try:
                with open(self.model_file, 'rb') as f:
                    self.model = pickle.load(f)
                self.is_trained = True
                print("Loaded existing anomaly detection model")
            except Exception as e:
                print(f"Could not load model: {e}")

    def _save_model(self):
        """Save trained model to disk"""
        try:
            with open(self.model_file, 'wb') as f:
                pickle.dump(self.model, f)
            print("Saved anomaly detection model")
        except Exception as e:
            print(f"Could not save model: {e}")

    def _extract_features(self, devices):
        """Convert devices to numbers ML can understand"""
        features = []
        for d in devices:
            port_count = len(d['open_ports'])
            mac_prefix = d['mac'].replace(':', '')[:6]
            is_iot = 1 if mac_prefix in {'B827EB', 'A4C138', 'CC50E3', 'D831CF'} else 0
            hour = datetime.now().hour
            features.append([port_count, is_iot, hour])
        return features

    def train(self, devices):
        """Learn what 'normal' looks like"""
        X = self._extract_features(devices)
        self.model.fit(X)
        self.is_trained = True
        self._save_model()
        print("Trained on current network state (this is now 'normal')")

    def find_anomalies(self, devices):
        """Return IPs that look suspicious"""
        if not self.is_trained:
            return []
        X = self._extract_features(devices)
        predictions = self.model.predict(X)  # -1 = anomaly, 1 = normal
        return [d['ip'] for d, pred in zip(devices, predictions) if pred == -1]