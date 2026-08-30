"""
anomaly_detector.py

Flags suspicious traffic using unsupervised anomaly detection.

Design choice (important): we do NOT run Isolation Forest on raw
per-packet rows. A single packet rarely looks "suspicious" on its
own - it's the PATTERN across packets (e.g. one source IP hitting
50 different destination ports in 5 seconds = port scan) that
matters. So this module:

  1. Aggregates raw parsed packets into per-source-IP flow windows
     (e.g. all packets from one IP within a rolling time bucket).
  2. Builds flow-level features from that aggregation.
  3. Trains Isolation Forest on those flow-level features.
  4. Flags flows (not individual packets) as suspicious.

This also means: no labeled "attack" data required. It learns what
"normal" looks like from your own captured traffic and flags
deviations - genuinely defensible as "unsupervised" in an interview,
unlike claiming a model "detects intrusions" with no ground truth.

Usage:
    from anomaly_detector import AnomalyDetector

    detector = AnomalyDetector()
    flows_df = detector.build_flow_features(raw_packets_df)
    detector.fit(flows_df)                      # train on "mostly normal" data
    flagged = detector.predict(flows_df)         # -> adds 'is_suspicious', 'anomaly_score'

Expected input (raw_packets_df) columns - adjust names in
build_flow_features() to match your actual parser.py output:
    timestamp, src_ip, dst_ip, src_port, dst_port, flags
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib


class AnomalyDetector:

    FEATURE_COLUMNS = [
        "packet_count",
        "unique_dst_ips",
        "unique_dst_ports",
        "syn_count",
        "syn_ratio",
        "rst_count",
        "avg_inter_packet_time",
        "bytes_estimate",
    ]

    def __init__(self, window_seconds=10, contamination=0.05, random_state=42):
        """
        window_seconds: size of the rolling time bucket used to group
                         packets into a "flow" per source IP. Smaller
                         windows catch fast port scans; larger windows
                         catch slow, low-and-slow exfiltration attempts.
        contamination:  expected proportion of anomalies in training
                         data (Isolation Forest hyperparameter). 0.05
                         is a reasonable starting point - tune based
                         on what fraction of your captured traffic you
                         actually believe is suspicious.
        """
        self.window_seconds = window_seconds
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=200,
        )
        self.scaler = StandardScaler()
        self._is_fitted = False

    def build_flow_features(self, df, time_col="time",
                             src_ip_col="src_ip", dst_ip_col="dst_ip",
                             dst_port_col="dst_port", flags_col="flags",
                             length_col="length"):
        """
        Aggregates raw packet rows into per-source-IP, per-time-window
        flow features.

        Matches parser.py's actual output: 'time' is a float (seconds,
        e.g. from tshark's relative time column), not a datetime -
        so windowing is done with integer division instead of
        pandas' dt.floor().
        """
        df = df.copy()
        df["_window"] = (df[time_col] // self.window_seconds) * self.window_seconds

        rows = []
        grouped = df.groupby([src_ip_col, "_window"])
        for (src_ip, window), group in grouped:
            flags = group[flags_col].astype(str)
            syn_count = flags.str.contains("SYN", case=False, na=False).sum()
            rst_count = flags.str.contains("RST", case=False, na=False).sum()
            packet_count = len(group)

            times_sorted = group[time_col].sort_values()
            inter_times = times_sorted.diff().dropna()
            avg_inter_packet_time = inter_times.mean() if len(inter_times) > 0 else 0.0

            rows.append({
                "src_ip": src_ip,
                "window_start": window,
                "packet_count": packet_count,
                "unique_dst_ips": group[dst_ip_col].nunique(),
                "unique_dst_ports": group[dst_port_col].nunique(),
                "syn_count": syn_count,
                # SYNs with no matching ACK is a classic scan signature
                "syn_ratio": syn_count / packet_count if packet_count else 0,
                "rst_count": rst_count,
                "avg_inter_packet_time": avg_inter_packet_time,
                # real byte length, straight from parser.py's 'length' field
                "bytes_estimate": group[length_col].sum(),
            })

        return pd.DataFrame(rows)

    def fit(self, flows_df):
        """Train on flow-level features. Assumes MOSTLY normal traffic -
        Isolation Forest tolerates some contamination but a training set
        that's mostly attacks will learn the wrong 'normal'."""
        X = flows_df[self.FEATURE_COLUMNS].fillna(0)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self._is_fitted = True
        return self

    def predict(self, flows_df):
        """Returns flows_df with 'anomaly_score' and 'is_suspicious' columns.
        Lower anomaly_score = more anomalous (Isolation Forest convention)."""
        if not self._is_fitted:
            raise RuntimeError("Call .fit() before .predict()")

        X = flows_df[self.FEATURE_COLUMNS].fillna(0)
        X_scaled = self.scaler.transform(X)

        result = flows_df.copy()
        result["anomaly_score"] = self.model.decision_function(X_scaled)
        result["is_suspicious"] = self.model.predict(X_scaled) == -1  # -1 = anomaly
        return result.sort_values("anomaly_score")

    def save(self, path="anomaly_model.joblib"):
        joblib.dump({"model": self.model, "scaler": self.scaler,
                     "window_seconds": self.window_seconds}, path)

    @classmethod
    def load(cls, path="anomaly_model.joblib"):
        data = joblib.load(path)
        detector = cls(window_seconds=data["window_seconds"])
        detector.model = data["model"]
        detector.scaler = data["scaler"]
        detector._is_fitted = True
        return detector


if __name__ == "__main__":
    # Minimal smoke test with synthetic data matching parser.py's real
    # output shape ('time' as float seconds) - replace with your
    # actual parsed tcpdump.txt output for a real run.
    np.random.seed(0)
    n_normal = 200
    n_attack = 10

    normal = pd.DataFrame({
        "time": np.arange(n_normal) * 0.5,
        "src_ip": np.random.choice(["10.0.0.5", "10.0.0.6"], n_normal),
        "dst_ip": np.random.choice(["93.184.216.34", "142.250.195.100"], n_normal),
        "dst_port": np.random.choice([443, 80], n_normal),
        "flags": np.random.choice(["ACK", "SYN, ACK"], n_normal),
        "length": np.random.randint(60, 1500, n_normal),
    })

    # simulate a port scan: one source IP, many destination ports, tight timing
    attack = pd.DataFrame({
        "time": 5.0 + np.arange(n_attack) * 0.02,
        "src_ip": ["10.0.0.99"] * n_attack,
        "dst_ip": ["10.0.0.1"] * n_attack,
        "dst_port": range(1000, 1000 + n_attack),
        "flags": ["SYN"] * n_attack,
        "length": [60] * n_attack,
    })

    combined = pd.concat([normal, attack], ignore_index=True)

    detector = AnomalyDetector(window_seconds=10, contamination=0.1)
    flows = detector.build_flow_features(combined)
    detector.fit(flows)
    results = detector.predict(flows)

    print(results[["src_ip", "window_start", "packet_count", "unique_dst_ports",
                    "syn_ratio", "bytes_estimate", "anomaly_score", "is_suspicious"]])
