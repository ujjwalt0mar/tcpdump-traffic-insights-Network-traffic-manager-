"""
run_anomaly_detection.py

Runs the anomaly detector on your combined capture and prints the
flagged suspicious flows.

Run from the project root:
    python src/run_anomaly_detection.py
"""

import sys
import os
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))
from parser import parse_tcpdump
from anomaly_detector import AnomalyDetector

DATA_PATH = os.path.join("data", "tcpdump_combined.txt")

pd.set_option("display.max_columns", None)
pd.set_option("display.width", 200)

if __name__ == "__main__":
    print(f"Parsing {DATA_PATH} ...")
    df = parse_tcpdump(DATA_PATH)
    print(f"Total packets: {len(df)}\n")

    detector = AnomalyDetector(window_seconds=10, contamination=0.05)
    flows = detector.build_flow_features(df)
    print(f"Aggregated into {len(flows)} flow-windows\n")

    detector.fit(flows)
    results = detector.predict(flows)

    print("=== Top 15 most suspicious flows ===")
    print(results.head(15)[[
        "src_ip", "window_start", "packet_count", "unique_dst_ips",
        "unique_dst_ports", "syn_ratio", "rst_count", "anomaly_score", "is_suspicious"
    ]])

    print(f"\nFlagged {results['is_suspicious'].sum()} of {len(results)} flow-windows as suspicious")

    os.makedirs("models", exist_ok=True)
    detector.save(os.path.join("models", "anomaly_detector.joblib"))
