"""
run_pipeline.py

End-to-end script: parses your combined capture, trains the flag
classifier with cross-validation, and saves the model.

Run from the project root:
    python src/run_pipeline.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from parser import parse_tcpdump
from model import train_and_evaluate, save_model

DATA_PATH = os.path.join("data", "tcpdump_combined.txt")
MODEL_OUT = os.path.join("models", "flag_classifier_real.joblib")

if __name__ == "__main__":
    print(f"Parsing {DATA_PATH} ...")
    df = parse_tcpdump(DATA_PATH)
    print(f"Parsed {len(df)} rows total")

    tcp_df = df[df["protocol"] == "TCP"].copy()
    print(f"Training on {len(tcp_df)} TCP packets (rows with real flags)\n")

    clf, feature_columns = train_and_evaluate(tcp_df, n_splits=5)

    os.makedirs("models", exist_ok=True)
    save_model(clf, feature_columns, path=MODEL_OUT)
