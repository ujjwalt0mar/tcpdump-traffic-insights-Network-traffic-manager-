"""
model.py

Trains the TCP flag classifier on leak-free behavioral features.

Key differences from the earlier version:
  - Target is the actual TCP flag combination (see features.py's
    normalize_flags), not a port-derived 'application' label.
  - Exact port number is excluded as a feature (only port CATEGORY
    is used) - so the model can't just memorize dst_port==443.
  - Uses stratified 5-fold cross-validation, not a single train/test
    split, so the reported accuracy isn't a lucky/unlucky split.
  - Reports per-class F1 and a confusion matrix, not just overall
    accuracy - overall accuracy hides poor performance on rare
    classes (e.g. RST is usually much rarer than ACK).
"""

import sys
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import classification_report, confusion_matrix
import joblib

sys.path.insert(0, ".")
from features import engineer_features, encode_features, FLAG_CLASSES


def train_and_evaluate(df, n_splits=5, random_state=42):
    X_raw, y = engineer_features(df)
    X = encode_features(X_raw)

    # Guard: warn if any class has too few samples for stratified k-fold
    class_counts = y.value_counts()
    min_class_count = class_counts.min()
    if min_class_count < n_splits:
        print(f"[warning] Smallest class ('{class_counts.idxmin()}') has only "
              f"{min_class_count} samples - below n_splits={n_splits}. "
              f"Reduce n_splits or capture more data for that flag type.")
        n_splits = max(2, min_class_count)

    clf = RandomForestClassifier(
        n_estimators=200, random_state=random_state, class_weight="balanced"
    )

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    y_pred = cross_val_predict(clf, X, y, cv=skf)

    print("=== Cross-validated classification report (5-fold) ===")
    print(classification_report(y, y_pred, zero_division=0))

    print("=== Confusion matrix ===")
    labels_present = sorted(y.unique())
    cm = confusion_matrix(y, y_pred, labels=labels_present)
    cm_df = pd.DataFrame(cm, index=labels_present, columns=labels_present)
    print(cm_df)

    # Fit final model on all data for deployment/saving
    clf.fit(X, y)

    return clf, X.columns.tolist()


def save_model(clf, feature_columns, path="flag_classifier.joblib"):
    joblib.dump({"model": clf, "feature_columns": feature_columns}, path)
    print(f"\nSaved model to {path}")


def load_model(path="flag_classifier.joblib"):
    data = joblib.load(path)
    return data["model"], data["feature_columns"]


if __name__ == "__main__":
    # Smoke test with synthetic data shaped like parser.py's real output.
    # Replace this block with: df = parse_tcpdump("tcpdump.txt") on your
    # real capture for actual results - these numbers are NOT real
    # accuracy, just a pipeline correctness check.
    import numpy as np
    np.random.seed(0)
    n = 800

    protocol = np.random.choice(["TCP", "UDP"], n, p=[0.9, 0.1])
    src_ip = np.random.choice(["192.168.1.5", "192.168.1.6", "8.8.8.8", "1.1.1.1"], n)
    dst_ip = np.random.choice(["8.8.8.8", "1.1.1.1", "192.168.1.5"], n)
    src_port = np.random.choice([443, 51000, 51500, 80, 22], n)
    dst_port = np.random.choice([443, 80, 22, 51000], n)
    length = np.random.randint(40, 1500, n)
    flags = np.random.choice(
        ["SYN", "SYN, ACK", "ACK", "FIN, ACK", "RST", "PSH, ACK"],
        n, p=[0.15, 0.1, 0.4, 0.1, 0.05, 0.2]
    )

    df = pd.DataFrame({
        "protocol": protocol, "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port,
        "length": length, "flags": flags,
    })

    clf, feature_columns = train_and_evaluate(df)
    save_model(clf, feature_columns)
