from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

# ===== 1. Select features =====
feature_cols = [
    "src_port", "dst_port",
    "direction_inbound", "direction_outbound", "direction_external",
    "ACK", "FIN", "PSH", "RST", "SYN",
    "timeofday_night"
]

# Add one-hot encoded columns for port categories
feature_cols += [c for c in df.columns if "src_port_cat_" in c or "dst_port_cat_" in c]

# ===== 2. Define X and y =====
X = df[feature_cols]
y = df["label"]

# ===== 3. Train-Test Split =====
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# ===== 4. Train Model =====
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# ===== 5. Predictions & Evaluation =====
y_pred = clf.predict(X_test)

print("Classification Report:\n", classification_report(y_test, y_pred))
print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
