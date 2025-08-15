# model.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from parser import parse_file
from features0 import enrich_features

# Step 1: Parse and preprocess
df = parse_file("tcpdump.txt")
if df.empty:
    print("No valid data parsed from tcpdump.txt")
    exit()

df = enrich_features(df)

# Step 2: Select features and label
features = [
    'time', 'ACK', 'FIN', 'PSH', 'RST', 'SYN',
    'src_port_cat_unknown', 'dst_port_cat_dynamic', 'dst_port_cat_unknown',
    'dst_port_cat_well_known', 'direction_external', 'direction_inbound',
    'direction_outbound', 'timeofday_night'
]
X = df[features]
y = df['flag_encoded']

# Step 3: Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Step 4: Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Step 5: Evaluate
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print("Model Accuracy:", accuracy)
