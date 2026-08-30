# 🛰️ TCP Traffic Insights — Network Traffic Manager

A machine learning system that parses raw network captures, classifies TCP flag behavior, flags suspicious traffic patterns, and identifies which services (Amazon, Google, GitHub, etc.) your machine is talking to — all tied together in a live dashboard.

Originally built as a prototype during an internship at **DRDO (DESIDOC)**, then substantially rebuilt to fix a critical data leakage bug, add real behavioral features, and extend it from a single-notebook flag classifier into a three-part traffic analysis system.

---

## What it does

| Component | What it does | Real result |
|---|---|---|
| **Flag classifier** | Predicts TCP flag type (SYN/ACK/RST/FIN/PSH) from packet + flow features | **92% cross-validated accuracy**, no label leakage |
| **Anomaly detector** | Flags unusual traffic flows (port scans, connection bursts) with no labeled attack data needed | Isolation Forest, unsupervised, interpretable |
| **Service identifier** | Names the destination of each connection (Amazon, Google, GitHub, etc.) | **80%+ of unique destinations identified** via SNI + IP lookup |
| **Dashboard** | Live Streamlit UI tying all three together | See screenshots below |

---

## Dashboard

**Suspicious traffic detection** — flows ranked by anomaly score, with packet counts and flag ratios:

![Suspicious Traffic](screenshots\dashboard_suspicious_traffic.png)

**Service breakdown** — real traffic tagged by destination service:

![Service Breakdown](screenshots\dashboard_service_breakdown.png)

**TCP flag distribution** — real flag class counts from the trained classifier:

![Flag Distribution](screenshots\dashboard_flag_distribution.png)

---

## Architecture

```
tcpdump-traffic-insights-Network-traffic-manager/
│
├── dev-history/              # earlier attempts, kept for the debugging story (see below)
│   ├── features0.py, features1.py, features2.py
│   ├── model0.py, model1.py, model2.py
│   ├── parser0.py, parser1.py, parser2.py
│   └── ML_pipeline0.ipynb, ML_pipeline1.ipynb
│
├── src/                       # working pipeline
│   ├── parser.py              # tshark text output → structured DataFrame (flags, TCP options, etc.)
│   ├── features.py            # leak-free feature engineering + flow-position features
│   ├── model.py                # trains + cross-validates the flag classifier
│   ├── sni_extractor.py        # pulls service names from tshark's decoded TLS SNI
│   ├── service_identifier.py   # IP-range + reverse-DNS fallback for service ID
│   ├── anomaly_detector.py     # Isolation Forest on aggregated flow features
│   ├── dashboard.py            # Streamlit dashboard
│   ├── run_pipeline.py         # end-to-end: parse → train → save model
│   ├── run_anomaly_detection.py
│   └── run_service_identification.py
│
├── data/                       # raw captures (not committed — see .gitignore)
├── models/                     # trained model artifacts (.joblib)
├── scripts/
│   ├── capture_traffic.ps1     # Windows capture script (tshark-based)
│   └── capture_traffic.sh      # Linux/Mac capture script (tcpdump-based)
├── docs/screenshots/
├── .streamlit/config.toml      # dashboard theme
├── requirements.txt
└── README.md
```

---

## Setup

```powershell
pip install -r requirements.txt
```

**Capture traffic** (Windows, requires Wireshark/tshark installed):
```powershell
.\scripts\capture_traffic.ps1 -Duration 300 -InterfaceNumber <your interface> -OutFile data\tcpdump_session1.txt
```
Run multiple sessions, then combine:
```powershell
Get-Content data\tcpdump_session*.txt | Set-Content data\tcpdump_combined.txt
```

**Train the flag classifier:**
```powershell
python src\run_pipeline.py
```

**Run anomaly detection:**
```powershell
python src\run_anomaly_detection.py
```

**Run service identification:**
```powershell
python src\run_service_identification.py
```

**Launch the dashboard:**
```powershell
python -m streamlit run src\dashboard.py
```

---

## Model details

- **Algorithm:** RandomForestClassifier (flag classifier), IsolationForest (anomaly detector)
- **Target:** TCP flag class — SYN, SYN-ACK, ACK, FIN-ACK, PSH-ACK, RST
- **Features:** protocol, packet length, port category (well-known/registered/dynamic — not exact port), connection direction, TCP options (MSS/SACK_PERM/WS — present only on handshake packets), and flow-position features (packet index within flow, time since flow start, time since previous packet in flow)
- **Validation:** stratified 5-fold cross-validation, not a single train/test split
- **Result:** 92% accuracy overall; 100% on RST/SYN/SYN-ACK; 84%/63% precision/recall on FIN-ACK (the hardest class — genuinely similar to a steady-state ACK when a connection idles before closing)

---

## Development Journey

This project went through several real iterations — kept in `dev-history/` rather than deleted, because the debugging process is part of the story:

1. **Original prototype** (`parser0-2.py`, `model0-2.py`) — a working end-to-end pipeline, but the reported ~94.7% accuracy was measuring the wrong thing: the model predicted an `application` label (HTTPS/OTHER) that was *itself defined* by the destination port — and the destination port was also fed in as a feature. The model wasn't learning traffic behavior; it was re-deriving a rule already written in the parser (**label leakage**). The suspiciously perfect classification report was the tell.

2. **First real fix** — rebuilt the target to be the actual TCP flag (not a port-derived label), and rebuilt the parser to actually extract flags (it previously wasn't extracting them at all — `features.py` referenced a `flags` field the parser never produced). Removed exact port number as a feature to eliminate any leakage risk. Result: **17% accuracy** — correct behavior for genuinely leak-free features that turned out not to carry much signal on their own (SYN/SYN-ACK/ACK all shared similar length and port characteristics).

3. **Second fix** — added real TCP option fields (MSS, SACK_PERM, WS, window size), which are genuinely present only in handshake packets — not label leakage, just previously-unparsed protocol signal. Result: **67% accuracy**, perfect on RST/SYN/SYN-ACK, but ACK/FIN-ACK still confused.

4. **Third fix** — added flow-position features (packet index within the connection, time since the flow started, time since the previous packet in that flow), since a `FIN-ACK` is fundamentally about *when* in a connection's life a packet occurs, not just its static fields. Result: **92% accuracy**, the current model.

5. **Along the way:** fixed a Windows-specific bug where reverse-DNS lookups for the service identifier could silently fall back to LLMNR/NetBIOS resolution and mislabel unrelated remote IPs as the local machine's own hostname.

---

## Future Enhancements

- Real-time packet monitoring using `scapy`
- FastAPI-based REST service for network monitoring
- Export capabilities for SIEM tools and logging servers
- Improve FIN-ACK/PSH-ACK separation with additional flow-level features (e.g. bytes transferred so far in the flow)

---

## Use Cases

- DRDO or defense network traffic analysis
- TCP packet behavior detection (SYN floods, RST scans, etc.)
- Feature logging for firewall/IDS systems
- Educational tool for ML in networking

---

## Author

**Ujjwal Tomar**
🎓 B.Tech in AI & Data Science, Delhi Technical Campus (GGSIPU)
📌 General Secretary, GDGoC Delhi Technical Campus
🛡️ ML Intern at DESIDOC (DRDO)