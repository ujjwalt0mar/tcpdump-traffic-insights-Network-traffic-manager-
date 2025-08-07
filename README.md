# 🛰️ tcpdump-traffic-insights-Network-traffic-manager


🔗 **Project Notebook**: `ML_Pipline.ipynb`  
📁 **Repository**: `tcpdump-traffic-insights-Network-traffic-manager-`

This project is a prototype built during an internship at **DRDO (DESIDOC)**. It analyzes and classifies TCP packets from raw tcpdump logs using machine learning and intelligent feature engineering. The goal is to detect and prioritize TCP behaviors like SYN, RST, FIN, and ACK for network-level analysis.

---

## 📌 Key Features

✅ Parses tcpdump logs into structured tabular format  
✅ Extracts TCP flags and other key metadata  
✅ Engineers features like IP direction, port type, time bins  
✅ Trains a **Random Forest** model for TCP flag classification  
✅ Visualizes flag distribution, trends, and time-based prioritization  
✅ Fully implemented in a self-contained Jupyter Notebook  

---

## 🧠 What the Notebook Does

- Reads raw `tcpdump.txt` or similar log files  
- Extracts fields: timestamp, source IP, destination IP, ports, flags  
- Converts TCP flags into one-hot encoded features  
- Categorizes ports (well-known, dynamic, private)  
- Adds metadata like packet direction and time of day  
- Trains a model to classify or predict TCP flag behavior  
- Outputs accuracy metrics and visual insights

---

## 🧪 Model Details

- 📌 **Algorithm**: RandomForestClassifier  
- 🧠 **Framework**: scikit-learn  
- 🎯 **Expected Accuracy**: ~94.7%  
- 🏷️ **Target**: TCP Flags (SYN, ACK, FIN, RST, etc.)  
- 📊 **Features**: Time bin, IP direction, port type, flag encodings  

---

## 📁 Project Structure

| File             | Purpose                                        |
|------------------|------------------------------------------------|
| `DRDO.ipynb`     | Main notebook for parsing, ML, and plots       |
| `README.md`      | This documentation                             |

---

## 🔧 Optional Files (Recommended for Modularity)

| File            | Purpose                                              |
|-----------------|------------------------------------------------------|
| `parser.py`     | Script to parse tcpdump lines into structured data   |
| `features.py`   | Feature engineering utilities for ML input prep      |
| `model.py`      | ML training and evaluation script (Random Forest)    |
| `requirements.txt` | Python dependencies list                          |

---

## 🚀 How to Use

1. Clone the repository:
   ```bash
   git clone https://github.com/ujjwalt0mar/tcpdump-traffic-insights-Network-traffic-manager-.git
   cd tcpdump-traffic-insights-Network-traffic-manager-

## 🚀 How to Use

1. **Open and run the notebook:**
   ```bash
   jupyter notebook ML_Pipline.ipynb
   ```

2. **(Optional) Run script files if modular setup is used:**
   ```bash
   python parser.py
   python features.py
   python model.py
   ```

---

## 💡 Use Cases

- DRDO or defense network traffic analysis  
- TCP packet behavior detection (SYN flood, RST scans, etc.)  
- Feature logging for firewall/IDS systems  
- Real-time prioritization of critical TCP flags  
- Educational tool for ML in networking  

---

## 🧑‍💻 Author

**Ujjwal Tomar**  
🎓 B.Tech in AI & Data Science  
📌 Management Sub-Head, CESTA  
🛡️ Intern at DESIDOC (DRDO)  
💡 Passionate about cybersecurity, ML, and network automation  

---

## 📦 Future Enhancements

- Real-time packet monitoring using `scapy`  
- Streamlit dashboard for live flag classification  
- FastAPI-based REST service for network monitoring  
- Export capabilities for SIEM tools and logging servers  
