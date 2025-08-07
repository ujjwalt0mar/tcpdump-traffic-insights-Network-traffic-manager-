# 🛰️ tcpdump-traffic-insights-Network-traffic-manager


🔗 **Project Notebook**: `ML_Pipline.ipynb`  
📁 **Repository Name**: `tcpdump-traffic-insights-Network-traffic-manager-`

This project is a prototype designed during an internship at DRDO (DESIDOC) to classify TCP packet types from parsed tcpdump logs and derive structured insights from raw network traffic. It uses machine learning to identify and prioritize packet behavior across time and port patterns.

---

## 📌 Key Features

✅ Parses tcpdump logs into structured tabular format  
✅ Extracts and processes TCP flags (SYN, ACK, FIN, RST, etc.)  
✅ Feature engineering for IP direction, port types, and timestamp bins  
✅ Trains a Random Forest Classifier for flag prediction  
✅ Visualizes traffic patterns over time  
✅ Built as a single, self-contained Jupyter Notebook (`DRDO.ipynb`)  

---

## 🧠 What the Notebook Does

- Reads and parses raw tcpdump lines  
- Splits fields like IP, ports, flags, sequence numbers  
- Encodes TCP flags into machine-readable features  
- Classifies packet types using `RandomForestClassifier`  
- Plots flag distribution and time-based behavior  

---

## 🧪 Model Details

- 📌 **Algorithm**: RandomForestClassifier  
- 🧠 **Framework**: scikit-learn  
- 🎯 **Expected Accuracy**: ~94–95% (based on historical runs)  
- 🏷️ **Labels**: Encoded TCP Flags (e.g., SYN, ACK, FIN, RST)  
- 📊 **Features**: Time bins, IP types, port roles, and one-hot encoded flags  

---

## 📁 Project Structure

| File           | Purpose                                      |
|----------------|----------------------------------------------|
| `DRDO.ipynb`   | All parsing, training, and visualization code |
| `README.md`    | This documentation file                      |
| *(Optional)* `parser.py` | Script version of parsing logic   |
| *(Optional)* `features.py` | Script for feature engineering  |

---

## 🚀 How to Use

1. Clone the repo or download the `.ipynb` file:
   ```bash
   git clone https://github.com/ujjwalt0mar/tcpdump-traffic-insights-Network-traffic-manager-.git
   cd tcpdump-traffic-insights-Network-traffic-manager-

## 🚀 How to Use

1. **Open and run the notebook:**
   ```bash
   jupyter notebook DRDO.ipynb
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
