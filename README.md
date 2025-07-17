# 🛰️ tcpdump-traffic-insights-Network-traffic-manager

🔗 GitHub Repository: [ujjwalt0mar/tcpdump-traffic-insights-Network-traffic-manager](https://github.com/ujjwalt0mar/tcpdump-traffic-insights-Network-traffic-manager-)

An intelligent system to analyze and classify TCP packet types using parsed tcpdump logs. This project extracts structured insights from raw network traffic and uses machine learning to identify, predict, and prioritize TCP flags (SYN, ACK, FIN, RST, etc.) across time and port behavior.

---

## 📌 Key Features

- ✅ Parses raw tcpdump logs into structured packet data  
- ✅ Classifies TCP packets based on flags  
- ✅ Engineers intelligent features: direction, port type, time of day  
- ✅ Trains a Random Forest model with 94.7% accuracy  
- ✅ Visualizes traffic trends and flag prioritization  
- ✅ Acts as a base for building a full network traffic monitoring dashboard

---

## 🧠 What It Does

This tool takes raw tcpdump.txt logs and:

1. Extracts source/destination IP, ports, TCP flags, and timestamp  
2. Categorizes ports (well-known, dynamic, etc.)  
3. Detects direction (inbound, outbound, external)  
4. Labels the time of day (morning, evening, etc.)  
5. One-hot encodes TCP flags (e.g., SYN, RST, ACK)  
6. Trains a machine learning model to predict packet types  
7. Analyzes time-based flag prioritization (e.g., more RSTs at night)

---

## 📊 Results

- 🎯 Accuracy: 94.7% (Random Forest Classifier)  
- 📈 Top features: time, ACK, SYN, direction, port types  
- 🧠 Output: Real-time classification of TCP packet intent  
- ✅ Ready for integration into Streamlit or FastAPI dashboards

---

## 📁 Project Structure

| File            | Purpose                                   |
|-----------------|--------------------------------------------|
| tcpdump.txt     | Input: captured tcpdump log               |
| parser.py       | Line-by-line parser for log               |
| features.py     | Feature engineering (flags, direction…)   |
| model.py        | ML training and evaluation script         |
| notebook.ipynb  | Full notebook version (optional)          |
| README.md       | You’re reading it                         |

---

## 🚀 How to Use

1. Clone this repo:
   ```bash
   git clone https://github.com/ujjwalt0mar/tcpdump-traffic-insights-Network-traffic-manager-.git
   cd tcpdump-traffic-insights-Network-traffic-manager-
