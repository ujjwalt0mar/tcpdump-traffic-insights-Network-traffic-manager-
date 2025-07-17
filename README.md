🛰️ tcpdump-traffic-insights-Network-traffic-manager
An intelligent system to analyze and classify TCP packet types using parsed tcpdump logs. This project extracts structured insights from raw network traffic and uses machine learning to identify, predict, and prioritize TCP flags (SYN, ACK, FIN, RST, etc.) across time and port behavior.

—

📌 Key Features
✅ Parses raw tcpdump logs into structured packet data
✅ Classifies TCP packets based on flags
✅ Engineers intelligent features: direction, port type, time of day
✅ Trains a Random Forest model with 94.7% accuracy
✅ Visualizes traffic trends and flag prioritization
✅ Acts as a base for building a full network traffic monitoring dashboard

—

🧠 What It Does
This tool takes raw tcpdump.txt logs and:

Extracts source/destination IP, ports, TCP flags, and timestamp

Categorizes ports (well-known, dynamic, etc.)

Detects direction (inbound, outbound, external)

Labels the time of day (morning, evening, etc.)

One-hot encodes TCP flags (e.g., SYN, RST, ACK)

Trains a machine learning model to predict packet types

Analyzes time-based flag prioritization (e.g., more RSTs at night)

—

📊 Results
🎯 Accuracy: 94.7% (Random Forest Classifier)

📈 Top features: time, ACK, SYN, direction, port types

🧠 Output: Real-time classification of TCP packet intent

✅ Ready for integration into Streamlit or FastAPI dashboards

—

📁 Project Structure
File	Purpose
tcpdump.txt	Input: captured tcpdump log
parser.py	Line-by-line parser for log
features.py	Feature engineering (flags, direction…)
model.py	ML training and evaluation script
notebook.ipynb	Full notebook version (optional)
README.md	You’re reading it

—

🚀 How to Use
Clone this repo:

bash
Copy
Edit
git clone https://github.com/your-username/tcpdump-traffic-insights-Network-traffic-manager.git
cd tcpdump-traffic-insights-Network-traffic-manager
Install requirements:

bash
Copy
Edit
pip install pandas scikit-learn matplotlib seaborn
Run the notebook or model.py:

bash
Copy
Edit
python model.py
—

💡 Use Cases
Network traffic monitoring

TCP behavior analysis

Anomaly detection

SYN/FIN prioritization patterns

Foundation for firewall or IDS automation

—

🧾 Model Details
ML Algorithm: RandomForestClassifier

Framework: scikit-learn

Evaluation: 94.7% accuracy

Label: Encoded TCP Flags

Input features: time, direction, flag types, port categories, etc.

—

👤 Author
Ujjwal Tomar
B.Tech in AI & Data Science
CESTA Management Sub-Head | Passionate about ML, Networking, and Tech Tools
