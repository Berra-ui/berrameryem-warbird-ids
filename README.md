# ✈️ Warbird: AI-Powered Intrusion Detection System for Fighter Jets

**Warbird** is a simple Python-based IDS (Intrusion Detection System) using AI to detect anomalous network behavior in a simulated military aircraft scenario.

## 🚀 Features
- TCP packet sniffing using Scapy
- Feature extraction (port numbers, packet size)
- Anomaly detection using Isolation Forest (AI)
- Logs events to `ids_log.txt`

## 🔧 Technologies
- Python 3
- Scapy
- scikit-learn
- NumPy
- Logging

## 🛡️ Use Case
Simulates how a fighter aircraft system can detect and log unauthorized or suspicious network activity in real-time.

## 💻 Usage
```bash
sudo python jet_ids.py
