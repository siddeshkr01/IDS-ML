# Intrusion Detection System (IDS) using Machine Learning on Flow-based Features

**Project Title:**  
Real-Time Network Intrusion Detection System using Flow-based Machine Learning

---

## 📄 Project Description

This project implements a real-time Intrusion Detection System (IDS) using flow-based feature extraction from network traffic. The system extracts flow-level features directly from captured packet data, trains a machine learning model using the TON_IoT dataset, and performs live intrusion detection using PyShark in real-time.

The project simulates a professional IDS pipeline following CICFlowMeter-style feature extraction using 5-tuple based flows.

---

## 📂 Project Structure

```
IDS/
│
├── data/
│   ├── raw_pcap/              # Reduced PCAP files (training dataset)
│   ├── TON_IoT/               # Extracted flow-level Train.csv
│   ├── processed/             # Reduced feature dataset (reduced_train.csv)
│   └── extracted_csv/         # Live captured flows (output_flows.csv)
│
├── models/                    # Trained ML model & encoders
│
├── src/                       # All project source code
│
├── master_pipeline.py         # One-click master automation file
│
├── README.md                  # This file
├── requirements.txt           # Python dependencies
└── CNS_Synopsis_2025ids.pdf   # Project report
```

---

## 📊 Dataset Used

- **Dataset:** TON_IoT Network Dataset (2020)
- **Source:** [CIC-TON-IoT Dataset](https://research.unsw.edu.au/projects/toniot-datasets)
- The dataset includes normal and multiple attack types such as:
  - DoS, DDoS, Password attacks, MITM, Scanning, Injection, XSS, Ransomware, etc.

- **Note:**  
  For this project, only selected PCAP files were extracted and reduced to create a lightweight, demo-ready dataset.

---

## 🚀 Pipeline Stages

| Stage | Description |
|-------|-------------|
| 1️⃣ Flow Extraction | Extracts flows using PyShark with bidirectional bytes and dynamic TCP flags |
| 2️⃣ Feature Reduction | Keeps only the selected features for training |
| 3️⃣ Model Training | Trains Random Forest model |
| 4️⃣ Live IDS | Captures 10 seconds of live traffic and predicts |

---

## ⚙️ Dependencies

Install all dependencies inside your virtual environment:

```bash
pip install -r requirements.txt
```

Main libraries:
- pandas
- scikit-learn
- pyshark
- joblib
- tshark (must be installed on system, comes with Wireshark)

👉 **Tshark Installation:**  
Download and install Wireshark:  
https://www.wireshark.org/download.html

✅ Ensure `tshark` is accessible from system PATH.

---

## 🚀 Running The Full Pipeline

### 1️⃣ Activate virtual environment

```bash
cd IDS
venv\Scripts\activate   # for Windows

# OR

source venv/bin/activate  # for Linux/Mac
```

### 2️⃣ Run complete pipeline:

```bash
python master_pipeline.py
```

✅ This will automatically:

- Extract flows  
- Reduce dataset  
- Train model  
- Start live real-time intrusion detection

### 3️⃣ During live detection:

- The system will capture 10 seconds of live network traffic.
- Extract features.
- Perform ML prediction and display output labels in real-time.

---

## 🎯 Flow Features Used

- protocol_type
- src_ip
- dst_ip
- src_port
- dst_port
- flag (extracted dynamically from TCP flags)
- src_bytes
- dst_bytes
- duration
- count

---

## 📡 Real-Time Capture Interface

By default, the interface is set to `Wi-Fi` (Windows):

```bash
interface='Wi-Fi'
```

Change this in `real_time_detector.py` if using different network interface.

---

## ✅ Project Status

- ✅ Fully functional flow-based real-time IDS
- ✅ Live prediction using trained ML model
- ✅ End-to-end automation using master pipeline
- ✅ Clean code structure for submission

---

## 🔬 Authors

- SIDDESH K R
- SUBRAMANYA G M

---

## 🔖 Acknowledgement

- TON_IoT Dataset - UNSW Canberra
- CICFlowMeter concepts inspired the flow feature extraction methodology.

---
