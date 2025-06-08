# Intrusion Detection System (IDS) Using AI/ML

This project implements a Machine Learning-based Intrusion Detection System (IDS) that detects malicious network traffic using ensemble techniques. It captures network traffic (via Wireshark), extracts features, preprocesses them, trains models, and offers real-time predictions using a Streamlit interface.

## 📁 Project Structure
```
IDS/
├── data/                 # Network traffic data files
│   ├── raw_pcap/         # .pcap files from Wireshark
│   ├── extracted_csv/    # CSV files from pcap
│   └── processed/        # Cleaned/preprocessed datasets
├── models/               # Trained model files (.pkl)
├── notebooks/            # Jupyter notebooks for exploration
├── src/                  # Python scripts for ML pipeline
├── utils/                # Helper files and feature config
├── tests/                # Unit tests
├── app/                  # Streamlit app
├── requirements.txt      # Dependencies
├── Dockerfile            # Docker container setup
├── .dockerignore         # Docker exclusions
├── .gitignore            # Git exclusions
└── README.md             # This file
```

## 🚀 Getting Started

### 1. Install Requirements
```bash
pip install -r requirements.txt
```

### 2. Preprocess Data and Train Model
```bash
python src/train_models.py
```

### 3. Evaluate Trained Model
```bash
python src/evaluate_models.py
```

### 4. Make Predictions on New Data
```bash
python src/predict.py
```

### 5. Run the Streamlit Web App
```bash
streamlit run app/streamlit_app.py
```

Upload a CSV file with features to see predictions and intrusion alerts.

---

## 🧪 Run Unit Tests (Optional)
```bash
pip install pytest
pytest tests/
```

---

## 🐳 Docker Usage (Optional)
### 1. Build Docker image
```bash
docker build -t ids-app .
```

### 2. Run Docker container
```bash
docker run -p 8501:8501 ids-app
```

Then open [http://localhost:8501](http://localhost:8501) to view the app.

---

## 🔍 Dataset Format
Example expected CSV columns:
```
duration,protocol_type,service,src_bytes,dst_bytes,flag,land,wrong_fragment,urgent,label
```
Where `label` is `normal` or `attack`.

---

## 👥 Authors
- **ML Development**: Your Name
- **Wireshark & Packet Capture**: Your Friend's Name

---

## 📜 License
This project is for educational use only under the terms of your institution's academic policy.
