import os
import time
import subprocess
import pandas as pd
import joblib

PCAP_PATH = 'data/raw_pcap/live.pcap'
CSV_PATH = 'data/extracted_csv/output_flows.csv'

model = joblib.load('models/final_ids_model.pkl')
scaler = joblib.load('models/scaler.pkl')
le_dict = joblib.load('models/label_encoders.pkl')
label_encoder = joblib.load('models/label_encoder.pkl')

REQUIRED_FEATURES = model.feature_names_in_ if hasattr(model, "feature_names_in_") else []

def capture_pcap(duration=10):
    print(f"📡 Capturing {duration} seconds of traffic...")
    os.makedirs(os.path.dirname(PCAP_PATH), exist_ok=True)
    subprocess.run(['tshark', '-i', 'Wi-Fi', '-a', f'duration:{duration}', '-w', PCAP_PATH], check=True)

def extract_flows():
    print("⚙️ Extracting flows using Python CICFlowMeter...")
    os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
    subprocess.run(['cicflowmeter', '-f', PCAP_PATH, '-c', CSV_PATH], check=True)

def preprocess_and_predict():
    if not os.path.exists(CSV_PATH):
        print("⚠️ No flow CSV found.")
        return

    df = pd.read_csv(CSV_PATH)
    df.drop(columns=[col for col in df.columns if col.lower() in ['flow id', 'source ip', 'destination ip', 'timestamp', 'label']], errors='ignore', inplace=True)

    for col in REQUIRED_FEATURES:
        if col not in df.columns:
            df[col] = 0

    df = df[REQUIRED_FEATURES]
    for col in le_dict:
        if col in df:
            df[col] = le_dict[col].transform(df[col].fillna('unknown'))

    df.fillna(0, inplace=True)
    X = scaler.transform(df)
    preds = model.predict(X)
    labels = label_encoder.inverse_transform(preds)

    print("🧠 Predictions from live capture:")
    for i, lbl in enumerate(labels, start=1):
        print(f"   Flow {i}: {lbl}")

def real_time_loop():
    while True:
        try:
            capture_pcap(10)
            extract_flows()
            preprocess_and_predict()
            print("🔁 Waiting 5 seconds...\n")
            time.sleep(5)
        except KeyboardInterrupt:
            print("🛑 Stopped by user.")
            break
        except Exception as e:
            print("❌ Error during live detection:", e)
            break

if __name__ == "__main__":
    real_time_loop()
