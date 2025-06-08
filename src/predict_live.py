import pandas as pd
import joblib
import os

def predict_live_input():
    model = joblib.load('models/final_ids_model.pkl')
    scaler = joblib.load('models/scaler.pkl')
    le_dict = joblib.load('models/label_encoders.pkl')
    label_encoder = joblib.load('models/label_encoder.pkl')

    features = [  # 41 feature names only
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
    ]

    print("\nEnter 41 feature values separated by commas:")
    print(", ".join(features))

    while True:
        raw_input_str = input("\nEnter feature values:\n")
        values = raw_input_str.strip().split(',')
        if len(values) != len(features):
            print(f"❌ Expected {len(features)} values, got {len(values)}.")
            continue
        try:
            input_data = []
            for i, f in enumerate(features):
                val = values[i].strip()
                if f in le_dict:
                    le = le_dict[f]
                    val = le.transform([val])[0]
                else:
                    val = float(val)
                input_data.append(val)
            break
        except Exception as e:
            print(f"❌ Error: {e}. Try again.")

    input_df = pd.DataFrame([input_data], columns=features)
    input_scaled = pd.DataFrame(scaler.transform(input_df), columns=features)

    pred = model.predict(input_scaled)[0]
    print(f"✅ Prediction: {label_encoder.inverse_transform([pred])[0]}")

if __name__ == "__main__":
    required_models = [
        'models/final_ids_model.pkl',
        'models/scaler.pkl',
        'models/label_encoders.pkl',
        'models/label_encoder.pkl'
    ]
    if not all(os.path.exists(m) for m in required_models):
        print("❌ Models missing. Run train_models.py first.")
    else:
        predict_live_input()
