import pandas as pd
import joblib
import os

# Features used (same as your extracted features)
features = [
    'protocol_type',
    'src_ip',
    'dst_ip',
    'src_port',
    'dst_port',
    'flag',
    'src_bytes',
    'dst_bytes',
    'duration',
    'count'
]

# Load encoders & model
model = joblib.load('models/final_ids_model.pkl')
scaler = joblib.load('models/scaler.pkl')
label_encoders = joblib.load('models/label_encoders.pkl')

def preprocess(df):
    # Fill missing columns if any
    for col in features:
        if col not in df.columns:
            df[col] = 'unknown'

    # Handle unseen values for categorical features
    categorical = ['protocol_type', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'flag']

    for col in categorical:
        le = label_encoders[col]
        df[col] = df[col].apply(lambda x: x if x in le.classes_ else 'unknown')
        # Now safely transform
        df[col] = le.transform(df[col])

    # Handle numerical features
    numerical = ['src_bytes', 'dst_bytes', 'duration', 'count']
    df[numerical] = scaler.transform(df[numerical])

    return df

def run_prediction(live_csv_path):
    if not os.path.exists(live_csv_path):
        print("No extracted flows to predict on.")
        return

    df = pd.read_csv(live_csv_path)

    # Make sure columns match exactly
    df = df[features]
    df = preprocess(df)

    predictions = model.predict(df)

    # Load label encoder for target label
    label_encoder = joblib.load('models/label_encoder.pkl')
    decoded_preds = label_encoder.inverse_transform(predictions)

    print("\nPredictions on Live Traffic:")
    for pred in decoded_preds:
        print(f"Prediction: {pred}")
