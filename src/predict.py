import joblib
import pandas as pd
from src.preprocess import preprocess_pipeline

input_csv_path = 'data/processed/new_input.csv'
categorical_cols = ['protocol_type', 'service', 'flag']

# Load model and preprocess tools
model = joblib.load('models/final_ids_model.pkl')
scaler = joblib.load('models/scaler.pkl')
le_dict = joblib.load('models/label_encoders.pkl')
label_encoder = joblib.load('models/label_encoder.pkl')

df = pd.read_csv(input_csv_path)
X, _, _, _ = preprocess_pipeline(df, categorical_cols, scaler=scaler, le_dict=le_dict)

predictions = model.predict(X)
decoded_preds = label_encoder.inverse_transform(predictions)

for i, label in enumerate(decoded_preds, 1):
    print(f"Sample {i}: Predicted Attack Type → {label}")
