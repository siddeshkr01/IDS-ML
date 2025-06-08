import pandas as pd
import joblib
from sklearn.metrics import classification_report, confusion_matrix
from src.preprocess import preprocess_pipeline

# Load entire dataset again
col_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'label', 'difficulty'
]
full_df = pd.read_csv("https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt", names=col_names)
full_df.drop(columns=['difficulty'], inplace=True)

categorical_cols = ['protocol_type', 'service', 'flag']
model = joblib.load('models/final_ids_model.pkl')
scaler = joblib.load('models/scaler.pkl')
le_dict = joblib.load('models/label_encoders.pkl')
label_encoder = joblib.load('models/label_encoder.pkl')

X_scaled, y, _, _ = preprocess_pipeline(full_df, categorical_cols, scaler=scaler, le_dict=le_dict)

# Filter test set to only known labels
valid_idx = y.isin(label_encoder.classes_)
X_scaled = X_scaled[valid_idx]
y = y[valid_idx]

y_encoded = label_encoder.transform(y)
y_pred = model.predict(X_scaled)

print("✅ Confusion Matrix:")
print(confusion_matrix(y_encoded, y_pred))

print("\n✅ Classification Report:")
print(classification_report(
    label_encoder.inverse_transform(y_encoded),
    label_encoder.inverse_transform(y_pred)
))
