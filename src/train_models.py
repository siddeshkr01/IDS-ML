import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from lightgbm import LGBMClassifier
from sklearn.preprocessing import LabelEncoder
from src.preprocess import preprocess_pipeline

# Load full NSL-KDD dataset
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
train_df = pd.read_csv("https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt", names=col_names)
test_df = pd.read_csv("https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt", names=col_names)

full_df = pd.concat([train_df, test_df], ignore_index=True)
full_df.drop(columns=['difficulty'], inplace=True, errors='ignore')

categorical_cols = ['protocol_type', 'service', 'flag']
X_scaled, y, scaler, le_dict = preprocess_pipeline(full_df, categorical_cols)

# Encode label
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

# Split to train/test ensuring all labels are in training
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y_encoded, test_size=0.2, stratify=y_encoded, random_state=42
)

# Train ensemble
model = VotingClassifier(estimators=[
    ('lr', LogisticRegression(max_iter=500)),
    ('rf', RandomForestClassifier(n_estimators=100)),
    ('mlp', MLPClassifier(max_iter=300)),
    ('lgbm', LGBMClassifier())
], voting='hard')

model.fit(X_train, y_train)

# Save everything
joblib.dump(model, 'models/final_ids_model.pkl')
joblib.dump(scaler, 'models/scaler.pkl')
joblib.dump(le_dict, 'models/label_encoders.pkl')
joblib.dump(label_encoder, 'models/label_encoder.pkl')
print("✅ Training complete and models saved.")
