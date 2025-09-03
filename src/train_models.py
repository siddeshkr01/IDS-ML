import pandas as pd
import joblib
import os
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import numpy as np

INPUT_PATH = "data/processed/reduced_train.csv"
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

# Full feature list
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

# Define categorical and numerical columns
categorical = ['protocol_type', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'flag']
numerical = ['src_bytes', 'dst_bytes', 'duration', 'count']

# Read dataset
df = pd.read_csv(INPUT_PATH)

# Fill missing categorical values as 'unknown'
for col in categorical:
    df[col] = df[col].fillna('unknown')

# Prepare LabelEncoders for categorical features
label_encoders = {}
for col in categorical:
    le = LabelEncoder()
    le.fit(list(df[col].unique()) + ['unknown'])
    df[col] = le.transform(df[col])
    label_encoders[col] = le

# Scale numerical features
scaler = StandardScaler()
df[numerical] = scaler.fit_transform(df[numerical])

# Encode target labels
label_encoder = LabelEncoder()
df['label'] = df['label'].fillna('unknown')
label_encoder.fit(list(df['label'].unique()) + ['unknown'])
df['label'] = label_encoder.transform(df['label'])

# Train/Test split
X = df[features]
y = df['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


rf_model = RandomForestClassifier(n_estimators=500, random_state=42)
gb_model = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, random_state=42)
et_model = ExtraTreesClassifier(n_estimators=100, random_state=42)
lr_model = LogisticRegression(max_iter=3000, solver='lbfgs', random_state=42)
mlp_model = MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=500, random_state=42)

#Create ensemble model using hard voting
ensemble_model = VotingClassifier(
    estimators=[
        ('rf', rf_model),
        ('gb', gb_model),
        ('et', et_model),
        ('lr', lr_model),
        ('mlp', mlp_model)
    ],
    voting='hard'
)


ensemble_model.fit(X_train, y_train)

# Evaluate model
y_pred = ensemble_model.predict(X_test)

labels_present = np.unique(y_test)
target_names_present = label_encoder.inverse_transform(labels_present)

print("\nClassification Report for Strong Ensemble Model:\n")
print(classification_report(y_test, y_pred, labels=labels_present, target_names=target_names_present))

# Save final ensemble model + encoders
joblib.dump(ensemble_model, os.path.join(MODEL_DIR, 'final_ids_model.pkl'))
joblib.dump(scaler, os.path.join(MODEL_DIR, 'scaler.pkl'))
joblib.dump(label_encoders, os.path.join(MODEL_DIR, 'label_encoders.pkl'))
joblib.dump(label_encoder, os.path.join(MODEL_DIR, 'label_encoder.pkl'))

print("\nEnsemble model and encoders saved successfully.")
