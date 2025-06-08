import streamlit as st
import pandas as pd
import joblib

@st.cache_resource
def load_artifacts():
    model = joblib.load('models/final_ids_model.pkl')
    scaler = joblib.load('models/scaler.pkl')
    le_dict = joblib.load('models/label_encoders.pkl')
    return model, scaler, le_dict

model, scaler, le_dict = load_artifacts()

st.title("Intrusion Detection System (IDS) - Live Packet Prediction")

features = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
    'dst_host_srv_rerror_rate'
]

def user_input_features():
    data = {}

    data['duration'] = st.number_input('Duration', min_value=0, value=0)
    data['protocol_type'] = st.selectbox('Protocol Type', list(le_dict['protocol_type'].classes_))
    data['service'] = st.selectbox('Service', list(le_dict['service'].classes_))
    data['flag'] = st.selectbox('Flag', list(le_dict['flag'].classes_))
    data['src_bytes'] = st.number_input('Source Bytes', min_value=0, value=0)
    data['dst_bytes'] = st.number_input('Destination Bytes', min_value=0, value=0)

    numeric_features = [
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
        'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
        'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
        'dst_host_srv_rerror_rate'
    ]

    for feature in numeric_features:
        if 'rate' in feature:
            data[feature] = st.slider(feature.replace('_', ' ').title(), 0.0, 1.0, 0.0, 0.01)
        else:
            data[feature] = st.number_input(feature.replace('_', ' ').title(), min_value=0, value=0)

    return pd.DataFrame([data])

input_df = user_input_features()

for cat_feature in ['protocol_type', 'service', 'flag']:
    le = le_dict[cat_feature]
    input_df[cat_feature] = le.transform(input_df[cat_feature])

input_scaled = scaler.transform(input_df)

if st.button('Predict'):
    prediction = model.predict(input_scaled)[0]
    label = "NORMAL packet" if prediction == 0 else "ATTACK packet"
    st.write(f"### Prediction: {label}")
