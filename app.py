import streamlit as st
import pandas as pd
import os
import joblib
from io import StringIO
from src.predict_live import run_prediction
from src.pcap_to_flows import extract_flows_from_pcap, extract_flows_from_live, infer_label
from scapy.all import get_if_list
import winreg
import numpy as np
import time

# Function to get human-readable interface descriptions
def get_interface_description(iface):
    try:
        reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        reg_key = winreg.OpenKey(reg, r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}")
        guid = iface.split("NPF_")[1] if "NPF_" in iface else iface
        subkey = winreg.OpenKey(reg_key, f"{guid}\\Connection")
        description, _ = winreg.QueryValueEx(subkey, "Name")
        winreg.CloseKey(subkey)
        winreg.CloseKey(reg_key)
        winreg.CloseKey(reg)
        return description
    except Exception:
        return "Unknown"

# Set up paths
MODEL_DIR = "models"
UPLOAD_DIR = "data/uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Load models and preprocessors
model = joblib.load(os.path.join(MODEL_DIR, 'final_ids_model.pkl'))
scaler = joblib.load(os.path.join(MODEL_DIR, 'scaler.pkl'))
label_encoders = joblib.load(os.path.join(MODEL_DIR, 'label_encoders.pkl'))
label_encoder = joblib.load(os.path.join(MODEL_DIR, 'label_encoder.pkl'))

# Features expected by the model
features = [
    'protocol_type', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
    'flag', 'src_bytes', 'dst_bytes', 'duration', 'count'
]

# Preprocessing function (same as in predict_live.py)
def preprocess(df):
    for col in features:
        if col not in df.columns:
            df[col] = 'unknown'

    # Handle categorical columns
    categorical = ['protocol_type', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'flag']
    print("Categorical columns:", categorical[1])
    
    for col in categorical:
        le = label_encoders[col]
        # Replace any NaN values with 'unknown'
        df[col] = df[col].fillna('unknown')
        # Ensure the values are in the encoder's classes
        df[col] = df[col].apply(lambda x: x if x in le.classes_ else 'unknown')
        # Transform to integers and ensure the column is int64
        df[col] = le.transform(df[col]).astype(np.int64)

    # Handle numerical columns
    numerical = ['src_bytes', 'dst_bytes', 'duration', 'count']
    # Replace NaN with 0 for numerical columns
    df[numerical] = df[numerical].fillna(0)
    df[numerical] = scaler.transform(df[numerical])

    return df

# Function to decode numerical values back to strings for display
def decode_flow(flow, label_encoders):
    decoded_flow = flow.copy()
    categorical = ['protocol_type', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'flag']
    for col in categorical:
        le = label_encoders[col]
        # Ensure the value is an integer (cast from float if necessary)
        value = int(decoded_flow[col])  # Convert to int
        # Wrap in array for inverse_transform
        value_array = np.array([value], dtype=np.int64)
        decoded_value = le.inverse_transform(value_array)[0]
        decoded_flow[col] = decoded_value
    return decoded_flow

# Function to process uploaded PCAP or CSV file
def process_file(uploaded_file):
    file_path = os.path.join(UPLOAD_DIR, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    if uploaded_file.name.endswith((".pcap", ".pcapng")):
        st.write(f"Processing PCAP file: {uploaded_file.name}")
        try:
            df = extract_flows_from_pcap(file_path)
        except Exception as e:
            st.error(f"Error processing PCAP file: {str(e)}")
            return None
        label = infer_label(uploaded_file.name)
        if not df.empty:
            df['label'] = label
        else:
            st.error("No flows extracted from the PCAP file.")
            return None
    else:  # CSV file
        st.write(f"Processing CSV file: {uploaded_file.name}")
        df = pd.read_csv(file_path)

    # Preprocess and predict
    if not df.empty:
        df = df[features]
        df = preprocess(df)
        predictions = model.predict(df)
        decoded_preds = label_encoder.inverse_transform(predictions)
        return decoded_preds
    else:
        st.error("The file is empty or invalid.")
        return None

# Streamlit app
st.title("Network Intrusion Detection System")

# Create tabs
tab1, tab2 = st.tabs(["File-Based Prediction", "Live Packet Prediction"])

# Tab 1: File-Based Prediction
with tab1:
    st.header("Predict Attack Class from File")
    st.write("Upload a PCAP or CSV file to predict the attack class.")

    uploaded_file = st.file_uploader("Choose a PCAP or CSV file", type=["pcap", "pcapng", "csv"], key="file_uploader")

    if uploaded_file is not None:
        predictions = process_file(uploaded_file)
        if predictions is not None:
            st.subheader("Predictions:")
            for i, pred in enumerate(predictions):
                st.write(f"Flow {i+1}: Predicted Attack Class - **{pred}**")

# Tab 2: Live Packet Prediction
with tab2:
    st.header("Predict Attack Class from Live Packets")
    st.write("Capture live network packets and predict their attack classes in real-time.")

    # Get list of network interfaces
    try:
        interfaces = get_if_list()
    except Exception as e:
        st.error(f"Error retrieving network interfaces: {str(e)}")
        st.error("Ensure npcap is installed and the app is running with administrator privileges.")
        st.stop()

    if not interfaces:
        st.error("No network interfaces found. Ensure npcap is installed and you have network adapters available.")
        st.stop()

    # Create a mapping of human-readable names to interface IDs
    interface_options = []
    interface_dict = {}
    for iface in interfaces:
        description = get_interface_description(iface)
        display_name = f"{description} ({iface})"
        interface_options.append(display_name)
        interface_dict[display_name] = iface

    # Let user select an interface
    st.write("Select a network interface to capture packets from:")
    selected_option = st.selectbox("Network Interface", interface_options, key="interface_selector")
    selected_interface = interface_dict[selected_option]

    # Initialize session state for predictions DataFrame and capture control
    if 'predictions_df' not in st.session_state:
        # Initialize an empty DataFrame with the desired columns
        st.session_state.predictions_df = pd.DataFrame(columns=[
            "Flow Number", "Source IP", "Dest IP", "Source Port", 
            "Dest Port", "Protocol", "Flag", "Predicted Attack Class"
        ])
    if 'capturing' not in st.session_state:
        st.session_state.capturing = False
    if 'flow_counter' not in st.session_state:
        st.session_state.flow_counter = 0  # To keep track of flow numbers

    # Buttons to start and stop capturing
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Start Capture"):
            st.session_state.capturing = True
            # Reset predictions DataFrame and counter
            st.session_state.predictions_df = pd.DataFrame(columns=[
                "Flow Number", "Source IP", "Dest IP", "Source Port", 
                "Dest Port", "Protocol", "Flag", "Predicted Attack Class"
            ])
            st.session_state.flow_counter = 0
            st.success(f"Started capturing packets on {selected_option}...")
    with col2:
        if st.button("Stop Capture"):
            st.session_state.capturing = False
            st.success("Stopped capturing packets.")

    # Placeholder for displaying the predictions table
    prediction_placeholder = st.empty()

    # Continuous capture and predict loop while capturing is active
    if st.session_state.capturing:
        try:
            # Capture a batch of packets (e.g., 20 packets per batch)
            df = extract_flows_from_live(interface=selected_interface, packet_count=20)
            if not df.empty:
                # Preprocess and predict
                df = df[features]
                df = preprocess(df)
                predictions = model.predict(df)
                decoded_preds = label_encoder.inverse_transform(predictions)

                # Process each flow and add to the DataFrame
                new_rows = []
                for i, pred in enumerate(decoded_preds):
                    st.session_state.flow_counter += 1
                    flow = df.iloc[i].to_dict()
                    # Decode numerical values back to strings for display
                    decoded_flow = decode_flow(flow, label_encoders)
                    # Create a new row for the table
                    new_row = {
                        "Flow Number": st.session_state.flow_counter,
                        "Source IP": decoded_flow['src_ip'],
                        "Dest IP": decoded_flow['dst_ip'],
                        "Source Port": decoded_flow['src_port'],
                        "Dest Port": decoded_flow['dst_port'],
                        "Protocol": decoded_flow['protocol_type'].upper(),
                        "Flag": decoded_flow['flag'],
                        "Predicted Attack Class": pred
                    }
                    new_rows.append(new_row)

                # Append new rows to the DataFrame
                new_df = pd.DataFrame(new_rows)
                st.session_state.predictions_df = pd.concat(
                    [st.session_state.predictions_df, new_df], 
                    ignore_index=True
                )

                # Sort by Flow Number to ensure newest rows are at the bottom
                st.session_state.predictions_df = st.session_state.predictions_df.sort_values(by="Flow Number")

                # Display updated predictions table
                with prediction_placeholder.container():
                    st.subheader("Live Predictions:")
                    if not st.session_state.predictions_df.empty:
                        st.dataframe(st.session_state.predictions_df, use_container_width=True)
                    else:
                        st.write("No predictions yet. Waiting for packets...")
            else:
                st.write("No flows extracted from the captured packets. Ensure there is network activity (TCP/UDP traffic).")

            # Small delay to prevent the app from becoming unresponsive
            time.sleep(2)

            # Rerun the script to continue capturing
            st.rerun()

        except Exception as e:
            st.error(f"Error capturing packets: {str(e)}")
            st.error("Ensure the app is running with administrator privileges and the selected interface is active.")
            st.session_state.capturing = False

    # Display predictions table even after stopping capture
    if not st.session_state.capturing and not st.session_state.predictions_df.empty:
        with prediction_placeholder.container():
            st.subheader("Live Predictions (Last Captured):")
            st.dataframe(st.session_state.predictions_df, use_container_width=True)