import streamlit as st
import subprocess

st.set_page_config(page_title="IDS Dashboard", layout="centered")
st.title("🛡️ Real-Time Intrusion Detection System")

if st.button("▶️ Start Real-Time Detection"):
    st.info("Running live detection in terminal. Close this tab when done.")
    subprocess.Popen(['python', 'src/real_time_detector.py'])
