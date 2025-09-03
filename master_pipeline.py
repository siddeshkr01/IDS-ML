import os
import subprocess
import time
import sys

def run_script(script_path):
    print(f"\n🚀 Running: {script_path}")
    result = subprocess.run([sys.executable, script_path])
    if result.returncode != 0:
        print(f"❌ Error occurred in: {script_path}")
        exit(1)
    else:
        print(f"✅ Completed: {script_path}")

def extract_flows():
    run_script('src/pcap_to_flows.py')

def reduce_dataset():
    run_script('src/reduce_ton_dataset.py')

def train_model():
    run_script('src/train_models.py')

def run_live_ids():
    run_script('src/real_time_detector.py')

if __name__ == "__main__":

    print("\n ===== IDS Master Pipeline Started =====\n")

    extract_flows()

    reduce_dataset()

    train_model()

    print("\n ===== Model Training Completed =====")
    input("Press ENTER to start live real-time detection...\n")

    run_live_ids()

    print("\n ===== IDS Master Pipeline Completed =====\n")
