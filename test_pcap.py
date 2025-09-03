import pandas as pd
from src.pcap_to_flows import extract_flows_from_pcap

# Path to a specific PCAP file
# Replace with an actual PCAP file in the raw_pcap directory
pcap_path = "D:\\EL\\CNS\\IDS2\\IDS\\data\\raw_pcap\\live.pcap"  # Example file, adjust as needed

# Run the extraction
df = extract_flows_from_pcap(pcap_path)
print("Extracted Flows:")
print(df)