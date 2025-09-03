from scapy.all import sniff, get_if_list

# Print available interfaces
print("Available interfaces:", get_if_list())

# Replace with your Wi-Fi interface
interface = "\\Device\\NPF_{D3DBA9F3-9D73-45AF-8E14-7B6B6A8929BF}"
print(f"Capturing on interface: {interface}")

# Capture packets for 10 seconds
packets = sniff(iface=interface, timeout=10, filter="tcp or udp")
print(f"Captured {len(packets)} packets")

# Print packet summaries
for pkt in packets:
    print(pkt.summary())