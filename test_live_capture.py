from scapy.all import sniff, get_if_list

# List available network interfaces
print("Available network interfaces:")
for iface in get_if_list():
    print(iface)

# Capture 10 packets from the default interface (you can specify an interface later)
print("\nCapturing 10 packets...")
packets = sniff(count=10, filter="ip and (tcp or udp)")

# Print the captured packets
print("\nCaptured packets:")
for pkt in packets:
    print(pkt.summary())