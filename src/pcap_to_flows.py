import pandas as pd
import os
from scapy.all import rdpcap, IP, TCP, UDP, sniff

# Simple label inference (same as before)
def infer_label(filename):
    name = filename.lower()
    if 'password' in name:
        return 'password'
    elif 'xss' in name:
        return 'xss'
    elif 'scanning' in name:
        return 'scanning'
    elif 'runsomware' in name or 'ransomware' in name:
        return 'ransomware'
    elif 'ddos' in name:
        return 'ddos'
    elif 'dos' in name:
        return 'dos'
    elif 'mitm' in name:
        return 'mitm'
    elif 'injection' in name:
        return 'injection'
    else:
        return 'normal'

# Function to parse TCP flags
def extract_flag(pkt):
    try:
        if TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x02:  # SYN
                return 'SYN'
            elif flags & 0x04:  # RST
                return 'RST'
            elif flags & 0x08:  # PSH
                return 'PSH'
            elif flags & 0x10:  # ACK
                return 'ACK'
            elif flags & 0x01:  # FIN
                return 'FIN'
            else:
                return 'OTH'
        else:
            return 'OTH'
    except:
        return 'OTH'

def extract_flows_from_pcap(pcap_path):
    # Read the PCAP file using scapy
    packets = rdpcap(pcap_path)
    if not packets:
        return pd.DataFrame()

    flows = {}

    for pkt in packets:
        try:
            if IP not in pkt:
                continue

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if TCP in pkt:
                transport = 'TCP'
                src_port = str(pkt[TCP].sport)
                dst_port = str(pkt[TCP].dport)
            elif UDP in pkt:
                transport = 'UDP'
                src_port = str(pkt[UDP].sport)
                dst_port = str(pkt[UDP].dport)
            else:
                transport = 'other'
                src_port = '0'
                dst_port = '0'

            protocol_type = transport.lower()

            # Create both flow directions (bidirectional logic)
            forward_key = (src_ip, dst_ip, src_port, dst_port, protocol_type)
            reverse_key = (dst_ip, src_ip, dst_port, src_port, protocol_type)

            direction = 'forward'

            if forward_key in flows:
                key = forward_key
            elif reverse_key in flows:
                key = reverse_key
                direction = 'reverse'
            else:
                key = forward_key
                flows[key] = {
                    'start_time': pkt.time,
                    'end_time': pkt.time,
                    'src_bytes': 0,
                    'dst_bytes': 0,
                    'count': 0,
                    'flags': []
                }

            # Update flow
            flows[key]['end_time'] = pkt.time
            flows[key]['count'] += 1

            if direction == 'forward':
                flows[key]['src_bytes'] += len(pkt)
            else:
                flows[key]['dst_bytes'] += len(pkt)

            # Extract flags if TCP
            if transport == 'TCP':
                flag = extract_flag(pkt)
                flows[key]['flags'].append(flag)

        except Exception as e:
            print(f"Error processing packet: {e}")
            continue

    # Build DataFrame
    flow_list = []

    for key, values in flows.items():
        src_ip, dst_ip, src_port, dst_port, protocol_type = key
        duration = values['end_time'] - values['start_time']

        # Pick most frequent flag seen in this flow
        flag_summary = max(set(values['flags']), key=values['flags'].count) if values['flags'] else 'OTH'

        flow_list.append({
            'protocol_type': protocol_type,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'flag': flag_summary,
            'src_bytes': values['src_bytes'],
            'dst_bytes': values['dst_bytes'],
            'duration': duration,
            'count': values['count']
        })

    return pd.DataFrame(flow_list)

# New function for live packet capture
def extract_flows_from_live(interface, packet_count=20):
    # Capture packets live using scapy
    packets = sniff(iface=interface, count=packet_count, filter="ip and (tcp or udp)")
    if not packets:
        return pd.DataFrame()

    flows = {}

    for pkt in packets:
        try:
            if IP not in pkt:
                continue

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            if TCP in pkt:
                transport = 'TCP'
                src_port = str(pkt[TCP].sport)
                dst_port = str(pkt[TCP].dport)
            elif UDP in pkt:
                transport = 'UDP'
                src_port = str(pkt[UDP].sport)
                dst_port = str(pkt[UDP].dport)
            else:
                transport = 'other'
                src_port = '0'
                dst_port = '0'

            protocol_type = transport.lower()

            # Create both flow directions (bidirectional logic)
            forward_key = (src_ip, dst_ip, src_port, dst_port, protocol_type)
            reverse_key = (dst_ip, src_ip, dst_port, src_port, protocol_type)

            direction = 'forward'

            if forward_key in flows:
                key = forward_key
            elif reverse_key in flows:
                key = reverse_key
                direction = 'reverse'
            else:
                key = forward_key
                flows[key] = {
                    'start_time': pkt.time,
                    'end_time': pkt.time,
                    'src_bytes': 0,
                    'dst_bytes': 0,
                    'count': 0,
                    'flags': []
                }

            # Update flow
            flows[key]['end_time'] = pkt.time
            flows[key]['count'] += 1

            if direction == 'forward':
                flows[key]['src_bytes'] += len(pkt)
            else:
                flows[key]['dst_bytes'] += len(pkt)

            # Extract flags if TCP
            if transport == 'TCP':
                flag = extract_flag(pkt)
                flows[key]['flags'].append(flag)

        except Exception as e:
            print(f"Error processing live packet: {e}")
            continue

    # Build DataFrame
    flow_list = []

    for key, values in flows.items():
        src_ip, dst_ip, src_port, dst_port, protocol_type = key
        duration = values['end_time'] - values['start_time']

        # Pick most frequent flag seen in this flow
        flag_summary = max(set(values['flags']), key=values['flags'].count) if values['flags'] else 'OTH'

        flow_list.append({
            'protocol_type': protocol_type,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'flag': flag_summary,
            'src_bytes': values['src_bytes'],
            'dst_bytes': values['dst_bytes'],
            'duration': duration,
            'count': values['count']
        })

    return pd.DataFrame(flow_list)

# ================================

if __name__ == "__main__":
    RAW_PCAPPATH = "data/raw_pcap"
    OUTPUT_CSV = "data/TON_IoT/Train.csv"
    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)

    all_flows = []

    for file in os.listdir(RAW_PCAPPATH):
        if file.endswith(".pcap") or file.endswith(".pcapng"):
            pcap_path = os.path.join(RAW_PCAPPATH, file)
            label = infer_label(file)
            print(f"Processing: {file} | Label: {label}")

            flows = extract_flows_from_pcap(pcap_path)
            if not flows.empty:
                flows['label'] = label
                all_flows.append(flows)

    if all_flows:
        final_df = pd.concat(all_flows, ignore_index=True)
        final_df.to_csv(OUTPUT_CSV, index=False)
        print(f"All flows extracted and written to {OUTPUT_CSV}")
    else:
        print("No flows extracted.")