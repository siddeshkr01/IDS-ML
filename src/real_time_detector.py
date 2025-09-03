import pyshark
import pandas as pd
import os
from predict_live import run_prediction

# ============================
# Dynamic flag extraction
# ============================
def extract_flag(pkt):
    try:
        flags = pkt.tcp.flags
        flags_bin = bin(int(flags, 16))[2:].zfill(8)
        if flags_bin[1] == '1':
            return 'SYN'
        elif flags_bin[3] == '1':
            return 'RST'
        elif flags_bin[4] == '1':
            return 'PSH'
        elif flags_bin[5] == '1':
            return 'ACK'
        elif flags_bin[2] == '1':
            return 'FIN'
        else:
            return 'OTH'
    except:
        return 'OTH'

# ============================
# Flow extraction from packets
# ============================
def extract_flows_from_packets(packet_list):
    flows = {}

    for pkt in packet_list:
        try:
            transport = pkt.transport_layer
            protocol_type = transport.lower() if transport else 'other'
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst

            if transport in ['TCP', 'UDP']:
                src_port = pkt[transport].srcport
                dst_port = pkt[transport].dstport
            else:
                src_port = dst_port = '0'

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
                    'start_time': float(pkt.sniff_timestamp),
                    'end_time': float(pkt.sniff_timestamp),
                    'src_bytes': 0,
                    'dst_bytes': 0,
                    'count': 0,
                    'flags': []
                }

            flows[key]['end_time'] = float(pkt.sniff_timestamp)
            flows[key]['count'] += 1

            if direction == 'forward':
                flows[key]['src_bytes'] += int(pkt.length)
            else:
                flows[key]['dst_bytes'] += int(pkt.length)

            if transport == 'TCP':
                flag = extract_flag(pkt)
                flows[key]['flags'].append(flag)

        except AttributeError:
            continue

    flow_list = []
    for key, values in flows.items():
        src_ip, dst_ip, src_port, dst_port, protocol_type = key
        duration = values['end_time'] - values['start_time']
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

    df = pd.DataFrame(flow_list)
    return df

# ============================
# Main Real-Time Detection
# ============================
def run_live_detection(interface='Wi-Fi'):
    os.makedirs("data/extracted_csv", exist_ok=True)

    try:
        while True:
            print("\n--- Starting live capture of 20 packets ---")

            capture = pyshark.LiveCapture(interface=interface, bpf_filter="ip and (tcp or udp)")

            capture.sniff(packet_count=20)
            print("Finished capturing 20 packets. Parsing...")

            packet_list = [pkt for pkt in capture]
            capture.close()

            if not packet_list:
                print("No packets captured.")
                continue

            print(f"Total packets captured: {len(packet_list)}")

            df = extract_flows_from_packets(packet_list)
            if not df.empty:
                csv_path = "data/extracted_csv/output_flows.csv"
                df.to_csv(csv_path, index=False)
                print(f"Flows written to {csv_path}")
                run_prediction(csv_path)
            else:
                print("No valid flows extracted.")

    except KeyboardInterrupt:
        print("\nIDS stopped by user.")

# ============================
# Entry Point
# ============================
if __name__ == "__main__":
    run_live_detection()
