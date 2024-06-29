import pickle
import subprocess
from scapy.all import sniff, IP, TCP
import numpy as np

def extract_flow_features(packets):
    flow_features = {}
    pkt_lengths = []
    fwd_pkt_lengths = []
    bwd_pkt_lengths = []
    fwd_iats = []
    bwd_iats = []

    for packet in packets:
        if IP in packet and TCP in packet:
            pkt_lengths.append(len(packet))
            if packet[IP].src:
                fwd_pkt_lengths.append(len(packet))
                fwd_iats.append(packet.time - packet.lastlayer().time if hasattr(packet.lastlayer(), 'time') else 0)
            else:
                bwd_pkt_lengths.append(len(packet))
                bwd_iats.append(packet.time - packet.lastlayer().time if hasattr(packet.lastlayer(), 'time') else 0)
            fwd_psh_flags = int(bool(packet[TCP].flags & 0x08))
            bwd_psh_flags = int(bool(packet[TCP].flags & 0x08))
            fwd_urg_flags = int(bool(packet[TCP].flags & 0x20))
            bwd_urg_flags = int(bool(packet[TCP].flags & 0x20))
            fin_flag_cnt = int(bool(packet[TCP].flags & 0x01))
            syn_flag_cnt = int(bool(packet[TCP].flags & 0x02))
            rst_flag_cnt = int(bool(packet[TCP].flags & 0x04))
            psh_flag_cnt = int(bool(packet[TCP].flags & 0x08))
            ack_flag_cnt = int(bool(packet[TCP].flags & 0x10))
            urg_flag_cnt = int(bool(packet[TCP].flags & 0x20))
            cwe_flag_count = int(bool(packet[TCP].flags & 0x40))
            ece_flag_cnt = int(bool(packet[TCP].flags & 0x80))
    flow_features['pkt_len_min'] = min(pkt_lengths)
    flow_features['pkt_len_max'] = max(pkt_lengths)
    flow_features['pkt_len_mean'] = np.mean(pkt_lengths)
    flow_features['pkt_len_std'] = np.std(pkt_lengths)
    flow_features['fwd_pkt_len_max'] = max(fwd_pkt_lengths)
    flow_features['fwd_pkt_len_min'] = min(fwd_pkt_lengths)
    flow_features['fwd_pkt_len_mean'] = np.mean(fwd_pkt_lengths)
    flow_features['fwd_pkt_len_std'] = np.std(fwd_pkt_lengths)
    flow_features['bwd_pkt_len_max'] = max(bwd_pkt_lengths)
    flow_features['bwd_pkt_len_min'] = min(bwd_pkt_lengths)
    flow_features['bwd_pkt_len_mean'] = np.mean(bwd_pkt_lengths)
    flow_features['bwd_pkt_len_std'] = np.std(bwd_pkt_lengths)
    flow_features['fwd_iat_mean'] = np.mean(fwd_iats)
    flow_features['fwd_iat_std'] = np.std(fwd_iats)
    flow_features['fwd_iat_max'] = max(fwd_iats)
    flow_features['fwd_iat_min'] = min(fwd_iats)
    flow_features['bwd_iat_mean'] = np.mean(bwd_iats)
    flow_features['bwd_iat_std'] = np.std(bwd_iats)
    flow_features['bwd_iat_max'] = max(bwd_iats)
    flow_features['bwd_iat_min'] = min(bwd_iats)
    flow_features['fwd_psh_flags'] = fwd_psh_flags
    flow_features['bwd_psh_flags'] = bwd_psh_flags
    flow_features['fwd_urg_flags'] = fwd_urg_flags
    flow_features['bwd_urg_flags'] = bwd_urg_flags
    flow_features['fin_flag_cnt'] = fin_flag_cnt
    flow_features['syn_flag_cnt'] = syn_flag_cnt
    flow_features['rst_flag_cnt'] = rst_flag_cnt
    flow_features['psh_flag_cnt'] = psh_flag_cnt
    flow_features['ack_flag_cnt'] = ack_flag_cnt
    flow_features['urg_flag_cnt'] = urg_flag_cnt
    flow_features['cwe_flag_count'] = cwe_flag_count
    flow_features['ece_flag_cnt'] = ece_flag_cnt
    return flow_features
with open("xgb_model.pkl", "rb") as f:
    xgb_model = pickle.load(f)

def detect_ddos(packet):
    prediction = xgb_model.predict([packet])
    return prediction[0]

def firewall(packet):
    if detect_ddos(packet) != 5:
        return False
    else:
        return True
    
def block_ip(ip_address):
    command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    subprocess.run(command, shell=True)
    print(f"Blocked IP address: {ip_address}")
    
def process_packet(packet):
    if IP in packet:
        if detect_ddos(packet) != 5:
            print("DDoS attack detected.")
            block_ip(packet[IP].src)
        else:
            print("Normal traffic.")

sniff(filter="ip", prn=process_packet)
