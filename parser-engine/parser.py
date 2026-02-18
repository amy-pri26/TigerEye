## parser engine

from scapy.all import rdpcap, IP, TCP, UDP
import json
import os

class PcapEngine:
    def __init__(self, output_dir="network_db"):
        self.output_dir = output_dir
        self.ensure_dir(self.output_dir)
        self.all_packets = []

    def ensure_dir(self, path):
        if not os.path.exists(path):
            os.makedirs(path)

    def pcap_read(self, pcap_file):
        print(f"Loading {pcap_file}...")
        packets = rdpcap(pcap_file)

        for i, pkt in enumerate(packets):
            if IP in pkt:
                packet_data = {
                    "id": i,
                    "timestamp": float(pkt.time),
                    "src": pkt[IP].src,
                    "dst": pkt[IP].dst,
                    "proto": pkt[IP].get_field('proto').i2s[pkt[IP].proto].upper(),
                    "len": len(pkt)
                }

                sport, dport = "none", "none"
                if pkt.haslayer(TCP):
                    sport, dport = pkt[TCP].sport, pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    sport, dport = pkt[UDP].sport, pkt[UDP].dport
                packet_data["sport"] = sport
                packet_data["dport"] = dport

                self.store_packet(packet_data)

                self.all_packets.append(packet_data)

        print("FINAL COLLECTION SUMMARY")
        print(json.dumps(self.all_packets, indent=2))

        return self.all_packets
    
    def store_packet(self, data):
        categories = {
            "ips": data['dst'],
            "protocols": data['proto'],
            "ports": str(data['dport'])
        }

        for folder, subfolder in categories.items():
            path = os.path.join(self.output_dir, folder, subfolder)
            self.ensure_dir(path)
            with open(os.path.join(path, f"pkt_{data['id']}.json"), 'w') as f:json.dump(data,f)
    

if __name__ == "__main__":
    engine = PcapEngine("analysis_results")
    full_data = engine.pcap_read("smallFlows.pcap")