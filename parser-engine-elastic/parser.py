## parser engine

from scapy.all import rdpcap, IP, TCP, UDP
from elasticsearch import Elasticsearch, helpers
import json
import os

ES_HOST = "http://localhost:9200"   # change if running on a different host
ES_INDEX = "dnp3_packets"           # the index name that will appear in Kibana

class PcapEngine:
    def __init__(self, output_dir="network_db"):
        self.output_dir = output_dir
        self.ensure_dir(self.output_dir)
        self.all_packets = []
        self.es = self.connect_es()

    def connect_es(self):
        """Connect to Elasticsearch and create the index if it doesn't exist."""
        es = Elasticsearch(ES_HOST)
        if not es.ping():
            raise ConnectionError(f"Could not connect to Elasticsearch at {ES_HOST}. "
                                  "Make sure the Docker container is running.")
        print(f"Connected to Elasticsearch at {ES_HOST}")

        # Create index with a basic mapping if it doesn't already exist
        if not es.indices.exists(index=ES_INDEX):
            es.indices.create(index=ES_INDEX, mappings={
                "properties": {
                    "id":        {"type": "integer"},
                    "timestamp": {"type": "date"},
                    "src":       {"type": "ip"},
                    "dst":       {"type": "ip"},
                    "proto":     {"type": "keyword"},
                    "len":       {"type": "integer"},
                    "sport":     {"type": "keyword"},
                    "dport":     {"type": "keyword"}
                }
            })
            print(f"Created Elasticsearch index: {ES_INDEX}")
        else:
            print(f"Using existing Elasticsearch index: {ES_INDEX}")

        return es

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
                    "timestamp": int(float(pkt.time) * 1000), # convert to milliseconds for ES date type
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
                packet_data["sport"] = str(sport)
                packet_data["dport"] = str(dport)

                self.store_packet(packet_data)
                self.all_packets.append(packet_data)

        print(f"\nDone. Indexed {len(self.all_packets)} packets into Elasticsearch.")
        print(f"View them in Kibana at http://localhost:5601  (index: {ES_INDEX})")
        print("\nFINAL COLLECTION SUMMARY")
        print(json.dumps(self.all_packets, indent=2))

        return self.all_packets

    def store_packet(self, data):
        # --- Write to local JSON files (original behaviour) ---
        categories = {
            "ips":       data['dst'],
            "protocols": data['proto'],
            "ports":     str(data['dport'])
        }
        for folder, subfolder in categories.items():
            path = os.path.join(self.output_dir, folder, subfolder)
            self.ensure_dir(path)
            with open(os.path.join(path, f"pkt_{data['id']}.json"), 'w') as f:
                json.dump(data, f)

        # --- Index into Elasticsearch ---
        self.es.index(
            index=ES_INDEX,
            id=data['id'],      # use packet id as the ES document id (prevents duplicates on re-run)
            document=data
        )


if __name__ == "__main__":
    engine = PcapEngine("dnp3_analysis_results")
    full_data = engine.pcap_read(r"C:\Users\mkpat\VSCode_Repos\TigerEye\DNP3-TestDataPart1.pcap")