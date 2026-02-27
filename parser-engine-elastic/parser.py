## parser engine

from scapy.all import rdpcap, IP, TCP, UDP
from elasticsearch import Elasticsearch, helpers
import json
import os

# Elasticsearch connection settings
ES_HOST = "http://localhost:9200"   # change to VM IP for actual database (whenever we spin that up))
ES_INDEX = "dnp3_packets"           # the index name that will appear in Grafana

class PcapEngine:
    def __init__(self, output_dir="network_db"):
        self.output_dir = output_dir        # root folder for local JSON output
        self.ensure_dir(self.output_dir)    # create the output folder if it doesn't exist
        self.all_packets = []               # holds all parsed packet data for final summary
        self.es = self.connect_es()         # establish Elasticsearch connection on startup

    # Connect to Elasticsearch and create the index with field mappings if it doesn't exist.
    def connect_es(self):
        es = Elasticsearch(ES_HOST)

        # verify the connection is live before continuing
        if not es.ping():
            raise ConnectionError(f"Could not connect to Elasticsearch at {ES_HOST}. "
                                  "Make sure the Docker container is running.")
        print(f"Connected to Elasticsearch at {ES_HOST}")

        # create the index with explicit field type mappings if it doesn't already exist
        # timestamp is stored in milliseconds and mapped as a date type for Grafana compatibility
        if not es.indices.exists(index=ES_INDEX):
            es.indices.create(index=ES_INDEX, mappings={
                "properties": {
                    "id":        {"type": "integer"},
                    "timestamp": {"type": "date"},      # stored in ms for Grafana time range queries
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

    # Create a directory if it does not already exist
    def ensure_dir(self, path):
        if not os.path.exists(path):
            os.makedirs(path)

    # Read a .pcap file and extract metadata from each IP packet.
    # Extracts: timestamp, source/destination IP, protocol, packet length, and ports
    # Non-IP packets are skipped. Each packet is stored locally as a JSON file and indexed in Elasticsearch
    def pcap_read(self, pcap_file):
        print(f"Loading {pcap_file}...")
        packets = rdpcap(pcap_file)

        for i, pkt in enumerate(packets):
            if IP in pkt:
                packet_data = {
                    "id":        i,
                    "timestamp": int(float(pkt.time) * 1000),  # convert Unix timestamp to milliseconds for elasticsearch date type
                    "src":       pkt[IP].src,
                    "dst":       pkt[IP].dst,
                    "proto":     pkt[IP].get_field('proto').i2s[pkt[IP].proto].upper(),
                    "len":       len(pkt)
                }

                # extract source and destination ports for TCP/UDP packets
                # defaults to "none" for protocols that don't use ports
                sport, dport = "none", "none"
                if pkt.haslayer(TCP):
                    sport, dport = pkt[TCP].sport, pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    sport, dport = pkt[UDP].sport, pkt[UDP].dport
                packet_data["sport"] = str(sport)
                packet_data["dport"] = str(dport)

                self.store_packet(packet_data)
                self.all_packets.append(packet_data)

    # basic info to output to the terminal after processing is complete
        print(f"\nDone. Indexed {len(self.all_packets)} packets into Elasticsearch.")
        print(f"View them in Grafana at http://localhost:3000  (index: {ES_INDEX})")
        print("\nFINAL COLLECTION SUMMARY")
        print(json.dumps(self.all_packets, indent=2))

        return self.all_packets

    # Store a single packet in two places:
    # First, as a local JSON file organized by destination IP, protocol, and destination port
    # Second, as a document in Elasticsearch indexed by packet ID (prevents duplicates on re-run)
    def store_packet(self, data):
        # write to local JSON files organized into category subfolders
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

        # index the packet into Elasticsearch
        # using packet id as the document id prevents duplicate entries on re-run
        self.es.index(
            index=ES_INDEX,
            id=data['id'],
            document=data
        )


if __name__ == "__main__":
    engine = PcapEngine("dnp3_analysis_results")
    full_data = engine.pcap_read(r"C:\Users\mkpat\VSCode_Repos\TigerEye\DNP3-TestDataPart1.pcap")