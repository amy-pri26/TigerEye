#Aidan Anderson
# Senior Design - TigerEye Alert engine proto
# Used to find OT and IT vulnerabilites in network out put
# Intel source = Alienblue Open Threat Exchange
# Primary Input: .Json file holding packet information from pcap files of defensive target
from OTXv2 import OTXv2,IndicatorTypes
import json
import requests



#IP Check
#params: pulse_list - list of pulse IDs to check against
#params: ip_list - list of IPs to check against pulse list
#Output: returns a set of malicious ips foound in the pcap input 
def ip_check(pulse_list, ip_list, api_key):
    otx = OTXv2(api_key)
    malicious_ips = set()  # IPs associated with any of the pulses
    for pulse in pulse_list:
        try:
            # If pulse is just an ID, fetch full details
            if isinstance(pulse, str):
                pulse_data = otx.get_pulse_details(pulse)
            indicators = pulse_data.get("indicators", [])
            # Sanity check print(indicators)
            for ind in indicators:
                if ind.get("type") in ["IPv4", "IPv6"]:
                    ip = ind.get("indicator")
                    if ip:
                        malicious_ips.add(ip)
        except Exception as e:
            print(f"Error processing pulse {pulse}: {e}")

    # Now check against your input IP list
    alerted_ips = set()
    for ip in ip_list:
        if ip in malicious_ips:
            #print(f"{ip} is malicious according to OTX pulses")
            alerted_ips.add(ip)
    return alerted_ips



# Main
if __name__ == "__main__":
   print("Processing OTX data...")
   #ALL BELOW ARE HARD CODED  FOR TTESTING & DEMO
   # Pulse ID array
   pulses = ["69c089cbd0a402c9d49b0cfb"]
   # Input Ups that would come from our pcap parser
   ip_list = ["192.168.1.1", "10.0.0.1", "38.54.95.226", "185.242.3.87", "54.93.241.141", "148.135.177.43"] #148.135.177.43 = trigger
   api_key = "95499d2d7796a58144fda22ec0989ae2b68001612b3f191d0e0d9bc68ec7a37a"
   print(ip_check(pulses, ip_list, api_key))