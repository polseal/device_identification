import csv
from scapy.all import *


from functions import extract_domains, lookup_mac_organizations, extract_and_print_mdns, process_raw_layer_user_agent, get_tls_issuer, get_dhcp_host_name

folder_path = "data"
files = os.listdir(folder_path)
pcap_files = [file for file in files if file.endswith(".pcap")]
def process_pcap_file(pcap_file):
    pcap_file_path = os.path.join(folder_path, pcap_file)
    packets = rdpcap(pcap_file_path)
    domains = extract_domains(packets)
    mdns_results = extract_and_print_mdns(packets)
    host_name = get_dhcp_host_name(packets)
    user_agents = process_raw_layer_user_agent(packets)
    mac_org = lookup_mac_organizations(packets)
    tls_issuer = get_tls_issuer(packets)
    return {
        "PCAP File": pcap_file,
        "Domains": domains,
        "MDNS Results": mdns_results,
        "MAC Organizations": mac_org,
        "Host name": host_name,
        "User-agents": user_agents,
        "Tls-issuer": tls_issuer,
    }
results = []

for pcap_file in pcap_files:
    result = process_pcap_file(pcap_file)
    results.append(result)

def write_results_to_csv(file_path, results):
    with open(file_path, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["PCAP File",
                                                  "Domains",
                                                  "MDNS Results",
                                                  "MAC Organizations",
                                                  "Host name",
                                                  "User-agents",
                                                  "Tls-issuer"])


        writer.writeheader()
        writer.writerows(results)

write_results_to_csv('file.csv', results)
