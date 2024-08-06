import re
from netaddr import EUI
from scapy.layers.dhcp import DHCP
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
from scapy.layers.tls.handshake import TLSCertificate

from scapy.layers.tls.record import TLS

def clean_word(word):
    return re.sub(r'^\W+|\W+$', '', word)

def resembles_ip(word):
    return re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', word)

def process_raw_layer_model(packets):
    model_set = set()
    for packet in packets:
        if 'Raw' in packet:
            try:
                output = packet['Raw'].load.decode('utf-8')
                pat = r'(?:model(?:id|Description|Number|Name|_name)?[=:">]\s*)([^\s,<]+)'  # r'((?:Model|model|modelid|modelDescription|modelName)\s*\S+)'
                model_patterns = re.findall(pat, output, re.IGNORECASE)
                if len(model_patterns) > 0:
                    model_set |= {x for x in model_patterns if len(x) <= 40}
            except:
                pass
    if len(model_set) != 0:
        filtered_set = {word for word in model_set if len(word) > 2 and not resembles_ip(word)}
        cleaned_set = {clean_word(word) for word in filtered_set}
        return ','.join(cleaned_set)

def process_raw_layer_user_agent(packets):
    user_agent_set = set()
    for packet in packets:
        if 'Raw' in packet:
            try:
                output = packet['Raw'].load.decode('utf-8')
                user_agent_match = re.search(r'User-Agent: (.*)', output, re.IGNORECASE)
                if user_agent_match:
                    user_agent = user_agent_match.group(1).strip()
                    user_agent_set.add(user_agent)
            except:
                pass
    if len(user_agent_set) != 0:
        filtered_set = {word for word in user_agent_set if len(word) > 2 and not resembles_ip(word)}
        cleaned_set = {clean_word(word) for word in filtered_set}
        return ','.join(cleaned_set)


def extract_domains(packets):

    def remove_trailing_dot(string):
        if string.endswith('.'):
            return string[:-1]
        return string

    domains = set()
    for packet in packets:
        if DNS in packet:
            if DNSQR in packet and packet[DNS].qr == 0:
                domain = packet[DNSQR].qname.decode('utf-8')
                domains.add(remove_trailing_dot(domain))
    if len(domains) == 0:
        return ""
    else:
        domains_str = ';'.join(domains)
        return domains_str

def extract_functions(packets):

    list_of_functions = ["sleep", "light", "scale", "speed", "pressure", "blood", "water", "speed"]
    functions = set()
    context_radius = 10
    for packet in packets:
        if 'Raw' in packet:
            try:
                output = packet['Raw'].load.decode('utf-8')
                print(output)
                #for func in list_of_functions:
                    #function_match = re.search(rf'.{{0,{context_radius}}}{func}.{{0,{context_radius}}}', output, re.IGNORECASE)
                    #if function_match:
                    #    functions.add(function_match.group(0))
            except:
                pass
    if len(functions) != 0:
        filtered_set = {word for word in functions if len(word) > 2 and not resembles_ip(word)}
        cleaned_set = {clean_word(word) for word in filtered_set}
        return ','.join(cleaned_set)
def extract_and_print_mdns(packets):

    def remove_trailing_dot(string):
        if string.endswith('.'):
            return string[:-1]
        return string

    mdns_packets = []
    for pkt in packets:
        if UDP in pkt and pkt[UDP].dport == 5353:
            if DNS in pkt:
                mdns_packets.append(pkt)
    unique_names = set()
    for pkt in mdns_packets:
        if pkt:
            for mdns_pkt in pkt:
                mdns = mdns_pkt.getlayer(DNS)
                if mdns is None:
                    continue
                if mdns.qd:
                    for i in range(0, str(mdns.qd).count('DNSQR')):
                        clean_question = re.sub(r'\b(IN ANY|IN PTR)\b', '', re.sub(r"b'|'$", "" ,str(mdns.qd[i].qname)))
                        unique_names.add(remove_trailing_dot(clean_question))
                if mdns.an:
                    for answer in mdns.an:
                        if answer.type == 12:
                            unique_names.add(remove_trailing_dot(answer.rdata.decode()))
        if len(unique_names) == 0:
            return ""
        else:
            unique_names_str = ';'.join(unique_names)
            return unique_names_str

def extract_mdns(packets):

    def remove_trailing_dot(string):
        if string.endswith('.'):
            return string[:-1]
        return string

    def process_mdns_packets(mdns_packets):
        result = ""
        for pkt in mdns_packets:
            dns_summary = pkt[DNS].summary()
            mdns_summary = pkt[DNS].summary()

            current_string = remove_trailing_dot(dns_summary)
            current_string += remove_trailing_dot(mdns_summary)

            if not(dns_summary in result and mdns_summary in result):
                result += current_string
        return result

    mdns_packets = []
    for pkt in packets:
        if UDP in pkt and pkt[UDP].dport == 5353:
            if DNS in pkt:
                mdns_packets.append(pkt)
    return process_mdns_packets(mdns_packets)


def lookup_mac_organizations(packets):

    def remove_trailing_dot(string):
        if string.endswith('.'):
            return string[:-1]
        return string

    def lookup_organization(mac_address):
        try:
            return remove_trailing_dot(EUI(mac_address).oui.registration().org)
        except:
            pass

    unique_macs = set()

    for packet in packets:
        if Ether in packet:
            source_mac = packet[Ether].src
            dest_mac = packet[Ether].dst
            unique_macs.add(remove_trailing_dot(source_mac))
            unique_macs.add(remove_trailing_dot(dest_mac))

    mac_organizations = set()
    for mac_address in unique_macs:
        organization = lookup_organization(mac_address)
        if organization:
            mac_organizations.add(organization)
    if len(mac_organizations) == 0:
        return ""
    else:
        mac_organizations_str = ';'.join(mac_organizations)
        return mac_organizations_str


def get_tls_issuer(packets):
    issuer = set()
    for packet in packets:
        if TLS in packet:
            tls = packet[TLS]
            if tls.haslayer(TLSCertificate):
                cert_layer = tls[TLSCertificate]
                for cert in cert_layer.certs:
                    pattern = r'/O=([^/]+)/'
                    ou_pattern = r'/OU=([^/]+)/'
                    match = re.search(pattern, cert[1].issuer_str)
                    issuer.add(match.group(1))
                    match_ou = re.search(ou_pattern, cert[1].issuer_str)
                    if match_ou:
                        issuer.add(match_ou.group(1))
    if len(issuer) == 0:
        return ""
    else:
        issuer_str = ';'.join(issuer)
        return issuer_str

def get_dhcp_host_name(packets):
    host_name = set()
    for packet in packets:
        if DHCP in packet:
            options = packet[DHCP].options
            for option in options:
                if option[0] == 'hostname':
                    host_name.add(option[1])
    if len(host_name) == 0:
        return ""
    else:
        host_name_str =  ';'.join(h.decode('utf-8') if isinstance(h, bytes) else h for h in host_name)
        return host_name_str