import json
import os
from glob import glob
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dns import *

###########
# JSON I/O
###########

def write_json(output_file, json_obj):
    with open(output_file, 'w') as outfile:
        json.dump(json_obj, outfile, indent=4)

def read_json_line_by_line(input_file):
    data = []
    for file_name in glob(input_file):
        print(f"Reading {file_name}")
        with open(file_name, 'r') as f:
            for line in f:
                data.append(json.loads(line))
    return data

def read_json_full(pattern):
    """Read and merge all JSON files matching a pattern into a single list."""
    data = []
    for file_name in glob(pattern):
        print(f"Reading {file_name}")
        with open(file_name, 'r') as f:
            data.extend(json.load(f))
    return data

def save_partial_results(results, batch_number):
    if not os.path.exists('tmp'):
        os.makedirs('tmp')

    filename = f'tmp/batch{batch_number}.json'
    write_json(filename, results)
    print(f'Saved {len(results)} results to {filename}')

def merge_partial_results(output_file):
    all_results = []
    for batch_file in glob('tmp/batch*.json'):
        batch = read_json_full(batch_file)
        all_results.extend(batch)
        os.remove(batch_file)
    write_json(output_file, all_results)

    os.removedirs('tmp')
    print(f'Scan output written to {output_file}')

###########
# SCAPY
###########

def measure_BAF(request, responses):
    req_size = len(request[UDP].payload)
    resp_size = 0

    UDP_header_size = 8  # bytes
    for resp in responses:  # Sum up all the payloads from all the response packets
        resp_size += resp[UDP].len - UDP_header_size

    return round(resp_size / req_size, 2)

###########
# SCAPY: DNS
###########

def valid_dns_response(packet, ip: str, dport: int):
    return IP in packet and packet[IP].src == ip and UDP in packet and packet[UDP].sport == 53 and packet[UDP].dport == dport

def send_dns_query_of_given_type(dns_server_ip: str, target_domain: str, record_type: int, timeout: int = 3):
    """
    Sends a DNS query of a given type to a specified DNS server and processes the response.

    Parameters:
    dns_server_ip (str): The IP address of the DNS server to query.
    target_domain (str): The domain name to query.
    record_type (int): The type of DNS record to request (e.g., 1 (A), 28 (AAAA), 255 (ANY), etc.) as defined at 
        https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
    timeout (int, optional): The timeout duration for sniffing DNS responses, in seconds. Default is 3 seconds.

    Returns:
    tuple: A tuple containing:
        - responses (list): A list of DNS response packets.
        - BAF (float): The ratio of the total size of the responses to the size of the request.

    Example:
    responses, BAF = send_dns_query_of_given_type("8.8.8.8", "example.com", 255)
    """

    udp_payload = DNS(
        id=random.randint(0, 0xFFFF),
        rd=1,
        qd=DNSQR(qname=target_domain, qtype=record_type),
        ar=DNSRROPT(rclass=4096)
    )
    source_port = random.randint(10000, 65000)
    query = IP(dst=dns_server_ip) / UDP(sport=source_port, dport=53) / udp_payload

    send(query, verbose=0)
    responses = sniff(lfilter=lambda x: valid_dns_response(x, dns_server_ip, source_port), timeout=timeout) 

    return responses, measure_BAF(query, responses)
