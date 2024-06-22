import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dns import *
from scapy.layers.ntp import *
from scapy.plist import *

sys.path.append('../..')
import utils

counter_lock = threading.Lock()
counter = 0

def increment_counter():
    global counter
    with counter_lock:
        counter += 1
    return counter

def valid_mc_response(packet, ip: str, dport: int):
    return (IP in packet and packet[IP].src == ip and UDP in packet and packet[UDP].sport == 11211 and packet[UDP].dport == dport)

def analyze_server(server_ip: str, timeout=3):
    """
    Analyzes server's responses to both binary and ASCII stat requests to measure BAF.

    Parameters:
    server_ip (str): The IP address of the Memcached server to analyze.
    timeout (int, optional): The timeout duration for sniffing Memcached responses, in seconds. Default is 3 seconds.

    Returns:
    dict or None: A dictionary containing BAFs for both types of requests if at least one was answered, otherwise None. 
    The returned dictionary has the following structure:
        {
            'ip': str,
            'binary_baf': float,
            'ascii_baf': float
        }

    Example:
    result = analyze_server('192.168.1.1')
    """
   
    # Packets crafted based on the docs:
    # https://github.com/memcached/memcached/wiki

    # 1. Stat requests
    binary_baf = 0
    ascii_baf = 0
    try:
        # I. Binary request
        binary_stats = b'\x80\x10' + b'\x00' * 22
        source_port = random.randint(10000, 65000)
        query = IP(dst=server_ip) / UDP(sport=source_port, dport=11211) / binary_stats
        send(query, verbose=0)
        responses = sniff(lfilter=lambda x: valid_mc_response(x, server_ip, source_port), timeout=timeout)
        if len(responses) > 0:
            binary_baf = utils.measure_BAF(query, responses)

        # II. Ascii request
        ascii_stats = b"stats\r\n"
        source_port = random.randint(10000, 65000)
        query = IP(dst=server_ip) / UDP(sport=source_port, dport=11211) / ascii_stats
        send(query, verbose=0)
        responses = sniff(lfilter=lambda x: valid_mc_response(x, server_ip, source_port), timeout=timeout)
        if len(responses) > 0:
            ascii_baf = utils.measure_BAF(query, responses)

    except Exception as err:
        print(f'Exception for IP {server_ip}')
        print(err)
        return None

    return {
        'ip': server_ip,
        'binary_baf': binary_baf,
        'ascii_baf': ascii_baf
    } if binary_baf or ascii_baf else None


def main(input_file, output_file, threads):
    servers = utils.read_json_full(input_file)

    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(analyze_server, server['ip']) for server in servers]

        for future in as_completed(futures):
            res = future.result()
            if res:
                results.append(res)

            current_count = increment_counter()
            if current_count % 50 == 0:
                print(f'Processed: {current_count} IP addresses')

    print(f'Writing {len(results)} results to {output_file}')
    utils.write_json(output_file, results)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Scanner for Memcached amplifiers.")
    parser.add_argument('input_file', type=str, help='Path to the input JSON file.')
    parser.add_argument('output_file', type=str, help='Path where the output JSON file should be placed.')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use. Default is 10.')

    args = parser.parse_args()
    main(args.input_file, args.output_file, args.threads)
