import argparse
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dns import *
from scapy.layers.ntp import *
from scapy.plist import *

sys.path.append('../../scanners')
import utils

counter_lock = threading.Lock()
counter = 0

def increment_counter():
    global counter
    with counter_lock:
        counter += 1
    return counter

def valid_ntp_response(packet, ip: str, dport: int):
    return (IP in packet and packet[IP].src == ip and UDP in packet and packet[UDP].sport == 123 and packet[UDP].dport == dport)

def send_ntp(server: dict, timeout: int = 2):
    """
    Sends different NTP debug queries to a specified server and processes the responses to determine the best BAF.

    Parameters:
    server (dict): A dictionary containing the server's information with the following structure:
        {
            'ip': str,
            'autonomous_system': str (optional),
            'operating_system': str (optional)
        }
    timeout (int, optional): The timeout duration for sniffing NTP responses, in seconds. Default is 2 seconds.

    Returns:
    dict or None: A dictionary containing the analysis results if a respones with BAF > 0 is received, otherwise None. The returned dictionary has the following structure:
        {
            'ip': str,
            'baf': float,
            'code': int,
            'autonomous_system': str or None,
            'operating_system': str or None
        }
    
    Example:
    result = send_ntp({'ip': '192.168.1.1', 'autonomous_system': 'AS12345', 'operating_system': 'Linux'})
    """
    server_ip = server['ip']
    autonomous_system = server['autonomous_system'] if 'autonomous_system' in server else None
    operating_system = server['operating_system'] if 'operating_system' in server else None
    
    try:
        best_baf = 0
        best_code = None

        # valid codes can be found at https://github.com/benegon/ntp/blob/master/include/ntp_request.h#L245
        # for code in ['\x00', '\x01', '\x04', '\x07', '\x10', '\x14', '\x2a']:
        for code in ['\x01', '\x07']:
            
            # version bytes: x17 (2), x1F (3), x27 (4)
            version = '\x17'
            source_port = random.randint(10000, 65000)
            query = IP(dst=server_ip)/UDP(sport=source_port, dport=123)/Raw(load=str(version + "\x00\x03" + code) + str("\00")*4)

            send(query, verbose=0)
            responses = sniff(lfilter=lambda x: valid_ntp_response(x, server_ip, source_port),
                              timeout=timeout)

            baf = utils.measure_BAF(query, responses)
            if baf > best_baf:
                best_baf = baf
                best_code = ord(code)

    except Exception as e:
        print(f'Exception for IP {server_ip}!')
        print(e)
        return None

    if best_baf > 0:
        return {
            'ip': server_ip,
            'baf': best_baf,
            'code': best_code,
            'autonomous_system': autonomous_system,
            'operating_system': operating_system
        }
    else:
        return None

def main(input_file, output_file, threads):
    entries = utils.read_json_full(input_file)
    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(send_ntp, entry) for entry in random.sample(entries, 50)]

        for future in as_completed(futures):
            res = future.result()
            if res:
                results.append(res)

            current_count = increment_counter()
            if current_count % 50 == 0:
                print(f'Left to process: {len(entries) - current_count}')

    results = sorted(results, key=lambda r: r['baf'], reverse=True)
    print(f'Writing {len(results)} results to {output_file}')
    utils.write_json(output_file, results)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="An amplification scanner for NTP servers.")
    parser.add_argument('input_file', type=str, help='Path to the input JSON file.')
    parser.add_argument('output_file', type=str, help='Path where the output JSON file should be placed.')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use. Default is 10.')
 
    args = parser.parse_args()
    main(args.input_file, args.output_file, args.threads)
