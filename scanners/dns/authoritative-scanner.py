import argparse
import os
import random
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from glob import glob
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dns import *

sys.path.append('../../scanners')
import utils

# Lock object for synchronizing counter and results updates
counter_lock = threading.Lock()
results_lock = threading.Lock()
counter = 0
batch_size = 500

# Function to update the shared counter safely
def increment_counter():
    global counter
    with counter_lock:
        counter += 1
    return counter

def analyze_server(server: dict, max_domains: int = 10):
    """
    Analyzes responses from a server to 6 query types for a given set of domains.

    Parameters:
    server (dict): A dictionary containing the server's IP and a list of domains. The dictionary should have the following structure:
        {
            'ip': str,
            'domains': list[str]
        }
    max_domains (int, optional): The maximum number of domains to analyze. Default is 10.

    Returns:
    dict: A dictionary containing the analysis results with the following structure:
        {
            'ip': str,
            'recursive': bool or None,
            'buffer_size': int or None,
            'domains': dict
        }
        The 'domains' dictionary maps each domain to a list containing the highest BAF and the corresponding query type.
        
    Example:
    result = analyze_server({'ip': '8.8.8.8', 'domains': ['example.com', 'example.org']})
    """
    ip = server['ip']
    recursive = None
    buffer_size = None

    # randomly select up to `max_domains` to save time if some servers host hundreds of domains
    picked_domains = random.sample(server['domains'], min(len(server['domains']), max_domains))
    
    domain_with_baf = {}
    for domain in picked_domains:
        # [Max Baf, Query Type]
        max_baf = [0, -1]

        # types that we try to query on all domains to try to retrieve the highest BAF
        selected_types = {
            'ALL': 255,
            'RRSIG': 46,
            'TXT': 16,
            'DNSKEY': 48,
            'NS': 2,
            'MX': 15,
        }
        
        for txt_type, num_type in selected_types.items():
            try:
                responses, baf = utils.send_dns_query_of_given_type(ip, domain, num_type)

                if len(responses) < 1:
                    # skip this domain
                    break

                # check BAF
                if baf > max_baf[0]:
                    max_baf[0] = baf
                    max_baf[1] = txt_type

                # check for recursion available 'ra' and the EDNS buffer size
                for res in responses:
                    if recursive and buffer_size:
                        break

                    if not res or not res.haslayer(DNS):
                        continue

                    # Check the EDNS buffer size
                    if res[DNS].arcount > 0:
                        for i in range(res[DNS].arcount):
                            ar_record = res[DNS].ar[i]
                            if ar_record.type == 41:
                                buffer_size = ar_record.rclass
                                break

                    # Check recursion available
                    recursive = res[DNS].ra == 1
            except Exception as e:
                print(f'Something went wrong: {e}')

        # save the BAF and query type that produced it for this domain
        domain_with_baf[domain] = max_baf

    return {
        'ip': ip,
        'recursive': recursive,
        'buffer_size': buffer_size,
        'domains': domain_with_baf,
    }

def main(input_file, output_file, threads, max_domains, country):
    servers = utils.read_json_full(input_file)
    # filter out servers from other countries
    servers = [server for server in servers if server['country'] == country]

    results = []
    batch_number = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(analyze_server, server, max_domains) for server in servers[2000:2002]]

        for future in as_completed(futures):
            res = future.result()
            if res:
                with results_lock:
                    results.append(res)

            current_count = increment_counter()
            if current_count % 50 == 0:
                print(f'Left to process: {len(servers) - current_count}')

            if len(results) >= batch_size:
                with results_lock:
                    if len(results) >= batch_size:
                        batch_number += 1
                        utils.save_partial_results(results, batch_number)
                        results.clear()

    # Save any remaining results
    if results:
        with results_lock:
            batch_number += 1
            utils.save_partial_results(results, batch_number)

    # Merge all partial results into one final result file
    utils.merge_partial_results(output_file)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Scanner for authoritative DNS amplifiers.")
    parser.add_argument('input_file', type=str, help='Path to the input JSON file.')
    parser.add_argument('output_file', type=str, help='Path where the output JSON file should be placed.')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use. Default is 10.')
    parser.add_argument('-d', '--max_domains', type=int, default=10, help='Maximum number of domains to randomly analyze per server. Default is 10.')
    parser.add_argument('-c', '--country', type=str, default='SE', help='The country code of servers to scan. Default is `SE`.')

    args = parser.parse_args()
    main(args.input_file, args.output_file, args.threads, args.max_domains, args.country)
