import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.dns import *

sys.path.append('../..')
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

def retrieve_buffer_size(res):
    if not res or not res.haslayer(DNS):
        return None
    
    # Check the EDNS buffer size
    if res[DNS].arcount > 0:
        for i in range(res[DNS].arcount):
            ar_record = res[DNS].ar[i]
            if ar_record.type == 41:
                return ar_record.rclass
    return None

def analyze_server(entry, domains, n):
    """
    Analyzes server's responses for a given set of domains and various DNS query types.

    Parameters:
    entry (dict): A dictionary containing the server's information with the following structure:
        {
            'ip': str,
            'autonomous_system': str (optional),
            'operating_system': str (optional)
        }
    domains (list of str): A list of domain names to query the server with.
    n (int): The number of domains to randomly select and query.

    Returns:
    dict or None: A dictionary containing the results if the server responded to the 'A' query and had 
    the recursion available ('ra') flag set, otherwise None. The returned dictionary has the following structure:
        {
            'ip': str,
            'domains': dict,
            'autonomous_system': str or None,
            'operating_system': str or None,
            'buffer_size': int or None
        }
        The 'domains' dictionary maps each domain to a dictionary of query types and the BAF values they triggered.

    Example:
    result = analyze_server({'ip': '192.168.1.1', 'autonomous_system': 'AS12345', 'operating_system': 'Linux'}, ['example.com', 'example.org', 'example.se'], 2)
    """
    picked_domains = random.sample(domains, n)
    domain_with_baf = {}

    ip = entry['ip']
    autonomous_system = entry['autonomous_system'] if 'autonomous_system' in entry else None
    operating_system = entry['operating_system'] if 'operating_system' in entry else None
    buffer_size = None

    for domain in picked_domains:
        try:
            responses, baf = utils.send_dns_query_of_given_type(ip, domain, 'A')

            # skip servers that do not answer a simple 'A' query or do not have the 'recursion available' flag set
            if not responses or not any(res[DNS].ra == 1 for res in responses if res.haslayer(DNS)):
                continue

            if not buffer_size:
                buffers = list(set([retrieve_buffer_size(res) for res in responses]))
                buffer_size = buffers[0] if len(buffers) > 0 else None

            max_baf = {}

            # try different query types on the domain
            QUERY_TYPES = [('ALL', 255), ('DNSKEY', 48), ('TXT', 16)]
            for record_type_text, record_type_num in QUERY_TYPES:
                responses, baf = utils.send_dns_query_of_given_type(ip, domain, record_type_num)
                max_baf[record_type_text] = baf

                if not buffer_size:
                    buffers = list(set([retrieve_buffer_size(res) for res in responses]))
                    buffer_size = buffers[0] if len(buffers) > 0 else None

            if max_baf:
                domain_with_baf[domain] = max_baf

        except Exception as e:
            print(f'Something went wrong: {e}')

    if domain_with_baf:
        return {'ip': ip,
                'domains': domain_with_baf,
                'autonomous_system': autonomous_system,
                'operating_system': operating_system,
                'buffer_size': buffer_size}
    return None

def main(input_file, output_file, threads, domains, n):
    servers = utils.read_json_full(input_file)

    results = []
    batch_number = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(analyze_server, server, domains, n) for server in servers[520:550]]

        for future in as_completed(futures):
            res = future.result()
            if res:
                with results_lock:
                    results.append(res)

            current_count = increment_counter()
            if current_count % 100 == 0:
                print(f'Processed: {current_count} IP addresses')

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
    parser = argparse.ArgumentParser(description="Scanner for recursive DNS amplifiers.")
    parser.add_argument('input_file', type=str, help='Path to the input JSON file.')
    parser.add_argument('output_file', type=str, help='Path where the output JSON file should be placed.')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use. Default is 10.')
    parser.add_argument('-d', '--domain_list', type=str, nargs="+",
                        default=['sjv.se', 'tff.se', 'mh.se', 'fao.se', 'esv.se', '0x5e.se', 'cdfn.se', 'vll.se', 'pff.se', 'fhs.se'], 
                        help='A list of domains from which we randomly choose n to query the servers. Default is [`example.com`].')
    parser.add_argument('-n', '--domains_per_server', type=int, default=3, help='Number of domains to randomly choose from the list. Default is 3.')

    args = parser.parse_args()
    main(args.input_file, args.output_file, args.threads, args.domain_list, args.domains_per_server)
