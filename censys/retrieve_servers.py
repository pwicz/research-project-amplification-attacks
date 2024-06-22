import argparse
import time
import sys
from censys.search import CensysHosts

sys.path.append('../')
import utils

def censys_search(query: str, per_page: int, pages: int, timeout: int, stop_at: int):
    h = CensysHosts()
    hosts = {}

    cursor = None
    while True:
        try:
            cur_count = len(hosts)
            results = h.search(query, per_page=per_page, pages=pages, cursor=cursor)

            for page in results:
                for host in page:
                    hosts[host['ip']] = host

            cursor = results.nextCursor
            print(f'Host count: {len(hosts)} (+{len(hosts) - cur_count} hosts)')

            if not cursor or len(hosts) >= stop_at:
                break

            time.sleep(timeout)
        except Exception as e:
            print('Exception occurred')
            print(e)
            print('Retrying in 60 s...')
            time.sleep(60)

    return [host for _, host in hosts.items()]

def main(output_file, country, service_name, per_page, pages, timeout, stop_at):
    query = f'location.country={country} and services.service_name={service_name}'
    servers = censys_search(query, per_page, pages, timeout, stop_at)
    print(f'Succesfully retieved {len(servers)} servers!')

    utils.write_json(output_file, servers)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Tool to retrieve servers from the Censys database.")
    parser.add_argument('output_file', type=str, help='Path where the output JSON file should be placed.')
    parser.add_argument('per_page', type=int, help='Number of results per page that should be retrieved.')
    parser.add_argument('pages', type=int, help='Number of pages of results that should be retrieved.')
    parser.add_argument('-c', '--country', type=str, default='Sweden', help='Country where servers should be located. Default is Sweden.')
    parser.add_argument('-s', '--service_name', type=str, default='DNS', help='Name of a service that should be present on the servers. Default is DNS.')
    parser.add_argument('-t', '--timeout', type=int, default=60, help='Seconds between each request made to Censys. Increase to avoid being rate limited. Default is 60s.')
    parser.add_argument('-st', '--stop_at', type=int, default=float('inf'), help='Stop having retrieved this many unique servers. Default is infinity.')


    args = parser.parse_args()
    main(args.output_file, args.country, args.service_name, args.per_page, args.pages, args.timeout, args.stop_at)
