# Amplification Detection: Determining DDoS Abuse Potential of Your Network

This repository contains code that was used to perform experiments for my Bachelor of Computer Science and Engineering Thesis.

## Installation

Assuming you have Python 3 on your system, clone the repository and install Python libraries.

```bash
# Verify your Python version
python --version

# Clone the repository
git clone https://github.com/pwicz/research-project-amplification-attacks

# Navigate into the project directory
cd research-project-amplification-attacks

# Install dependencies
pip install -r requirements.txt
```

## Usage

This project contains 4 scanners for DNS, NTP, and Memcached protocols and 1 script to retrieve IP addresses from the Censys database.

### censys/retrieve_servers.py

Before running the script, make sure that you configured your search credentials with `censys config`. More details on the [Censys Python Library](https://pypi.org/project/censys/) page. You can specify the country and the service running on the servers you intend to retrieve. Use `-h` to see all availble options.

As an example, this call should retrieve at least 500 NTP servers located in Sweden, 2 pages with 100 results each per request:

```bash
python retrieve_servers.py -t 15 -st 500 -c Sweden -s NTP ntp.json 100 2
```

### scanners/dns/authoritative_scanner.py

This script allows you to calculate maximum Bandwidth Amplification Factors (BAFs) that can be obtained from provided DNS authoritative servers. The minimum information needed to run this scan is an IP address of a name server and at least one domain for which the given server is authoritative.

The script expects input to be a JSON list with objects in this form:

```json
{
  "ip": "192.168.0.1",
  "domains": ["example.com"],
  "country": "SE"
}
```

### scanners/dns/recursive_scanner.py

This script allows you to calculate maximum Bandwidth Amplification Factors (BAFs) that can be obtained from provided DNS recursive servers. The minimum information needed to run this scan are IP addresses of (recursive) DNS servers and a list of domain names that the script will attempt to query.

The script expects input to be a JSON list with objects in this form:

```json
{
  "ip": "192.168.0.1"
}
```

Other fields such as `operating_system` or `autonomous_system` are optional and will be saved in the output together with the BAF if provided. This scanner can be run directly with the output from the `censys/retrieve_servers.py` script.

### scanners/ntp/ntp-scanner.py

This script allows you to calculate maximum Bandwidth Amplification Factors (BAFs) that can be obtained from provided NTP servers. The minimum information needed to run this scan are IP addresses of NTP servers.

The script expects input to be a JSON list with objects in this form:

```json
{
  "ip": "192.168.0.1"
}
```

Other fields such as `operating_system` or `autonomous_system` are optional and will be saved in the output together with the BAF if provided. This scanner can be run directly with the output from the `censys/retrieve_servers.py` script.

### scanners/memcached/memcached-scanner.py

This script allows you to calculate maximum Bandwidth Amplification Factors (BAFs) that can be obtained from provided Memcached servers. The minimum information needed to run this scan are IP addresses of Memcached servers.

The script expects input to be a JSON list with objects in this form:

```json
{
  "ip": "192.168.0.1"
}
```

This scanner can be run directly with the output from the `censys/retrieve_servers.py` script.
