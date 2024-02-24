# Domain-Footprint

#### Tool for the enumeration of DNS records, WhoIs Records, IPs, SSL Certificate, and subdomains associated with a public-facing domain

##### Results are written to a local sqlite db

##### *- please note that a shodan API key and Residential Proxy Subscription are required for full functionality*

## Installation

Create a virtual environment using your software of choice and install the dependencies from the requirements.txt file:

- On linux/UNIX:
```
# install venv if not already installed
pip install venv

# create virtual environment
python3 -m venv /path/to/new/virtual/environment

# activate virtual environment
source venv/bin/activate

# install the dependencies, run this command in the project directory
pip install -r requirements.txt
```

- on Windows (assumes you have added python to path):
```
# install venv if not already installed
pip install venv

# create virtual environment
python -m venv c:\path\to\myenv

# activate virtual environment
source venv/bin/activate

# install the dependencies, run this command in the project directory
pip install -r requirements.txt
```
## Environment Variables Setup

Create a `.env` file in the project directory with the following variables:

```
# Target Domain
DOMAIN='<Target domain, format "somedomain.com" no leading or trailing chars>'
# proxy configuration
PROXY_TEST_URL='<url to test that proxy is working as expected>'
HTTP_PROXY='<url of authenticated proxy http endpoint>'
HTTPS_PROXY='<url of authenticated proxy https endpoint>'
# shodan api config
SHODAN_API_KEY='<shodan account API key>'
# path to wordlist for bruteforce subdomain enumeration - replace with path to your wordlist
WORDLIST_FILE_PATH='./wordlist.txt'
```

Once the `.env` file is properly configured, the `domain-footprint.py` script can be run.

Check with your proxy provider's documentation to determine the PROXY_TEST_URL, HTTP_PROXY, and HTTPS_PROXY

The script can be used without a proxy, but it is not recommended and you will have to comment out the `testProxy()` function.

It will not run properly without a valid Shodan API key configured in the `.env` file.

A sample wordlist has been provided with ~100 entries, but more subdomains may be discovered with larger wordlists.

The path to the wordlist must be specified in the `.env` file to attempt to resolve additional subdomains - for subdomain-oriented wordlists to use with this tool please refer to the topic on github: https://github.com/topics/subdomain-wordlist

If you would like to skip bruteforce subdomain enumeration for speed, just specify a path to an empty file in the `.env` file.

## Usage

All of the necessary user variables are configured in the `.env` file, so once the `.env` file is configured the script can be run from the virtual environment without any arguments:

```
# run the script
python3 domain-footprint.py
```

The script will resolve the public IP of the environment through the proxy, and then resolve the PROXY_TEST_URL twice to confirm IP rotation. It then Tests the target domain and only proceeds on a Code 200 response.

If the target gives a 200 Response, the script executes the following functions and writes the results to tables in local sqlite DB in the `./output_db/` directory (the created DB has a timestamp of execution in the name, so subsequent executions will create a new DB with the time of execution).

Script functions:

1) DNS Record Lookup, Reverse DNS Lookup (`dns_lookup` table)
2) WhoIs Lookup (`whois_lookup` table)
3) Shodan Lookup (`shodan_host_summary`, `shodan_banners`, and `shodan_dns` tables)
4) Scrape and Decode SSL Certificate (`certificate_decoded` table - cert is also written to a local file in `./ssl/` directory)
5) Brute force additional subdomains (`bruteforced_subdomains` table)

The Bruteforce additional subdomains section can be time-consuming, so just specify an empty or short wordlist for faster execution if this function is not necessary.

The final section prints information from the output DB that is created:

6) Print DB Info (print all table names and tables)

## Limitations

This tool does not have the capability to resolve past a proxy, if a given domain is proxied through Cloudflare or a similar WAF/CDN it will return the records for this IP and not the actual host server, however the tool's output may still be useful in determining the footprint of subdomains and whether everything is configured correctly.

Subdomain discovery is not a perfect science, and while active subdomains can be quickly discovered using shodan and decoding the SAN DNS names in the certificate, the certificate may be using a wildcard or more subdomains that aren't unregistered might be active due to a misconfiguration, which is why bruteforce enumeration is still necessary.