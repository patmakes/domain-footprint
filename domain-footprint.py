#!/usr/bin/env python
# coding: utf-8

# # Domain-Footprint
# ## Script for the enumeration of DNS records, WhoIs Records, IPs, SSL Certificate, and subdomains associated with a public-facing domain
# ##### *- please note that a shodan API key and Residential Proxy Subscription is required for full functionality*

# ### - Install dependencies with pip & import necessary modules

# Import libraries
from dotenv import load_dotenv
import IPy
import re
import time
import requests
import os
import socket
import whois
import dns.resolver
import random
from tqdm import tqdm
from IPy import IP
from cryptography import x509, exceptions, hazmat
from cryptography.x509 import NameAttribute, ObjectIdentifier, Name
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, utils
import pandas as pd
import numpy as np
from bs4 import BeautifulSoup
import ssl
import sys
import csv
import socket
from OpenSSL import crypto, SSL
import shodan
from pprint import pprint
import sqlite_utils
import datetime


# ### - Configure target domain, destination database, proxy, shodan API

#load environment variables from the .env file
# override=True is to force the .env file to be reloaded, in some environments it isn't reloaded properly after
# modification to change the target URL 
load_dotenv(override=True)

# set target domain

# - domain format - <domain>.<extension> - no leading characters or slashes after
domain = os.getenv("DOMAIN")

domain_string = domain.split('.')[0]


# set up proxy
proxy_test_url = os.getenv("PROXY_TEST_URL")
proxy = os.getenv("HTTP_PROXY")
os.environ['http_proxy'] = os.getenv("HTTP_PROXY")
os.environ['https_proxy'] = os.getenv("HTTPS_PROXY")



#create timestamp for DB

# Get the current date and time
current_time = datetime.datetime.now()

# Format the timestamp as a string
timestamp = current_time.strftime("%Y-%m-%d-%H%M%S")


# set up destination db
db = sqlite_utils.Database(f"./output_db/{domain_string}-domain-footprint-{timestamp}.db")



# set up shodan API
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

shodan_api = shodan.Shodan(SHODAN_API_KEY)


# ### - Test Target and Proxy

# test proxy
def testProxy():
    test_url = proxy_test_url

    #Test for public IP
    ip = requests.get('https://api.ipify.org', proxies = {'http': proxy, 'https': proxy }).content.decode('utf8')
    print('Current public IP address is: {}'.format(ip))

    #Test proxy
    test1 = requests.get(test_url).content.decode('utf8')
    print('Proxy server IP is at: {}'.format(test1))
    

    #Test proxy again for IP rotation
    test2 = requests.get(test_url).content.decode('utf8')
    print('Proxy server IP is now at: {}'.format(test2))


# this tests the proxy - if you would like to proceed without the proxy or have not configured it comment this out (not reccomended)
testProxy()

def test_target():
    domain_address = f"http://{domain}"
    target = requests.get(domain_address)
    print(f'request to target domain gave response: {target.status_code}')
    if target.status_code != 200:
        sys.exit()


# confirm that the target returns code 200 before proceeding
test_target()


# ## Main Functions

# ### 1) DNS & Reverse DNS lookup functions

# regex for ip dns records reverse lookup
ip_v4_regex = re.compile(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")

#All DNS record types for dns enumeration
record_types = ['NONE',
        'A',
        'NS',
        'MD',
        'MF',
        'CNAME',
        'SOA',
        'MB',
        'MG',
        'MR',
        'NULL',
        'WKS',
        'PTR',
        'HINFO',
        'MINFO',
        'MX',
        'TXT',
        'RP',
        'AFSDB',
        'X25',
        'ISDN',
        'RT',
        'NSAP',
        'NSAP-PTR',
        'SIG',
        'KEY',
        'PX',
        'GPOS',
        'AAAA',
        'LOC',
        'NXT',
        'SRV',
        'NAPTR',
        'KX',
        'CERT',
        'A6',
        'DNAME',
        'OPT',
        'APL',
        'DS',
        'SSHFP',
        'IPSECKEY',
        'RRSIG',
        'NSEC',
        'DNSKEY',
        'DHCID',
        'NSEC3',
        'NSEC3PARAM',
        'TLSA',
        'HIP',
        'CDS',
        'CDNSKEY',
        'CSYNC',
        'SPF',
        'UNSPEC',
        'EUI48',
        'EUI64',
        'TKEY',
        'TSIG',
        'IXFR',
        'AXFR',
        'MAILB',
        'MAILA',
        'ANY',
        'URI',
        'CAA',
        'TA',
        'DLV',
                   ]


# get dns information and create dataframe
def enumerate_dns(domain):
    dns_list = []
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    for type in record_types:
        print(f"Trying {type}")
        try:
            answers = resolver.resolve(domain, type)
            
            for rdata in answers:
                Record_Type = rdata.rdtype
                Data = rdata.to_text()
                dns_dict = dict({'Domain': domain, "Record": type, "Record_Type": Record_Type, "Data": rdata.to_text()})
                dns_list.append(dns_dict)
                if ip_v4_regex.match(Data):
                    print(f"performing reverse lookup for A Record IP {Data}")
                    domain_ip = Data
                    print(f"Domain Host IP: {domain_ip}")
                    rev_name = IP(domain_ip).reverseName()
                    print(f"Reverse Lookup: {rev_name}")
                    rev_record_types = record_types
                    for rev_type in rev_record_types:
                        try:
                            answers = resolver.resolve(rev_name, rev_type)
                            for rdata in answers:
                                rev_dns_dict = dict({'Domain': rev_name, "Record": rev_type, "Record_Type": rdata.rdtype, "Data": rdata.to_text()})
                                dns_list.append(rev_dns_dict)
                        except Exception as e:
                            print(e)
                    top_domain_name = f"{'.'.join(Data.split('.')[::-1][1:])}.in-addr.arpa."
                    print(top_domain_name)
                    top_record_types = record_types
                    for top_type in top_record_types:
                        try:
                            answers = dns.resolver.resolve(top_domain_name, top_type)
                            for rdata in answers:
                                top_dns_dict = dict({'Domain': top_domain_name, "Record": top_type, "Record_Type": rdata.rdtype, "Data": rdata.to_text()})
                                dns_list.append(top_dns_dict)
                        except Exception as e:
                            print(e)
        except Exception as e:
            print(e)
    dns_df = pd.DataFrame(dns_list)
    return dns_df

# create dns dataframe
dns_df = enumerate_dns(domain=domain)

# TODO - set up dns_lookup table, iterate through dns_df and add rows to database
db['dns_lookup'].insert_all(dns_df.to_dict(orient='records'), pk='id', alter=True)


# ### 2) Whois lookup functions

# create class to parse domain whois info
class DomainInfo:
    def __init__(self, domain_info):
        self._domain_info = domain_info

    def to_dict(self):
        result = {}
        for key, value in self._domain_info.items():
            if isinstance(value, list):
                result[key] = [str(v) for v in value]
            else:
                result[key] = str(value)
        return result

# function - perform whois lookup and convert the result to a dictionary using DomainInfo class
def whois_lookup(domain):
    try:
        domain_info = whois.whois(f"{domain}")
        domain_obj = DomainInfo(domain_info)
        return domain_obj.to_dict()
    except Exception as e:
        print(f"{domain} lookup failed. Error: {e}")

# create dataframe from dict and add rows from dataframe to db
whois_info_list = []
whois_info_dict = whois_lookup(domain=domain)
whois_info_list.append(whois_info_dict)
whois_info_df = pd.DataFrame(whois_info_list)

# set up whois_lookup table and add dataframe to db
db['whois_lookup'].insert_all(whois_info_df.to_dict(orient='records'), pk='id', alter=True)

# ### 3) Shodan Lookup

# function to get data for domain host from shodan API
def host_ip_shodan(domain):
    #get host ip
    domain_ip = socket.gethostbyname(f"{domain}")
    
    #lookup host
    host = shodan_api.host(domain_ip)
    
    return host

# get host data
host=host_ip_shodan(domain=domain)

# Shodan host Summary info
shodan_host_info_dict = {key: value for key, value in host.items() if key != 'data'}
shodan_host_info_list = []
shodan_host_info_list.append(shodan_host_info_dict)
shodan_host_info_df = pd.DataFrame(shodan_host_info_list)

# set up shodan_host_summary table, iterate through shodan_host_info_df and add to db
db['shodan_host_summary'].insert_all(shodan_host_info_df.to_dict(orient='records'), pk='id', alter=True)

# shodan host banners
#get all banners, print type and append to list to create df
shodan_banner_list = []
for item in host['data']:
    banner_data = """ Port: {} \r\n IP: {} \r\n Banner: {} """.format(item['port'], item['ip_str'], item['data'])
    port = item['port']
    # Splitting the banner data into lines
    if port == 22:
        banner_data = """ Port: {} \n IP: {} \n Banner: {} """.format(item['port'], item['ip_str'], item['data'])
        banner_lines = banner_data.split('\n')
    else:
        banner_lines = banner_data.split('\r\n')
    # Dictionary to store key-value pairs
    shodan_banner_dict = {}
    line_counter = 0
    for line in banner_lines:
        if line.strip():  # Ignore empty lines
            if ': ' in line:
                key, value = line.split(': ', 1)
                shodan_banner_dict[key] = value
            else:
                # Handle lines without the expected delimiter
                info_key = f'port {port}-info-{line_counter}'
                line_counter+=1
                shodan_banner_dict[info_key] = line
    line_counter = 0
    shodan_banner_list.append(shodan_banner_dict)

# Create DataFrame
shodan_banner_df = pd.DataFrame(shodan_banner_list)

# replace NaN values with Null
shodan_banner_df = shodan_banner_df.fillna('NULL')

# setup shodan_banners table in db, iterate through shodan_banner_df and add to table in db
db['shodan_banners'].insert_all(shodan_banner_df.to_dict(orient='records'), pk='id', alter=True)

# get shodan dns and subdomain info
shodan_dns_info = shodan_api.dns.domain_info(domain=domain, history=False, type=None, page=1)

## Shodan DNS / Subdomain info to df to db

#set up list
shodan_dns_list = []

# Iterate through the 'data' key in the original dictionary
for entry in shodan_dns_info['data']:
    new_dict = {}
    # Iterate through the key:value pairs in each 'data' entry and append to new_dict
    for key, value in entry.items():
        new_dict[key] = value
    
    # Append new_dict to the new_list
    shodan_dns_list.append(new_dict)
    
shodan_dns_records_df = pd.DataFrame(shodan_dns_list)

# cleanup - replace '' values with NULL
shodan_dns_records_df = shodan_dns_records_df.replace('', pd.NA)

# cleanup - replace NaN values with NULL
shodan_dns_records_df = shodan_dns_records_df.fillna('NULL')

## set up shodan_dns table, iterate through shodan_dns_records_df and add records to db
db['shodan_dns'].insert_all(shodan_dns_records_df.to_dict(orient='records'), pk='id', alter=True)


# ### 4) Scrape and decode SSL Certificate

# function to scrape certificate from domain host
def scrape_certificate(domain):
    port = 443

    # get cert using ssl
    cert = ssl.get_server_certificate((domain, port))

    # Write the certificate to a file
    folder_path = './ssl'
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    file_path = os.path.join(folder_path, f'{domain_string}_certificate.pem')
    with open(file_path, 'wb') as cert_file:
        cert_file.write(cert.encode('utf-8'))


# get public certificate from domain
scrape_certificate(domain)

# set up class for decoded certificate information as dict
class DecodedCertificate:
    def __init__(self, cert_data):
        self.cert_data = cert_data
        self.cert_decoded = x509.load_pem_x509_certificate(cert_data.encode('utf-8'), default_backend())

    def _serialize_public_key(self):
        # Implement serialization logic for public key
        return self.cert_decoded.public_key()

    def _get_extensions(self):
        extensions = {}
        for extension in self.cert_decoded.extensions:
            ext_oid = extension.oid.dotted_string
            ext_value = extension.value
            extensions[ext_oid] = ext_value
        return extensions

    def to_dict(self):
        certificate_dict = {
            'Version': self.cert_decoded.version,
            'Issuer': self.cert_decoded.issuer,
            'Subject': self.cert_decoded.subject,
            'Not_Valid_After': self.cert_decoded.not_valid_after,
            'Not_Valid_Before': self.cert_decoded.not_valid_before,
            'Fingerprint': self.cert_decoded.fingerprint(hashes.SHA256()).hex(),
            'Public_Key': self._serialize_public_key(),
            'Serial_Number': self.cert_decoded.serial_number,
            'Signature': self.cert_decoded.signature,
            'Signature_Algorithm_OID': self.cert_decoded.signature_algorithm_oid,
            'Signature_Algorithm_Parameters': self.cert_decoded.signature_algorithm_parameters,
            'Signature_Hash_Algorithm': self.cert_decoded.signature_hash_algorithm,
            'TBS_Certificate_Bytes': self.cert_decoded.tbs_certificate_bytes,
            'TBS_Precertificate_Bytes': self.cert_decoded.tbs_precertificate_bytes,
            'Extensions': self._get_extensions(),
        }
        return certificate_dict


# function to decode certificate from file
def decode_certificate_from_file(file_path):
    with open(file_path, 'rb') as cert_file:
        cert_bytes = cert_file.read()
        cert_str = cert_bytes.decode('utf-8')

    cert_decoded = DecodedCertificate(cert_str)

    # add certificate subdomains to column in cert_info_df
    cert_dict = cert_decoded.to_dict()

    return cert_dict


# function to decode x509 cryptography objects
def extract_values_from_hazmat_objects(obj):
    if isinstance(obj, x509.Name):
        return str(obj)
    elif hasattr(obj, 'public_bytes'):
        return obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    elif isinstance(obj, x509.SignatureAlgorithmOID):
        return obj.dotted_string
    elif isinstance(obj, x509.CertificateBuilder):
        return {k: extract_values_from_hazmat_objects(v) for k, v in obj.__dict__.items()}
    elif isinstance(obj, list):
        return [extract_values_from_hazmat_objects(item) for item in obj]
    elif isinstance(obj, serialization.NoEncryption):
        return 'No Encryption'
    elif isinstance(obj, serialization.BestAvailableEncryption):
        return 'Best Available Encryption'
    elif isinstance(obj, x509.Extension):
        return {
            'OID': obj.oid.dotted_string,
            'Critical': obj.critical,
            'Value': obj.value
        }
    elif hasattr(obj, 'name'):
        return obj.name
    else:
        return str(obj)


# create cert dict
cert_dict = decode_certificate_from_file(f'./ssl/{domain_string}_certificate.pem')

# flatten the dictionary
flattened_dict = {key: extract_values_from_hazmat_objects(value) for key, value in cert_dict.items()}

#create dataframe from flattened dict
cert_dict_df = pd.DataFrame(flattened_dict, index=[0])

#Parse Subdomains from cert_info_df['Extensions']
extensions_string = str(cert_dict.get('Extensions', {}))

# Define a regular expression to match DNSName values in the SubjectAlternativeName
subdomain_regex = r"<DNSName\(value='(.*?)'\)>"

# Extract domain names using the regular expression
cert_subdomains = re.findall(subdomain_regex, extensions_string)

# Add the list of subdomains to the DataFrame
cert_dict_df['cert_subdomains'] = [cert_subdomains]

# set up certificate_decoded table and write cert_info_df to db
db['certificate_decoded'].insert_all(cert_dict_df.to_dict(orient='records'), pk='id', alter=True)


# ### 5) Attempt to bruteforce additional subdomains with wordlist

# function to get IP from subdomain
def subdomain_ip_lookup(base_domain, subdomain):
    try:
        print("getting IP")
        subdomain_ip = socket.gethostbyname(f"{subdomain}.{base_domain}")
        print(f"{subdomain}.{base_domain} returned IP: {subdomain_ip}")
    except Exception as e:
        print(f"Could not get IP. Error: {e}")

# subdomain bruteforce wordlist enumeration thread
def bruteforce_enumeration_thread(base_domain):
    discovered_subdomains = []

    def populate_wordlist():
        wordlist = []
        wordlist_file = os.getenv("WORDLIST_FILE_PATH")
        """Yield a list of common subdomain words."""
        with open(wordlist_file, "r") as file:
            for line in file:
                for word in line.strip().split():
                    yield word
                    wordlist.append(word)
        return wordlist

    wordlist = list(populate_wordlist())

    def response_test(test_url):
        try:
            return requests.get(test_url)
        except Exception as e:
            print(e)
            pass

    print("Starting bruteforce subdomain enumeration")
    for word in tqdm(wordlist, total=len(wordlist)):
        test_url = "http://"+word+"."+base_domain
        response = response_test(test_url)
        subdomain = word
        try:
            subdomain_ip = socket.gethostbyname(f"{subdomain}.{base_domain}")
            if ip_v4_regex.match(subdomain_ip):
                if(response.status_code == 200):
                    print(f"{test_url} Discovered !!!")
                    try:
                        subdomain_ip_lookup(base_domain=base_domain, subdomain=subdomain)
                    except Exception as e:
                        print(f"{test_url} did not resolve properly: {e}")
                    discovered_subdomains.append({
                        'test_url': test_url,
                        'subdomain_ip': subdomain_ip,
                        'response code': response.status_code
                    })
        except socket.gaierror as e:
            if e.args == (-2, 'Name or service not known'):
                pass
        except Exception as exception:
            pprint(exception)
        time.sleep(random.uniform(0,1))
    print(f'bruteforce attempt discovered subdomains: {discovered_subdomains}')
    print("Bruteforce Subdomain Enumeration Complete")
    return discovered_subdomains

discovered_subdomains=bruteforce_enumeration_thread(base_domain=domain)

discovered_subdomains_df = pd.DataFrame(discovered_subdomains)

## set up bruteforced_subdomains table, iterate through discovered_subdomains_df and add records to db
db['bruteforced_subdomains'].insert_all(discovered_subdomains_df.to_dict(orient='records'), pk='id', alter=True)


# ### 6) Print DB info

# set up db tables
tables = db.table_names()

pprint(tables)
print()

#iterate through tables
for table in tables:
    rows = db[f'{table}'].rows
    print(f"Table: {table}")
    table_info = db[table].columns_dict
    for column_name, column_type in table_info.items():
        print(f"  {column_name}: {column_type}")
    print()
    for row in rows:
        print(row)
    print()