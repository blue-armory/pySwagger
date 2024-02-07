import argparse
import logging
import requests
import os
import re
import ssl
from requests.adapters import HTTPAdapter
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
import json
import requests
from urllib.parse import urljoin
from urllib3.util import Retry
from keys.params import params
from datetime import datetime
from requests.packages.urllib3.util.ssl_ import create_urllib3_context

# Configuration for dangerous strings and quiet mode
dangerous_strings = ["test_dangerous"]
quiet = False
avoid_dangerous_requests = "y"
risk_surveyed = False
timestamp = datetime.now().strftime("%Y%m%dT%H%M")

class SSLAdapter(HTTPAdapter):
    """An HTTPS Transport Adapter that uses an arbitrary SSL version."""
    def __init__(self, ssl_version=None, **kwargs):
        self.ssl_version = ssl_version
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ssl_version=self.ssl_version, cert_reqs=ssl.CERT_NONE)
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Automates requests to discovered endpoints.")
    parser.add_argument("--local-file", help="Path to a local specification file.", default="")
    parser.add_argument("--proxy", help="Proxy address in the format ip:port.", default="NOPROXY")
    parser.add_argument("--insecure", help="Disable SSL certificate verification.", action="store_true")
    parser.add_argument("--p12-file", help="Path to a .p12 certificate file.", default="")
    parser.add_argument("--p12-password", help="Password for the .p12 certificate file.", default="")
    parser.add_argument("--params-file", help="Path to a JSON file containing parameters for GET requests.", default="{}")
    return parser.parse_args()

def load_p12_certificate(p12_path, p12_password):
    p12_path = f"keys/{p12_path}"
    with open(p12_path, 'rb') as p12_file:
        p12_data = p12_file.read()
    private_key, certificate, additional_certificates = load_key_and_certificates(p12_data, p12_password.encode(), default_backend())
    
    # Convert the private key and certificate to PEM format for requests
    cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return cert_pem, key_pem

def check_and_configure_proxy(proxy, insecure, cert=None):
    session = requests.Session()
    if insecure:
        session.mount('https://', SSLAdapter(ssl.PROTOCOL_TLS))
    if proxy != "NOPROXY":
        session.proxies = {"http": proxy, "https": proxy}
    if cert:
        session.cert = cert
    return session

def log_request_details(log_file, url, status_code, reason, cert_file, response_content):
    try:
        response_json = json.loads(response_content)
    except json.JSONDecodeError:
        response_json = {"raw_text": f"{response_content}"}

    log_entry = {
        "timestamp": timestamp,
        "url": url,
        "status_code": status_code,
        "reason": reason,
        "certificate_file": cert_file,
        "response": response_json  # Assuming response_content is a JSON string
    }
    
    try:
        # Try to read the existing content of the log file
        with open(log_file, 'r') as file:
            logs = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        # If the file doesn't exist or is not valid JSON, start with an empty list
        logs = []

    # Append the new log entry to the list of logs
    logs.append(log_entry)

    # TODO: Create a better logging solution than keeping all log entries in memory in a list
    # Write the updated list of logs back to the file
    with open(log_file, 'w') as file:
        json.dump(logs, file, indent=4, ensure_ascii=False)

def generate_get_requests_from_spec(local_file_path, cert=None, retries=0, log_file=f"logs/requests{timestamp}.json"):
    #Note: This is based on Swagger 2.0 spec
    with open(local_file_path, 'r') as file:
        try:
            spec = json.load(file)
        except ValueError as e:
            print(f"Error reading specification file: {e}")
            return
    logging.info("[*] Swagger file loaded successfully!")

    retry_strategy = Retry(
        total=retries,
        status_forcelist=[429, 500, 502, 503, 504],  # Retry on these status codes
        allowed_methods=["GET"],  # Retry for GET method only
        backoff_factor=1  # Time between retries
    )

    session = requests.Session()
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    if cert:
        session.cert = cert

    host = spec.get('host', '')
    basePath = spec.get('basePath', '/')
    schemes = spec.get('schemes', ['https'])  # Default to HTTPS if not specified
    base_url = f"{schemes[0]}://{host}{basePath}"  # Use the first scheme as the protocol
    paths = spec.get('paths', {})

    for path, methods in paths.items():
        if 'get' in methods:
            # Identify placeholders in the path using a regular expression
            placeholders = re.findall(r'\{([^\}]+)\}', path)
            if not placeholders:
                print(f"Skipping path {path} due to no required parameters.")
                continue

            missing_params = []  # List to keep track of missing parameters
        
        # Check if each placeholder has a corresponding value in params
        for placeholder in placeholders:
            if placeholder in params:
                path = path.replace(f'{{{placeholder}}}', params[placeholder])
            else:
                missing_params.append(placeholder)
        
        # If there are any missing parameters, skip this path
        if missing_params:
            print(f"Skipping path {path} due to missing parameters: {', '.join(missing_params)}.")
            continue
        
        full_url = urljoin(base_url, path)
        
        # Optionally adjust http to https
        full_url = full_url.replace("http://", "https://")
        
        print(f'[+] GET request URL: {full_url}')
        
        # Perform the GET request (optional)
        try:
            response = session.get(full_url)
            print(f"Response from {full_url}: {response.status_code} - {response.reason}")
            log_request_details(log_file, full_url, response.status_code, response.reason, os.path.basename(args.p12_file) if cert else "No Certificate", response.content.decode('utf-8'))
        except Exception as e:
            print(f"Error performing GET request to {full_url}: {e}")
            log_request_details(log_file, full_url, response.status_code, response.reason, os.path.basename(args.p12_file) if cert else "No Certificate", "ERROR")

def automate(local_file, proxy, insecure, p12_file, p12_password):
    cert = None
    if p12_file and p12_password:
        cert_pem, key_pem = load_p12_certificate(p12_file, p12_password)
        # You might need to save these PEM files temporarily or adjust requests to use them directly
        cert_temp_file = 'keys/cert_temp.pem'
        key_temp_file = 'keys/key_temp.pem'
        with open(cert_temp_file, 'wb') as cert_file:
            cert_file.write(cert_pem)
        with open(key_temp_file, 'wb') as key_file:
            key_file.write(key_pem)
        cert = (cert_temp_file, key_temp_file)

    logging.basicConfig(level=logging.INFO)
    logging.info("[*] Gathering API details.")    

    if local_file:
        try:
            generate_get_requests_from_spec(local_file, cert)
        except IOError as e:
            logging.error(f"Error opening file: {e}")
    else:
        logging.error("No local file specified. Please provide a local specification file.")

if __name__ == "__main__":
    args = parse_arguments()
    automate(args.local_file, args.proxy, args.insecure, args.p12_file, args.p12_password)
