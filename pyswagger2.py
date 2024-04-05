import argparse
import logging
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.hazmat.primitives import serialization
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
import json
import os
import re
from pathlib import Path
from datetime import datetime

# Assuming keys.params contains a dictionary mapping certificate filenames to passwords
from keys.params import params, loadcerts

TIMESTAMP = datetime.now().strftime("%Y%m%dT%H%M%S")
LOG_DIR = Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

def setup_logging(p12_file):
    log_file = LOG_DIR / f"{p12_file}/{TIMESTAMP}.json"
    logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    return log_file

class SSLAdapter(HTTPAdapter):
    def __init__(self, ssl_version=None):
        self.ssl_version = ssl_version or ssl.PROTOCOL_TLS
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ssl_version=self.ssl_version, cert_reqs=ssl.CERT_NONE)
        kwargs['ssl_context'] = context
        super().init_poolmanager(*args, **kwargs)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Automates requests to discovered endpoints.")
    parser.add_argument("--local-file", default="", help="Path to a local specification file.")
    return parser.parse_args()

def load_p12_certificate(p12_path, p12_password):
    p12_path = Path("keys") / p12_path
    with p12_path.open('rb') as p12_file:
        p12_data = p12_file.read()
    private_key, certificate, additional_certificates = load_key_and_certificates(p12_data, p12_password.encode(), default_backend())

    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )

    return cert_pem, key_pem

def log_request_details(log_file, url, status_code, cert_file, response_content):
    try:
        response_json = json.loads(response_content)
    except json.JSONDecodeError:
        response_json = {"raw_text": response_content}

    log_entry = {
        "timestamp": TIMESTAMP,
        "url": url,
        "status_code": status_code,
        "certificate_file": cert_file,
        "response": response_json
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

    with open(log_file, 'w') as file:
        json.dump(logs, file, indent=4, ensure_ascii=False)

def generate_get_requests_from_spec(spec, session, base_url, log_file, cert_filename):
    missing_params = []
    #INSERT SLEEP FOR POST
    paths = spec.get('paths', {})
    for orig_path, methods in paths.items():
        if 'get' in methods:
            placeholders = re.findall(r'\{([^\}]+)\}', orig_path)
            if len(placeholders) >= 1:
                if all(placeholder in params for placeholder in placeholders):
                    for placeholder in placeholders:
                        if placeholder in params:
                        #Check if testing multiple entries for single param
                            if isinstance(params[placeholder], list): 
                                    # Internal loop to make multiple requests to test multiple values for same param
                                    for value in params[placeholder]:
                                        path = orig_path.replace(f'{{{placeholder}}}', value)
                                        try:
                                            full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
                                            logging.info(f"Requesting replaced path: {full_url}")
                                            response = session.get(full_url)
                                            log_request_details(log_file, full_url, response.status_code, cert_filename, response.text)
                                        except Exception as e:
                                            logging.error(f"Failed to make GET request to {full_url}: {e}")
                        
                        elif placeholder not in params:
                            logging.warning(f"Skipping path {path} due to missing parameter: {placeholder}")
                            break
                        else:
                            path = path.replace(f'{{{placeholder}}}', params[placeholder])
                            try:
                                full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
                                logging.info(f"Requesting replaced path: {full_url}")
                                response = session.get(full_url)
                                log_request_details(log_file, full_url, response.status_code, cert_filename, response.text)
                            except Exception as e:
                                logging.error(f"Failed to make GET request to {full_url}: {e}")
                else:
                    logging.info(f"Not all parameters have been supplied {placeholders} for {full_url}")
            elif len(placeholders) == 0:
                logging.info(f"No parameters supplied, skipping: {orig_path}")

def cross_cert_test(local_file):
    if not local_file:
        logging.error("No local file specified for cross certification test.")
        return
    
    try:
        with open(local_file, 'r') as file:
            spec = json.load(file)
    except Exception as e:
        logging.error(f"Failed to load specification file for cross certification test: {e}")
        return

    base_url = f"{spec.get('schemes', ['https'])[0]}://{spec.get('host')}{spec.get('basePath', '/')}"

    for p12_file, p12_password in loadcerts.items():
        cert_pem, key_pem = load_p12_certificate(p12_file, p12_password)
        cert_temp_file = 'keys/cert_temp.pem'
        key_temp_file = 'keys/key_temp.pem'
        with open(cert_temp_file, 'wb') as cert_file:
            cert_file.write(cert_pem)
        with open(key_temp_file, 'wb') as key_file:
            key_file.write(key_pem)
        cert = (cert_temp_file, key_temp_file)

        session = requests.Session()
        session.cert = cert
        log_file = setup_logging(p12_file)
        generate_get_requests_from_spec(spec, session, base_url, log_file, p12_file)

def gen_post_request(local_file):
    pass
    # TODO
    # Read Swagger spec
    # try:
    #     with open(local_file, 'r') as file:
    #         spec = json.load(file)
    # except Exception as e:
    #     logging.error(f"Failed to load specification file for cross certification test: {e}")
    #     return

    # # Load SSL Session
    # for p12_file, p12_password in loadcerts.items():
    #     cert_pem, key_pem = load_p12_certificate(p12_file, p12_password)
    #     cert_temp_file = 'keys/cert_temp.pem'
    #     key_temp_file = 'keys/key_temp.pem'
    #     with open(cert_temp_file, 'wb') as cert_file:
    #         cert_file.write(cert_pem)
    #     with open(key_temp_file, 'wb') as key_file:
    #         key_file.write(key_pem)
    #     cert = (cert_temp_file, key_temp_file)

    #     session = requests.Session()
    #     session.cert = cert
    #     log_file = setup_logging(p12_file)
    
    #     #INSERT SLEEP FOR POST
    #     paths = spec.get('paths', {})
    #     for orig_path, methods in paths.items():
    #         if 'post' in methods:
    #             placeholders = re.findall(r'\{([^\}]+)\}', orig_path)
    #             if len(placeholders) >= 1:
    #                 if all(placeholder in params for placeholder in placeholders):
    #                     for placeholder in placeholders:
    #                         if placeholder in params:
    #                         #Check if testing multiple entries for single param
    #                             if isinstance(params[placeholder], list): 
    #                                     # Internal loop to make multiple requests to test multiple values for same param
    #                                     for value in params[placeholder]:
    #                                         path = orig_path.replace(f'{{{placeholder}}}', value)
    #                                         try:
    #                                             full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    #                                             logging.info(f"Requesting replaced path: {full_url}")
    #                                             response = session.get(full_url)
    #                                             log_request_details(log_file, full_url, response.status_code, cert_filename, response.text)
    #                                         except Exception as e:
    #                                             logging.error(f"Failed to make GET request to {full_url}: {e}")
                            
    #                         elif placeholder not in params:
    #                             logging.warning(f"Skipping path {path} due to missing parameter: {placeholder}")
    #                             break
    #                         else:
    #                             path = path.replace(f'{{{placeholder}}}', params[placeholder])
    #                             try:
    #                                 full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    #                                 logging.info(f"Requesting replaced path: {full_url}")
    #                                 response = session.get(full_url)
    #                                 log_request_details(log_file, full_url, response.status_code, cert_filename, response.text)
    #                             except Exception as e:
    #                                 logging.error(f"Failed to make GET request to {full_url}: {e}")
    #                 else:
    #                     logging.info(f"Not all parameters have been supplied {placeholders} for {full_url}")
    #             elif len(placeholders) == 0:
    #                 logging.info(f"No parameters supplied, skipping: {orig_path}")



def main():
    args = parse_arguments()
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    #cross_cert_test(args.local_file)
    gen_post_request(args.local_file)

if __name__ == "__main__":
    main()
