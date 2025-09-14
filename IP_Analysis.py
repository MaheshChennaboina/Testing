import os
import time
import json
import ipaddress
import requests
import pandas as pd
from datetime import datetime, timedelta
import logging
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import deque

# Setup logging
logging.basicConfig(filename='virustotal_analysis.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_api_keys(file_path):
    """Load API keys from JSON file using round-robin rotation."""
    with open(file_path, 'r') as file:
        keys = json.load(file).get('api_keys', [])
    return deque(keys) if keys else None

def convert_to_ist(utc_timestamp):
    """Convert UTC timestamp to IST (UTC+5:30), handling invalid timestamps."""
    try:
        if utc_timestamp > 0:
            return (datetime.utcfromtimestamp(utc_timestamp) + timedelta(hours=5, minutes=30)).strftime('%Y-%m-%d %H:%M:%S IST')
        else:
            return "Unknown"
    except (ValueError, OverflowError):
        logging.warning(f"Invalid timestamp detected: {utc_timestamp}")
        return "Unknown"

def get_virustotal_info(api_key, ip_address):
    """Retrieve VirusTotal information for an IP."""
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        attributes = data.get('data', {}).get('attributes', {})
        return {
            'Malicious_Count': attributes.get('last_analysis_stats', {}).get('malicious', 0),
            'ASN_Owner': attributes.get('as_owner', ''),
            'Country': attributes.get('country', ''),
            'Fortinet_Category': attributes.get('last_analysis_results', {}).get('Fortinet', {}).get('category', 'Unknown'),
            'Fortinet_Result': attributes.get('last_analysis_results', {}).get('Fortinet', {}).get('result', 'Uncategorized'),
            'Last_Analysis_Date': convert_to_ist(attributes.get('last_analysis_date', 0))  # Converted to IST
        }
    elif response.status_code == 429:
        retry_after = int(response.headers.get('Retry-After', 60))
        logging.warning(f'Rate limit exceeded. Retrying after {retry_after} seconds...')
        time.sleep(retry_after)
    else:
        logging.error(f'Error {response.status_code} for IP {ip_address}')
    
    return {}

def reanalyse_ip(api_key, ip_address):
    """Trigger reanalysis of an IP in VirusTotal."""
    
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/analyse'
    # print("I'm in the reanlayse")
    headers = {'x-apikey': api_key}
    response = requests.post(url, headers=headers)

    if response.status_code == 200:
        logging.info(f'Reanalysis triggered for IP: {ip_address}')
        return True
    else:
        logging.error(f'Failed to trigger reanalysis for IP {ip_address}. Status code: {response.status_code}')
        return False

def process_ip_reanalysis(ip_address, api_keys):
    """Reanalyse an IP asynchronously."""
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        logging.warning(f'Invalid IP address: {ip_address}')
        return None

    api_key = api_keys[0]  # Use first API key
    api_keys.rotate(-1)  # Rotate for next request

    return reanalyse_ip(api_key, ip_address)

def process_ip_retrieval(ip_address, api_keys):
    """Retrieve VirusTotal data for an IP after reanalysis."""
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        logging.warning(f'Invalid IP address: {ip_address}')
        return None

    api_key = api_keys[0]
    api_keys.rotate(-1)

    return {'IP': ip_address, **get_virustotal_info(api_key, ip_address)}

def process_excel(input_file, output_file, api_keys):
    """Processes the IP list, reanalyses, sleeps, and fetches VT details."""
    if not os.path.exists(input_file):
        logging.error(f'Input file {input_file} does not exist.')
        return

    df = pd.read_excel(input_file)
    ips = df['IP'].dropna().unique()

    # Step 1: Trigger Reanalysis for All IPs
    with ThreadPoolExecutor(max_workers=10) as executor:
        list(tqdm(executor.map(process_ip_reanalysis, ips, [api_keys]*len(ips)), total=len(ips), desc="Triggering Reanalysis"))

    # Step 2: Sleep for 1 Minute
    logging.info("Sleeping for 60 seconds to allow VirusTotal processing...")
    time.sleep(60)

    # Step 3: Retrieve Updated Results
    results = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_map = {executor.submit(process_ip_retrieval, ip, api_keys): ip for ip in ips}
        for future in tqdm(as_completed(future_map), total=len(ips), desc="Fetching Updated Results"):
            result = future.result()
            if result:
                fortinet_result = result.get('Fortinet_Result', 'Uncategorized')

                if fortinet_result not in results:
                    results[fortinet_result] = []
                results[fortinet_result].append(result)

    output_folder = "Result"
    os.makedirs(output_folder, exist_ok=True)
    output_path = f"{output_folder}/{output_file}"

    with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
        for category, data in results.items():
            safe_category_name = category[:31]
            logging.info(f"Saving {len(data)} entries to sheet: {safe_category_name}")
            
            sheet_df = pd.DataFrame(data)
            sheet_df.to_excel(writer, sheet_name=safe_category_name, index=False)

    logging.info(f'Results saved in \"{output_path}\" with categorized sheets.')

if __name__ == "__main__":
    api_keys = load_api_keys('api_keys.json')

    if not api_keys:
        logging.error('No API keys found in api_keys.json.')
    else:
        input_file = 'IP_input.xlsx'
        output_file = f"output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        process_excel(input_file, output_file, api_keys)
