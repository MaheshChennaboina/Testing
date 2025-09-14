import requests
import pandas as pd
import json
import os
from datetime import datetime
import time
from colorama import init, Fore, Style
import logging
from openpyxl import load_workbook
import socket
import whois
from concurrent.futures import ThreadPoolExecutor
import multiprocessing

# Initialize colorama
init()

# Configure logging
logging.basicConfig(filename='domain_analysis.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load API keys from api_keys.json and set up rotation
with open('api_keys.json') as config_file:
    config = json.load(config_file)
api_keys = config['api_keys']

def get_next_api_key():
    """Rotate through API keys to avoid rate limits."""
    global api_keys
    api_keys.append(api_keys.pop(0))  # Moves the first key to the end
    return api_keys[0]

# Optimized thread count based on system resources
max_threads = min(10, multiprocessing.cpu_count() * 2)

whois_cache = {}  # Store WHOIS results to prevent redundant lookups

def sanitize_domain(domain):
    """Replace [.] with . to normalize domain format."""
    return domain.replace("[.]", ".")

def check_domain(domain, reanalyze=False):
    headers = {"x-apikey": get_next_api_key()}
    domain = sanitize_domain(domain)  # Ensure domain is cleaned before processing

    if reanalyze:
        print(Fore.YELLOW + f"Requesting reanalysis for {domain}..." + Style.RESET_ALL)
        rescan_response = requests.post(f"https://www.virustotal.com/api/v3/domains/{domain}/analyse", headers=headers)
        # print(f"Hello in Re-analyis {domain}")
        if rescan_response.status_code == 200:
            print(Fore.YELLOW + f"Waiting for updated analysis..." + Style.RESET_ALL)
            data = wait_for_reanalysis(domain)
        else:
            data = None
    else:
        response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
        data = response.json() if response.status_code == 200 else None

    if data:
        stats = data['data']['attributes']['last_analysis_stats']['malicious']
        fortinet_data = extract_fortinet_info(data['data']['attributes']['last_analysis_results'])
        return domain, stats, resolve_ip(domain), *get_domain_creation_date_and_age(domain), fortinet_data
    else:
        return domain, None, "IP Not Resolved", "Creation Date Not Available", "Domain Age Not Available", {}

def extract_fortinet_info(vt_object):
    """Extract Fortinet-related details dynamically."""
    fortinet_data = {}
    if isinstance(vt_object, dict):
        for key, value in vt_object.items():
            if 'fortinet' in key.lower():
                fortinet_data['method'] = value.get('method', 'Not Available')
                fortinet_data['engine_name'] = value.get('engine_name', 'Not Available')
                fortinet_data['category'] = value.get('category', 'Not Available')
                fortinet_data['result'] = value.get('result', 'Not Available')
    return fortinet_data

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.error:
        return "IP Not Resolved"

def get_domain_creation_date_and_age(domain, retries=3):
    """Retrieve domain creation date and calculate its age with retries."""
    if domain in whois_cache:
        return whois_cache[domain]

    for attempt in range(retries):
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date is None:
                raise ValueError("Creation date is None")

            age = (datetime.now() - creation_date).days
            whois_cache[domain] = (creation_date, age)  # Store result
            return creation_date, age
        except Exception as e:
            logging.error(f"WHOIS lookup failed for {domain}, attempt {attempt + 1}: {e}")
            if attempt < retries - 1:
                time.sleep(2)  # Small delay before retrying

    return "Creation Date Not Available", "Domain Age Not Available"

def wait_for_reanalysis(domain):
    """Poll VirusTotal until analysis timestamp changes."""
    headers = {"x-apikey": get_next_api_key()}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    # print(f"Hello in analyis: {domain}")

    # Get initial analysis timestamp
    initial_response = requests.get(url, headers=headers)
    if initial_response.status_code != 200:
        return None
    initial_data = initial_response.json()
    initial_time = initial_data['data']['attributes'].get('last_analysis_date')

    for _ in range(10):
        time.sleep(10)
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            new_time = data['data']['attributes'].get('last_analysis_date')
            if new_time and new_time != initial_time:
                return data
    return None

def run_analysis(reanalyze=False):
    print(Fore.YELLOW + "\nStarting domain analysis...\n" + Style.RESET_ALL)

    input_file = 'Domain_input.xlsx'
    df = pd.read_excel(input_file)
    if 'Domain' not in df.columns:
        print(Fore.RED + "Error: 'Domain' column not found in the Excel file." + Style.RESET_ALL)
        return

    df['Domain'] = df['Domain'].apply(sanitize_domain)  # Ensure all domains are cleaned

    total_domains = len(df)
    results = []
    fortinet_details_list = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_results = {executor.submit(check_domain, domain, reanalyze): domain for domain in df['Domain']}
        for future in future_results:
            domain, score, ip, creation_date, domain_age, fortinet_details = future.result()
            results.append((domain, score, ip, creation_date, domain_age))
            fortinet_details_list.append(fortinet_details)
            print(Fore.CYAN + f"Completed {len(results)}/{total_domains}. {total_domains - len(results)} left." + Style.RESET_ALL)

    df['Domain'], df['Number Vendors Flagged as Malicious(Domain)'], df['IP Address'], df['Domain Creation Date'], df['Domain Age (days)'] = zip(*results)

    # Ensure Fortinet classification columns are dynamically created
    fortinet_columns = ['Fortinet Method', 'Fortinet Engine_Name', 'Fortinet Category', 'Fortinet Result']
    for col in fortinet_columns:
        df[col] = [details.get(col.replace('Fortinet ', '').lower(), "Not Available") for details in fortinet_details_list]

    clean_df = df[df['Number Vendors Flagged as Malicious(Domain)'] == 0]
    suspicious_df = df[(df['Number Vendors Flagged as Malicious(Domain)'] > 0) & (df['Number Vendors Flagged as Malicious(Domain)'] < 5)]
    malicious_df = df[df['Number Vendors Flagged as Malicious(Domain)'] >= 5]

    output_dir = 'Domain_response'
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f'Domain_analysis_{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.xlsx')

    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        clean_df.to_excel(writer, sheet_name='Clean', index=False)
        suspicious_df.to_excel(writer, sheet_name='Suspicious', index=False)
        malicious_df.to_excel(writer, sheet_name='Malicious', index=False)

    print(Fore.GREEN + f"Analysis complete! Results saved to {output_file}" + Style.RESET_ALL)

# --- Main Execution Loop ---
while True:
    print("\nSelect an option:")
    print("1. Analyze domains")
    print("2. Reanalyze domains (Force VirusTotal Reanalysis)")
    print("3. Exit")

    option = input("Enter the option number: ")

    if option == "1":
        run_analysis()
    elif option == "2":
        run_analysis(reanalyze=True)  # Ensures all domains are forcefully reanalyzed
    elif option == "3":
        print(Fore.RED + "Exiting script. Goodbye!" + Style.RESET_ALL)
        break
    else:
        print(Fore.RED + "Invalid option selected. Try again." + Style.RESET_ALL)
