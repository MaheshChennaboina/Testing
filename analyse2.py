import requests
import pandas as pd
import json
import os
import base64
import time
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from tqdm import tqdm
from colorama import init, Fore
import whois

# Initialize colorama
init()

# Configure logging
logging.basicConfig(filename='ioc_analysis.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Load API keys
with open('api_keys.json') as f:
    config = json.load(f)
api_keys = config['api_keys']

# API key manager
class APIKeyManager:
    def __init__(self, keys):
        self.keys = keys
        self.index = 0

    def get_key(self):
        return self.keys[self.index]

    def rotate_key(self):
        self.index = (self.index + 1) % len(self.keys)
        logging.warning("Rotated API key due to quota.")

api_manager = APIKeyManager(api_keys)

# --- Normalization helpers ---
def normalize_ip(ip):
    ip = ip.replace("[.]", ".")
    parts = ip.split(".")
    parts = [p for p in parts if p.isdigit()]
    if len(parts) >= 4:
        parts = parts[:4]
    candidate = ".".join(parts)
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except:
        return ip

def normalize_domain(domain):
    return domain.replace("[.]", ".").strip()

def normalize_url(url):
    return url.replace("hxxp", "http").replace("[.]", ".").strip()

def normalize_ioc(ioc, ioc_type):
    if ioc_type.lower() == "ip":
        return normalize_ip(ioc)
    elif ioc_type.lower() == "domain":
        return normalize_domain(ioc)
    elif ioc_type.lower() == "url":
        return normalize_url(ioc)
    return ioc

# --- VT helpers ---
def vt_get(endpoint):
    headers = {"x-apikey": api_manager.get_key()}
    response = requests.get(endpoint, headers=headers)
    if response.status_code == 429:
        api_manager.rotate_key()
        headers = {"x-apikey": api_manager.get_key()}
        response = requests.get(endpoint, headers=headers)
    return response

def vt_post(endpoint, data=None):
    headers = {"x-apikey": api_manager.get_key()}
    response = requests.post(endpoint, headers=headers, data=data)
    if response.status_code == 429:
        api_manager.rotate_key()
        headers = {"x-apikey": api_manager.get_key()}
        response = requests.post(endpoint, headers=headers, data=data)
    return response

# Extract Fortinet info
def extract_fortinet(data):
    fortinet = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {}).get("Fortinet", {})
    return (
        fortinet.get("method", "Unknown"),
        fortinet.get("engine_name", "Unknown"),
        fortinet.get("category", "Unknown"),
        fortinet.get("result", "Unknown"),
    )

# --- WHOIS helpers ---
whois_cache = {}

def get_domain_creation_and_age(domain):
    if domain in whois_cache:
        return whois_cache[domain]
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is None:
            creation_date = "Unknown"
            age = "Unknown"
        else:
            age = (datetime.now() - creation_date).days
        whois_cache[domain] = (creation_date, age)
        return creation_date, age
    except Exception as e:
        logging.error(f"WHOIS failed for {domain}: {e}")
        return "Unknown", "Unknown"

# Trigger re-analysis for one IOC
def trigger_reanalysis(ioc_val, ioc_type):
    try:
        if ioc_type == "url":
            encoded = base64.urlsafe_b64encode(ioc_val.encode()).decode().strip("=")
            vt_post(f"https://www.virustotal.com/api/v3/urls/{encoded}/analyse")
        elif ioc_type == "ip":
            vt_post(f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_val}/analyse")
        elif ioc_type == "domain":
            vt_post(f"https://www.virustotal.com/api/v3/domains/{ioc_val}/analyse")
    except Exception as e:
        logging.error(f"Failed to trigger re-analysis for {ioc_val}: {e}")

# Process one IOC
def process_ioc(row):
    date = row["Date"]
    actor = row["Threat Actor"]
    ioc_val = normalize_ioc(row["IOC Value"], row["IOC Type"])
    ioc_type = row["IOC Type"].lower()

    result = {
        "Date": date,
        "Threat Actor": actor,
        "IOC Value": ioc_val,
        "Malicious Score": "Unknown",
        "ASN": "",
        "ASN Owner": "",
        "Country": "",
        "Resolved IP": "",
        "Fortinet Method": "",
        "Fortinet Engine Name": "",
        "Fortinet Category": "",
        "Fortinet Result": "",
        "Domain Creation Date": "",
        "Domain Age (days)": "",
    }

    try:
        # Endpoint selection
        if ioc_type == "ip":
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_val}"
        elif ioc_type == "domain":
            endpoint = f"https://www.virustotal.com/api/v3/domains/{ioc_val}"
        elif ioc_type == "url":
            encoded = base64.urlsafe_b64encode(ioc_val.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{encoded}"
        else:
            logging.error(f"Unknown IOC type: {ioc_type}")
            return result

        # Fetch analysis
        response = vt_get(endpoint)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            result["Malicious Score"] = stats.get("malicious", 0)

            # IP/Domain info
            if ioc_type in ["ip", "domain"]:
                result["ASN"] = data["data"]["attributes"].get("asn", "")
                result["ASN Owner"] = data["data"]["attributes"].get("as_owner", "")
                result["Country"] = data["data"]["attributes"].get("country", "")

            # Resolved IPs for domains
            if ioc_type == "domain":
                res = data["data"]["attributes"].get("last_dns_records", [])
                if res:
                    ips = [r.get("value", "") for r in res if r.get("type") == "A"]
                    result["Resolved IP"] = ", ".join(ips)
                creation_date, age = get_domain_creation_and_age(ioc_val)
                result["Domain Creation Date"] = creation_date
                result["Domain Age (days)"] = age

            # URL special case
            if ioc_type == "url":
                result["Resolved IP"] = data["data"]["attributes"].get("last_final_url", "")

            # Fortinet fields
            fort_m, fort_eng, fort_cat, fort_res = extract_fortinet(data)
            result["Fortinet Method"] = fort_m
            result["Fortinet Engine Name"] = fort_eng
            result["Fortinet Category"] = fort_cat
            result["Fortinet Result"] = fort_res

        else:
            logging.error(f"Error fetching IOC {ioc_val}: {response.status_code} {response.content}")

    except Exception as e:
        logging.error(f"Exception processing {ioc_val}: {e}")

    return result

# --- Main ---
if __name__ == "__main__":
    input_file = "IOC_input.xlsx"
    df = pd.read_excel(input_file)
    df.columns = df.columns.str.strip()
    df = df[["Date", "Threat Actor", "IOC Value", "IOC Type"]].dropna()

    # Ask user in terminal
    mode_choice = input("Choose mode: (1) Analyse  (2) Re-analyse → ").strip()
    mode = "analyse" if mode_choice == "1" else "reanalyse"

    print(Fore.CYAN + f"Processing {len(df)} IOCs in {mode.upper()} mode..." + Fore.RESET)

    # Trigger re-analysis if chosen
    if mode == "reanalyse":
        print(Fore.YELLOW + "Triggering re-analysis for all IOCs..." + Fore.RESET)
        with ThreadPoolExecutor(max_workers=5) as executor:
            list(tqdm(executor.map(lambda r: trigger_reanalysis(normalize_ioc(r["IOC Value"], r["IOC Type"]), r["IOC Type"].lower()), df.to_dict("records")),
                      total=len(df), desc="Re-analysis"))

        # Wait 60 seconds for VirusTotal to update
        print(Fore.YELLOW + "Waiting 60 seconds for VirusTotal to process re-analyses..." + Fore.RESET)
        time.sleep(60)

    # Process IOCs
    results = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        for res in tqdm(executor.map(process_ioc, df.to_dict("records")),
                        total=len(df), desc="Analysing IOCs"):
            results.append(res)

    df_results = pd.DataFrame(results)

    # Categorize into Clean / Suspicious / Malicious sheets
    clean_df = df_results[df_results["Malicious Score"] == 0]
    suspicious_df = df_results[(df_results["Malicious Score"] > 0) & (df_results["Malicious Score"] < 5)]
    malicious_df = df_results[df_results["Malicious Score"] >= 5]

    # Save output
    output_folder = "IOC_analysis_results"
    os.makedirs(output_folder, exist_ok=True)
    output_file = f"{output_folder}/IOC_analysis_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.xlsx"

    with pd.ExcelWriter(output_file, engine="openpyxl") as writer:
        clean_df.to_excel(writer, sheet_name="Clean", index=False)
        suspicious_df.to_excel(writer, sheet_name="Suspicious", index=False)
        malicious_df.to_excel(writer, sheet_name="Malicious", index=False)

    print(Fore.GREEN + f"Results saved to {output_file}" + Fore.RESET)
