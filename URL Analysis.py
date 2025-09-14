import requests
import pandas as pd
import json
import os
import base64
import time
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from tqdm import tqdm
from openpyxl import load_workbook
from openpyxl.styles import Alignment
from colorama import init, Fore, Style

# Initialize colorama
init()

# Configure logging
logging.basicConfig(filename='url_analysis.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load API keys from api_keys.json
with open('api_keys.json') as config_file:
    config = json.load(config_file)
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
        logging.warning("Rotating API key due to rate limit.")

api_manager = APIKeyManager(api_keys)

# Convert URL format
def convert_url(url):
    return url.replace('hxxp', 'http').replace('[.]', '.')

# Extract Fortinet classification attributes
def extract_fortinet_data(analysis_data):
    fortinet_data = analysis_data.get('data', {}).get('attributes', {}).get('last_analysis_results', {}).get('Fortinet', {})
    return {
        "Fortinet_Method": fortinet_data.get("method", "Unknown"),
        "Fortinet_Engine_Name": fortinet_data.get("engine_name", "Unknown"),
        "Fortinet_Category": fortinet_data.get("category", "Unknown"),
        "Fortinet_Result": fortinet_data.get("result", "Unknown")
    }

# Request URL re-analysis
def request_reanalysis(url):
    headers = {"x-apikey": api_manager.get_key()}
    encoded_url = base64.urlsafe_b64encode(convert_url(url).encode()).decode().strip('=')
    response = requests.post(f"https://www.virustotal.com/api/v3/urls/{encoded_url}/analyse", headers=headers)

    if response.status_code == 200:
        logging.info(f"Requested re-analysis for: {url}")
        return url  # Returning URL for later data fetching
    else:
        logging.error(f"Error requesting re-analysis: {url}. Response: {response.content}")
        return None

# Fetch updated VirusTotal analysis results
def get_latest_analysis(row):
    url = row['URL']
    headers = {"x-apikey": api_manager.get_key()}
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{encoded_url}", headers=headers)

    if response.status_code == 200:
        data = response.json()
        fortinet_data = data['data']['attributes']['last_analysis_results'].get('Fortinet', {})
        return {
            "Date": row['Date'],
            "Threat_Actor": row['Threat Actor'],
            "URL": url,
            "Malicious_Score": data['data']['attributes']['last_analysis_stats']['malicious'],
            "Fortinet_Method": fortinet_data.get("method", "Unknown"),
            "Fortinet_Engine_Name": fortinet_data.get("engine_name", "Unknown"),
            "Fortinet_Category": fortinet_data.get("category", "Unknown"),
            "Fortinet_Result": fortinet_data.get("result", "Unknown"),
        }
    else:
        logging.error(f"Error retrieving updated analysis for {url}. Response: {response.content}")
        return {
            "Date": row['Date'],
            "Threat_Actor": row['Threat Actor'],
            "URL": url,
            "Malicious_Score": "Unknown",
            "Fortinet_Method": "Unknown",
            "Fortinet_Engine_Name": "Unknown",
            "Fortinet_Category": "Unknown",
            "Fortinet_Result": "Unknown",
        }

# Process URLs: first trigger reanalysis, sleep, then fetch updated results
def process_urls(df):
    logging.info("Triggering reanalysis for all URLs...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        reanalysis_urls = list(tqdm(executor.map(request_reanalysis, df['URL'].tolist()), total=len(df), desc="Requesting Reanalysis"))

    valid_urls = [url for url in reanalysis_urls if url]

    logging.info("Sleeping for 60 seconds to allow VirusTotal updates...")
    time.sleep(60)

    logging.info("Fetching updated results...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        results = list(tqdm(executor.map(get_latest_analysis, df.to_dict('records')), total=len(df), desc="Fetching Updated Data"))

    return results

# Load input Excel file
df = pd.read_excel('URL_input.xlsx')

# Ensure column names match exactly and remove extra spaces
df.columns = df.columns.str.strip()

# Extract relevant columns, handling missing values
df = df[['Date', 'Threat Actor', 'URL']].dropna()

# Process URLs and retrieve results
analysis_results = process_urls(df)

# Categorize URLs based on Malicious Score
df_results = pd.DataFrame(analysis_results)

clean_df = df_results[df_results['Malicious_Score'] == 0]
suspicious_df = df_results[(df_results['Malicious_Score'] > 0) & (df_results['Malicious_Score'] < 5)]
malicious_df = df_results[df_results['Malicious_Score'] >= 5]

# Ensure output directory exists
output_folder = "URL_analysis_results"
os.makedirs(output_folder, exist_ok=True)

output_file = f"{output_folder}/URL_analysis_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.xlsx"

# Save categorized results into Excel sheets with required columns
try:
    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        clean_df.to_excel(writer, sheet_name='Clean', index=False)
        suspicious_df.to_excel(writer, sheet_name='Suspicious', index=False)
        malicious_df.to_excel(writer, sheet_name='Malicious', index=False)

    logging.info(f"Results saved to {output_file}")
    print(f"Results saved to {output_file}")
except Exception as e:
    logging.error(f"Error saving file: {e}")
    print(f"Error saving file: {e}")
