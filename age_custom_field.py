import requests
import csv
import time
import json
import gzip
import io
import os
from collections import defaultdict
import sys
from datetime import datetime
from tqdm import tqdm
import logging
from dateutil import parser
import pytz

# Configuration
token_variable = os.environ.get('API_KEY')
base_url = "https://api.kennasecurity.com"
custom_field_id = 26  # replace with the custom field from your environment
custom_field_id_range = 25  # replace with the custom field for range from your environment
thresh_num = 25000  # Threshold for how many IDs you want to send in each request. Max possible is 30k as per API docs
batch_size = 25000  # Number of vulnerabilities to process in each batch

# Setup logging to a file
logging.basicConfig(filename='script_log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def request_data_export(token_variable):
    url = f"{base_url}/data_exports"
    headers = {
        'X-Risk-Token': token_variable,
        'accept': 'application/json',
        'content-type': 'application/json'
    }
    data = {
        "export_settings": {
            "format": "json",
            "model": "vulnerability",
            "slim": False,
        },
        "status": [
            "open",
            "risk accepted",
            "false positive"
        ]
    }
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 200:
        return response.json()['search_id']
    else:
        logging.error(f"Failed to send POST request. Status Code: {response.status_code}. Response Text: {response.text}")
        return None

def wait_for_data_export(search_id, token_variable, max_wait_time=7200, sleep_time=10):
    start_time = time.time()
    status_url = f"{base_url}/data_exports/status?search_id={search_id}"
    headers = {
        'X-Risk-Token': token_variable,
        'accept': 'application/json'
    }
    while True:
        status_response = requests.get(status_url, headers=headers)
        if status_response.status_code == 200 and status_response.json().get('message') == "Export ready for download":
            url = f"{base_url}/data_exports?search_id={search_id}"
            headers = {
                'X-Risk-Token': token_variable,
                'accept': 'application/gzip'
            }
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                decompressed_file = gzip.GzipFile(fileobj=io.BytesIO(response.content))
                data = json.load(decompressed_file)
                return data
            else:
                logging.error(f"Failed to fetch data. Status Code: {response.status_code}. Response Text: {response.text}")
                return None
        elif time.time() - start_time > max_wait_time:
            logging.error(f"Timed out after waiting for {max_wait_time} seconds.")
            return None
        else:
            logging.info(f"Data export is still in progress. Waiting for {sleep_time} seconds before trying again.")
            print(f"Data export is still in progress. Waiting for {sleep_time} seconds before trying again.")
            time.sleep(sleep_time)

def send_bulk_updates(vulns, custom_field_id, custom_field_id_range, token_variable):
    url = f"{base_url}/vulnerabilities/bulk"
    headers = {
        'X-Risk-Token': token_variable,
        'accept': 'application/json',
        'content-type': 'application/json'
    }
    for vuln in vulns:
        payload = {
            "vulnerability_ids": [vuln['id']],
            "vulnerability": {
                "custom_fields": {
                    str(custom_field_id): vuln['age_value'],
                    str(custom_field_id_range): vuln['range_value']
                }
            }
        }
        response = requests.put(url, headers=headers, json=payload)
        if response.status_code != 200:
            logging.error(f"Failed to send POST request for ID: {vuln['id']}. Response Status Code: {response.status_code}. Response Text: {response.text}")

def calculate_age_in_days(first_found_on):
    try:
        # Parse the first found date
        first_found_date = parser.isoparse(first_found_on)
        logging.info(f"Parsed first found date: {first_found_date}")
        # Get the current date in UTC and make it timezone-aware
        today = datetime.utcnow().replace(tzinfo=pytz.UTC)
        logging.info(f"Current date (UTC): {today}")
        # Calculate the age in days
        age_in_days = (today - first_found_date).days
        logging.info(f"First found date: {first_found_date}, Today: {today}, Age in days: {age_in_days}")
        return age_in_days
    except Exception as e:
        logging.error(f"Error calculating age in days: {e}")
        return None

def determine_range(age_in_days):
    if age_in_days is None:
        return "Unknown"
    if age_in_days <= 30:
        return "<= 30 days"
    elif 30 < age_in_days <= 60:
        return "31 - 60 days"
    elif 60 < age_in_days <= 90:
        return "61 - 90 days"
    elif 90 < age_in_days <= 180:
        return "91 - 180 days"
    else:
        return "> 180 days"

def main():
    search_id = request_data_export(token_variable)
    if not search_id:
        sys.exit(1)

    vulns_data = wait_for_data_export(search_id, token_variable)
    if not vulns_data:
        sys.exit(1)

    # Process vulnerabilities and calculate age in days
    total_vulns = len(vulns_data['vulnerabilities'])
    vulns_to_update = []
    with tqdm(total=total_vulns, desc="Processing vulnerabilities", unit="vuln") as pbar:
        for vuln in vulns_data['vulnerabilities']:
            if 'first_found_on' in vuln:
                age_value = calculate_age_in_days(vuln['first_found_on'])
                range_value = determine_range(age_value)
                vulns_to_update.append({
                    'id': vuln['id'],
                    'age_value': age_value,
                    'range_value': range_value
                })
                if len(vulns_to_update) >= batch_size:
                    send_bulk_updates(vulns_to_update, custom_field_id, custom_field_id_range, token_variable)
                    vulns_to_update = []
                pbar.update(1)
        # Send remaining vulnerabilities
        if vulns_to_update:
            send_bulk_updates(vulns_to_update, custom_field_id, custom_field_id_range, token_variable)

if __name__ == "__main__":
    main()
