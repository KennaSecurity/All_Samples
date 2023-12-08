import csv
import time
import gzip
import io
import json
import sys
import os
import requests
from datetime import datetime

token_variable = os.environ.get('KENNA_API_KEY')
base_url = "https://api.kennasecurity.com"

# Get the current date
today = datetime.today().strftime("%Y-%m-%d")

# Generate the CSV file name with the date
csv_file_name = f"output_vulns_{today}.csv"

def request_data_export(token_variable):
    url = f"{base_url}/data_exports"
    headers = {
        'X-Risk-Token': token_variable,
        'accept': 'application/json',
        'content-type': 'application/json'
    }
    data = {
        "export_settings": {
            "format": "jsonl",  # Set to jsonl
            "model": "vulnerability",
            "slim": False,
            "fields": [
                "details",
                "scanner_vulnerabilities",
                "connectors",
                "cve_id"
            ]
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
        print(f"Failed to send POST request. Status Code: {response.status_code}. Response Text: {response.text}")
        return None

def wait_for_data_export(search_id, token_variable, max_wait_time=5400, sleep_time=90):
    start_time = time.time()
    status_url = f"{base_url}/data_exports/status?search_id={search_id}"
    headers = {
        'X-Risk-Token': token_variable,
        'accept': 'application/json'
    }
    while True:
        status_response = requests.get(status_url, headers=headers)
        print("Status response: ", status_response.json())  # Print the status response
        if status_response.status_code == 200 and status_response.json().get('message') == "Export ready for download":
            print("Export is ready for download")  # Debug print
            url = f"{base_url}/data_exports?search_id={search_id}"
            headers = {
                'X-Risk-Token': token_variable,
                'accept': 'application/gzip'
            }
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                decompressed_file = gzip.GzipFile(fileobj=io.BytesIO(response.content))
                with open(csv_file_name, mode='w', newline='') as outFile:
                    writer = csv.writer(outFile)
                    writer.writerow(['Vulnerability ID', 'Details Connector Name', 'Details Value', 'CVE'])
                    count = 0
                    for line in decompressed_file:
                        vulnerability = json.loads(line)
                        vulnerability_id = vulnerability['id']
                        details = vulnerability.get('details', [])
                        connectors = vulnerability.get('connectors', [])
                        cve = vulnerability.get('cve_id', "")
                        details_connector_name = details[0]['connector_name'] if len(details) > 0 else ''
                        details_value = details[0]['value'] if len(details) > 0 else ''
                        if len(connectors) > len(details) and len(details) > 0:
                            count += 1
                            writer.writerow([vulnerability_id, details_connector_name, details_value, cve])
                            if count % 100 == 0:
                                print("Count is", count)
                return True
            else:
                print(f"Failed to fetch data. Status Code: {response.status_code}. Response Text: {response.text}")
                return None
        elif time.time() - start_time > max_wait_time:
            print(f"Timed out after waiting for {max_wait_time} seconds.")
            return None
        else:
            print(f"Data export is still in progress. Waiting for {sleep_time} seconds before trying again.")
            time.sleep(sleep_time)

# Request data export and get the search_id
search_id = request_data_export(token_variable)

if search_id is None:
    print("Failed to request data export.")
    sys.exit(1)

# Use the search_id to get the data export
export_success = wait_for_data_export(search_id, token_variable)

if not export_success:
    print("Failed to fetch data export.")
    sys.exit(1)

print(f"CSV file '{csv_file_name}' has been generated.")