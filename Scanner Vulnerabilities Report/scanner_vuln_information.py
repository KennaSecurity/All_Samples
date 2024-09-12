import csv
import time
import gzip
import io
import json
import sys
import os
import requests
from datetime import datetime

# Ensure the KENNA_API_KEY environment variable is set
token_variable = os.environ.get('KENNA_API_KEY')
if not token_variable:
    print("Error: KENNA_API_KEY environment variable is not set.")
    sys.exit(1)

base_url = "https://api.kennasecurity.com"

# Get the current date
today = datetime.today().strftime("%Y-%m-%d")

# Generate the CSV file name with the date
csv_file_name = f"output_vulns_{today}.csv"

def request_data_export(token_variable, model, ids=None):
    """Request a data export from the Kenna Security API."""
    url = f"{base_url}/data_exports"
    headers = {
        'X-Risk-Token': token_variable,
        'accept': 'application/json',
        'content-type': 'application/json'
    }
    data = {
        "export_settings": {
            "format": "jsonl",
            "model": model,
            "slim": False
        }
    }
    if model == "vulnerability":
        data["export_settings"]["fields"] = [
            "details",
            "scanner_vulnerabilities",
            "connectors",
            "cve_id",
            "asset_id"
        ]
        data["status"] = [
            "open",
            "risk accepted",
            "false positive"
        ]
    if ids:
        data["id"] = ids
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 200:
        return response.json()['search_id']
    else:
        print(f"Failed to send POST request. Status Code: {response.status_code}. Response Text: {response.text}")
        return None

def wait_for_data_export(search_id, token_variable, model, max_wait_time=12000, sleep_time=90):
    """Wait for the data export to be ready and download it."""
    start_time = time.time()
    status_url = f"{base_url}/data_exports/status?search_id={search_id}"
    headers = {
        'X-Risk-Token': token_variable,
        'accept': 'application/json'
    }
    while True:
        status_response = requests.get(status_url, headers=headers)
        if status_response.status_code == 200 and status_response.json().get('message') == "Export ready for download":
            print(f"{model.capitalize()} export is ready for download")
            url = f"{base_url}/data_exports?search_id={search_id}"
            headers = {
                'X-Risk-Token': token_variable,
                'accept': 'application/gzip'
            }
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                decompressed_file = gzip.GzipFile(fileobj=io.BytesIO(response.content))
                return decompressed_file
            else:
                print(f"Failed to fetch {model} data. Status Code: {response.status_code}. Response Text: {response.text}")
                return None
        elif time.time() - start_time > max_wait_time:
            print(f"Timed out after waiting for {max_wait_time} seconds.")
            return None
        else:
            print(f"{model.capitalize()} export is still in progress. Waiting for {sleep_time} seconds before trying again.")
            time.sleep(sleep_time)

# Request vulnerability data export and get the search_id
vuln_search_id = request_data_export(token_variable, "vulnerability")

if vuln_search_id is None:
    print("Failed to request vulnerability data export.")
    sys.exit(1)

# Use the search_id to get the vulnerability data export
vuln_data = wait_for_data_export(vuln_search_id, token_variable, "vulnerability")

if not vuln_data:
    print("Failed to fetch vulnerability data export.")
    sys.exit(1)

# Process vulnerability data and request asset data exports
vuln_list = []
asset_ids = set()
for line in vuln_data:
    vulnerability = json.loads(line)
    vulnerability_id = vulnerability['id']
    details = vulnerability.get('details', [])
    connectors = vulnerability.get('connectors', [])
    cve = vulnerability.get('cve_id', "")
    a_id = vulnerability['asset_id']
    details_connector_name = details[0]['connector_name'] if len(details) > 0 else ''
    details_value = details[0]['value'] if len(details) > 0 else ''
    if len(connectors) > len(details) and len(details) > 0:
        vuln_list.append({
            'vulnerability_id': vulnerability_id,
            'details_connector_name': details_connector_name,
            'details_value': details_value,
            'cve': cve,
            'asset_id': a_id
        })
        asset_ids.add(a_id)

# Request asset data export for each asset_id
asset_data = {}
for a_id in asset_ids:
    asset_search_id = request_data_export(token_variable, "asset", [a_id])
    if asset_search_id:
        asset_export = wait_for_data_export(asset_search_id, token_variable, "asset")
        if asset_export:
            for line in asset_export:
                asset = json.loads(line)
                asset_data[a_id] = {
                    'ip_address': asset.get('ip_address', ''),
                    'hostname': asset.get('hostname', ''),
                    'fqdn': asset.get('fqdn', ''),
                    'asset_groups': [group['name'] for group in asset.get('asset_groups', [])]
                }

# Generate the final CSV file with combined data
with open(csv_file_name, mode='w', newline='') as outFile:
    writer = csv.writer(outFile)
    writer.writerow(['Vulnerability ID', 'Details Connector Name', 'Details Value', 'CVE', 'Asset ID', 'IP Address', 'Hostname', 'FQDN', 'Risk Meters'])
    for vuln in vuln_list:
        a_id = vuln['asset_id']
        asset_info = asset_data.get(a_id, {})
        writer.writerow([
            vuln['vulnerability_id'],
            vuln['details_connector_name'],
            vuln['details_value'],
            vuln['cve'],
            vuln['asset_id'],
            asset_info.get('ip_address', ''),
            asset_info.get('hostname', ''),
            asset_info.get('fqdn', ''),
            ', '.join(asset_info.get('asset_groups', []))
        ])

print(f"CSV file '{csv_file_name}' has been generated.")
