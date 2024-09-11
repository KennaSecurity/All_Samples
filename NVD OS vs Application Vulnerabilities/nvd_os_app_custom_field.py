import requests
import csv
import time
import json
import gzip
import io
import os
from collections import defaultdict
import sys
import argparse

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Process CVE data and update vulnerabilities.')
parser.add_argument('--multi', action='store_true', help='Enable "multi" option for multiple product types')
parser.add_argument('--preference', choices=['a', 'o'], help='Preference for Application (a) or OS (o) when both are present')
args = parser.parse_args()

token_variable = os.environ.get('KENNA_API_KEY')
base_url = "https://api.kennasecurity.com"

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
        "fields": [
          "cve_id"
        ]
      },
      "status": [
        "open",
        "risk accepted",
        "false positive"
      ],
      "custom_fields:Vuln Type": ["none"]
    }
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 200:
        return response.json()['search_id']
    else:
        print(f"Failed to send POST request. Status Code: {response.status_code}. Response Text: {response.text}")
        return None

def wait_for_data_export(search_id, token_variable, max_wait_time=1200, sleep_time=10):
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
                print(f"Failed to fetch data. Status Code: {response.status_code}. Response Text: {response.text}")
                return None
        elif time.time() - start_time > max_wait_time:
            print(f"Timed out after waiting for {max_wait_time} seconds.")
            return None
        else:
            print(f"Data export is still in progress. Waiting for {sleep_time} seconds before trying again.")
            time.sleep(sleep_time)
    
custom_field_id = 39 # replace with the custom field from your environment

def send_bulk_updates(ids, app_or_os, custom_field_id, token_variable):
    url = f"{base_url}/vulnerabilities/bulk"
    headers = {
        'X-Risk-Token': token_variable,
        'accept': 'application/json',
        'content-type': 'application/json'
    }
    payload = {
        "vulnerability": {
            "custom_fields": {
                str(custom_field_id): app_or_os
            }
        },
        "vulnerability_ids": ids
    }
    response = requests.put(url, headers=headers, json=payload)
    if response.status_code == 200:
        print(f"POST request successfully for IDs: {ids}")
    else:
        print(f"Failed to send POST request for IDs: {ids}. Response Status Code: {response.status_code}. Response Text: {response.text}")

# Request data export and get the search_id
search_id = request_data_export(token_variable)

if search_id:
    # Use the search_id to get the data export
    vulns_data = wait_for_data_export(search_id, token_variable)
    if vulns_data is None:
        print("Failed to fetch data export.")
        sys.exit(1)

if vulns_data:
    vulns_cves = set(vuln['cve_id'] for vuln in vulns_data['vulnerabilities'] if vuln['cve_id'].startswith('CVE-'))

# Initialize a dictionary to count the number of CVEs for each type
type_counts = {'Application': 0, 'OS': 0, 'Hardware': 0, 'Network': 0}

# Initialize a dictionary to count the number of unique IDs for each type
id_counts = defaultdict(set)

# Create a dictionary where each CVE ID maps to a list of IDs
vulns_id = defaultdict(list)
for vuln in vulns_data['vulnerabilities']:
    if isinstance(vuln, dict) and isinstance(vuln.get('cve_id'), str) and vuln['cve_id'].startswith('CVE-'):
        vulns_id[vuln['cve_id']].append(vuln['id'])

# Map of product types
product_type_map = {'a': 'Application', 'o': 'OS', 'h': 'Hardware', 'n': 'Network'}

url = 'https://services.nvd.nist.gov/rest/json/cves/2.0/'
parameters = {'resultsPerPage': 2000, 'startIndex': 0}

# Get the start time
start_time = time.time()

# Create an empty dictionary to hold CVE data
cve_data = {}
fetch_failed = False  # Initialize fetch_failed

while  True:
    response = requests.get(url, params=parameters)

    if response.status_code == 200:
        data = response.json()

        for cve in data['vulnerabilities']:
            cve_id = cve['cve']['id']
            # Check if CVE is in both NVD_API code and export_vulns_cve.json file
            if cve_id in vulns_cves:
                # Check if 'configurations' field is present
                if 'configurations' in cve['cve']:
                    types = []  # Create a list to hold the product types
                    for config in cve['cve']['configurations']:
                        for node in config['nodes']:
                            if 'cpeMatch' in node:
                                for match in node['cpeMatch']:
                                    product_type = product_type_map.get(match['criteria'].split(':')[2], '')
                                    if product_type and product_type not in types:
                                        types.append(product_type)

                    # Apply the rules for selecting the product type
                    if args.multi and len(types) > 1:
                        types = [f"multi ({', '.join(sorted(types))})"]
                    else:
                        if 'Application' in types and 'OS' in types:
                            if args.preference == 'a':
                                types = ['Application']
                            elif args.preference == 'o':
                                types = ['OS']
                        elif 'Application' in types:
                            types = ['Application']
                        elif 'OS' in types:
                            types = ['OS']
                        elif 'Hardware' in types:
                            types = ['Hardware']
                        elif 'Network' in types:
                            types = ['Network']
                        elif 'OS' in types and 'Hardware' in types:
                            types = ['OS']
                        elif 'OS' in types and 'Network' in types:
                            types = ['OS']
                        elif 'Application' in types and 'Network' in types:
                            types = ['Application']
                        elif 'Application' in types and 'Hardware' in types:
                            types = ['Application']
                        elif 'Hardware' in types and 'Network' in types:
                            types = []

                    # Initialize the dictionary for this cve_id if it doesn't exist
                    if cve_id not in cve_data:
                        cve_data[cve_id] = {'CVE ID': cve_id, 'Type': [], 'id': set()}
                    # Add the type and id to the dictionary for this cve_id
                    cve_data[cve_id]['Type'].extend(types)
                    cve_data[cve_id]['id'].update(vulns_id[cve_id])
    else:
        print('Failed to fetch data from API')
        print('Status code:', response.status_code)
        print('Response text:', response.text)
        fetch_failed = True  # Set fetch_failed to True if response status is not 200
            
    if parameters['startIndex'] + parameters['resultsPerPage'] < data['totalResults']:
        parameters['startIndex'] += parameters['resultsPerPage']
        # Print out progress update
        progress = (parameters['startIndex'] / data['totalResults']) * 100
        print(f'Progress: {round(progress, 1)}%')
    else:
        break

    # Add a delay between each request
    time.sleep(6)

if fetch_failed:
    print('Exiting due to API fetch failure')

# Open the CSV file
with open('output_nvd_cve_vuln_ids.csv', 'w', newline='') as csvfile:
    fieldnames = ['CVE ID', 'Type', 'id']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    # Write the data to the CSV
    for cve_id in cve_data:
        writer.writerow({
            'CVE ID': cve_id, 
            'Type': ', '.join(cve_data[cve_id]['Type']), 
            'id': ', '.join(map(str, cve_data[cve_id]['id']))
        })
        # Increment the count for each type in this row
        for product_type in cve_data[cve_id]['Type']:
            if product_type not in type_counts:
                type_counts[product_type] = 0
            type_counts[product_type] += 1
            id_counts[product_type].update(cve_data[cve_id]['id'])

# Calculate and print the time taken
end_time = time.time()
time_taken = end_time - start_time
hours, remainder = divmod(time_taken, 3600)
minutes, seconds = divmod(remainder, 60)
print(f'Time taken: {int(hours)} hours, {int(minutes)} minutes, {round(seconds, 1)} seconds')

# Print the number of CVEs and IDs for each type
for type_name in type_counts.keys():
     print(f'{type_name}: {type_counts[type_name]} CVEs, {len(id_counts[type_name])} IDs')

# Create sets for app, os, hardware, and multi types
app_set = set()
os_set = set()
hardware_set = set()
network_set = set()
multi_sets = defaultdict(set)

# Go through the cve_data and add IDs to the appropriate sets
for cve_id in cve_data:
    for type_name in cve_data[cve_id]['Type']:
        if type_name == 'Application':
            app_set.update(cve_data[cve_id]['id'])
        elif type_name == 'OS':
            os_set.update(cve_data[cve_id]['id'])
        elif type_name == 'Hardware':
            hardware_set.update(cve_data[cve_id]['id'])
        elif type_name ==  'Network':
            network_set.update(cve_data[cve_id]['id'])
        else:
            multi_sets[type_name].update(cve_data[cve_id]['id'])

# Set your threshold number for grouping IDs
thresh_num = 25000       # Threshold for how many IDs you want to send in each request. Max possible is 30k as per API docs

# The sets with the IDs
sets = {'application': list(app_set), 'os': list(os_set), 'hardware': list(hardware_set), 'network': list(network_set)}

# Add multi sets if the flag is enabled
if args.multi:
    for multi_type, ids in multi_sets.items():
        sets[multi_type] = list(ids)

for set_type, ids in sets.items():
    print(f"Processing {set_type} with {len(ids)} IDs")  # Debugging line
    while len(ids) > 0:
        batch = ids[:thresh_num]
        custom_field_value = set_type
        send_bulk_updates(batch, custom_field_value, custom_field_id, token_variable)
        time.sleep(0.2)  # Add a delay of 0.2 seconds between each request
        ids = ids[thresh_num:]
