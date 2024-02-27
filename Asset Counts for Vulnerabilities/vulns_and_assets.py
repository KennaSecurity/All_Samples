import os
import requests
import json
import io
import gzip
import select
import sys
import time 
import pandas as pd

# Check if the API_KEY environment variable is set
API_KEY = os.environ.get('API_KEY')
if not API_KEY:
    print("API_KEY environment variable is not set.")
    exit(1)

# Base URL for the API
base_url = "https://api.kennasecurity.com/data_exports"

# Headers for the API
headers = {
    'X-Risk-Token': API_KEY,
    'accept': 'application/json',
    'content-type': 'application/json'
}

# Function to get user input with a timeout
def timed_input(prompt, timeout=90):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    ready, _, _ = select.select([sys.stdin], [],[], timeout)
    if ready:
        return sys.stdin.readline().rstrip('\n')  # Expecting the user to press enter
    else:
        print("\nNo input received within the time limit.")
        return None    

# Prompt the user for input with a specified timeout (e.g., 90 seconds by default)
input_choice = timed_input("Enter '1' to use Risk Meter ID or '2' to use CVE List: ", 90)

if input_choice is None:
    print("No input received. Exiting the script.")
    exit(1)

data_to_send = {
    "export_settings": {
        "format": "jsonl",
        "model": "vulnerability",
        "slim": False,
        "fields": [
            "id",
            "urls",
            "cve_id",
            "cve_description",
            "risk_meter_score"
        ]
    }
}

if input_choice == "1":
    search_id = input("Enter the Risk Meter ID: ")
    data_to_send["search_id"] = int(search_id)
elif input_choice == "2":
    query = input("Enter CVEs in a comma separated format (if more than one): ").strip()
    cve_list = [cve.strip() for cve in query.split(',')] # Strip spaces and split by comma
    if len(cve_list) == 1:
        # If there is only one CVE, format it without the "CVE-" prefix
        data_to_send["q"] = "cve:" + cve_list[0].replace("CVE-", "")
    else:
        # If there are multiple CVEs, create a query string with "OR" between CVE numbers
        formatted_cves = [cve.replace("CVE-", "") for cve in cve_list]  # Remove "CVE-" prefix
        data_to_send["q"] = "cve:(" + " OR ".join(formatted_cves) + ")"
else:
    print("Invalid input. Please enter '1' or '2'.")
    exit(1)

# Send the API request to initiate data export
response = requests.post(base_url, headers=headers, data=json.dumps(data_to_send))

if response.status_code == 200:
    print("Data export initiated...")
    export_data = response.json()
    export_search_id = export_data.get("search_id")
    status_url = f"{base_url}/status?search_id={export_search_id}"

    while True:
        status_response = requests.get(status_url, headers=headers)
        status_data = status_response.json()

        if status_data.get("message") == "Export ready for download":
            print("Export is ready for download! Retrieving the export...")

            download_headers = {
                'X-Risk-Token': API_KEY,
                'accept': 'application/gzip'
            }
            download_url = f"{base_url}?search_id={export_search_id}"
            download_response = requests.get(download_url, headers=download_headers, stream=True)

            if download_response.status_code == 200:
                # Process the gzip content directly in memory
                compressed_file = io.BytesIO(download_response.content)
                decompressed_file = gzip.GzipFile(fileobj=compressed_file)

                jsonl_content = decompressed_file.readlines()
                data = [json.loads(line) for line in jsonl_content]
                df_contents = pd.DataFrame(data)

                # Rename columns on final file
                df_contents.rename(
                    columns={
                        "id": "vulnerability_id",
                        "urls": "asset_url",
                        "risk_meter_score": "vulnerability_score"
                    },
                    inplace=True 
                )


                df_contents_exploded = df_contents.explode('asset_url')
                df_cve_url_count = df_contents_exploded.groupby('cve_id')['asset_url'].agg('count').reset_index()

                # Group by 'cve_id' and aggregate both 'urls' and 'risk_meter_score'
                df_cve_url_count = df_contents_exploded.groupby('cve_id').agg(
                asset_count=('asset_url', 'count'),
                vulnerability_score=('vulnerability_score', 'first')
                ).reset_index()

                # Sort the DataFrame by 'url_count' in descending order
                df_cve_url_count_sorted = df_cve_url_count.sort_values(by='asset_count', ascending=False)

                excel_file_path = f"vulns_with_counts.xlsx"
                with pd.ExcelWriter(excel_file_path) as writer:
                    df_contents.to_excel(writer, index=False, sheet_name='Full List')
                    df_cve_url_count_sorted.to_excel(writer, index=False, sheet_name='Vulnerabilities Assets Count')

                print(f"Data successfully written to {excel_file_path} with two sheets")
                break
            else:
                print("Failed to download the export.")
                print("Status Code:", download_response.status_code)
                print("Response from the server:")
                print(download_response.text)
                break
        else:
            print("Export is not ready yet. Checking again in 90 seconds...")
            time.sleep(90)
else:
    print("Failed to initiate data export.")
    print("Status Code:", response.status_code)
    print("Response from the server:")
    print(response.text)