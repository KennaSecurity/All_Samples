# Uses VI+ APIs to show vulnerability definitions and malware family and hashes.

import os
import sys
import json
import csv
import requests

def print_json(json_obj):
    print(json.dumps(json_obj, sort_keys=True, indent=2))


def delete_app(base_url, headers, app_id):
    print(f"Deleting application ID: {app_id}")

    app_del_url = base_url + "applications/" + app_id
    response = requests.delete(app_del_url, headers=headers)
    if response.status_code != 200:
        print("Delete Appliacation Error: " + str(response.status_code))
        sys.exit(1)
    resp_json = response.json()
    print_json(resp_json)

if __name__ == "__main__":
    if len(sys.argv) <= 1:
       print(f"{sys.argv[0]} <csv-file> or")
       print(f"{sys.argv[0]} <app-id> [app_id] ...")
       print("If the first argument is a number, it is assumed that the command line ")
       print("arguments are app IDs.")
       sys.exit(1)
   
    # KENNA_API_KEY is an environment variable.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
       print("KENNA_API key is non-existent")
       sys.exit(1)

    # Might have to change this depending on your server.
    base_url = "https://api.kennasecurity.com/"
   
    # HTTP header.
    headers = {'Accept': 'application/json',
              'X-Risk-Token': api_key,
              'User-Agent': 'vendor: Kenna Security; product: sample/delete_app; version: 1.0'}

    if sys.argv[1].isnumeric():
        # Pop off the program name and process app IDs as command line arguments.
        sys.argv.pop(0)
        print("")

        # For each app_id, delete it.
        for app_id in sys.argv:
            delete_app(base_url, headers, app_id)

    else:
        # Proces CSV file
        csv_file_name = sys.argv[1]
        with open(csv_file_name, newline='') as csv_file:
            app_ids_reader = csv.reader(csv_file)

            for row in app_ids_reader:
                for app_id in row:
                    if app_id.isnumeric():
                        app_id = app_id.lstrip()
                        app_id = app_id.rstrip()
                        delete_app(base_url, headers, app_id)

