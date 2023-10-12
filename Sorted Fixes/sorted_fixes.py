import requests
import pandas as pd
import json
import sys
import os
import datetime
    
#adjust base_url value if your account is on a different platform
base_url = "https://api.kennasecurity.com"
fixes_url = base_url + "/fixes"
api_key = os.getenv("kenna_api_key")

if api_key is None:
    print("Environment variable KENNA_API_KEY is non-existent")
    sys.exit(1)

headers = {"Accept": "application/json", "X-Risk-Token":api_key, "User-Agent": 'sorted_fixes/1.0.0 (Kenna Security)'}

sorted_fixes = pd.DataFrame()

try:
    first_page = requests.get(fixes_url, headers=headers)
    first_page.raise_for_status()
except requests.exceptions.HTTPError as err:
    print(err)
    sys.exit(1)

first_page = first_page.json()

total_count = first_page['meta']['total_count']
total_count = int(total_count)
page = 1
pages = int(first_page['meta']['pages'])

print(f'{total_count} fixes found over {pages} pages.')

while page <= pages:
    fixes_loop_url = fixes_url + "?page=" + str(page)

    try:
        response = requests.get(fixes_loop_url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(err)
        sys.exit(1)

    response = response.json()

    print(f'Grabbing page #{page}...')
    fix_group = response['fixes']

    for fix in fix_group:
        fix_id = fix['id']
        title = fix['title']
        asset_count = fix['asset_count']
        vuln_count = fix['vuln_count']
        max_vuln_score = fix['max_vuln_score']
        total_risk = vuln_count * max_vuln_score
        fix_data = [fix_id, title, asset_count, vuln_count, max_vuln_score, total_risk]
        fd_df = pd.DataFrame([fix_data], columns = ['fix_id', 'title', 'asset_count', 'vuln_count', 'max_vuln_score', 'total_risk'])
        sorted_fixes = pd.concat([sorted_fixes, fd_df], ignore_index = True)

    page += 1

sorted_fixes.rename(columns={'fix_id' : 'Fix ID', 'title' : 'Title', 'asset_count' : 'Asset Count', 'vuln_count' : 'Vuln Count', 'max_vuln_score' : 'Max Vuln Score', 'total_risk' : 'Total Risk'}, inplace = True)

sorted_fixes = sorted_fixes.sort_values(by = 'Total Risk', ascending=False)

sorted_fixes.to_csv('sorted_fixes.csv')

print(f"Sorted fixes were output to the file sorted_fixed.csv")
