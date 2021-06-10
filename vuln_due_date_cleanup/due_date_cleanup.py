import requests
import pandas as pd 
import json
import gzip
import time
import re
import sys
from tqdm.auto import tqdm
from datetime import datetime, timedelta

# Base URL of API Endpoint. You might have to modify this depending on your base URL.
base_url = "https://api.kennasecurity.com/" # US AWS
# base_url = "https://api.us.kennasecurity.com/" # US GCP
# base_url = "https://api.ca.kennasecurity.com/" # Canada
# base_url = "https://api.eu.kennasecurity.com/" # Europe

# Checking the information provided during the script call
if len(sys.argv) <= 3:
        print("==========================================================================================================")
        print("You are missing at least one parameter on your scrip call. Your script call should be like the following:")
        print(f"{sys.argv[0]} <risk_token/API_key> <risk_meter_id> <number_of_days>")
        print("==========================================================================================================")
        sys.exit(1)
elif len(sys.argv[1]) < 64:
    print("==========================================================================================================")
    print("Provided API Key (Risk_Token) is missing characters. Provided one has", len(sys.argv[1]), "as a normal one has 64. Missing", 64 - len(sys.argv[1]),"characters.")
    print("==========================================================================================================")
    sys.exit(1)
elif int(sys.argv[3]) > 7:
    print("==========================================================================================================")
    print("Number of days to look back can't be more than 7 days. You chose ", sys.argv[3])
    print("==========================================================================================================")
    sys.exit(1)

RiskToken = sys.argv[1]
RiskMeter = sys.argv[2]

# Created to validate if the vuln score changed during the last 24 hours or more (you can custom it)
num_days = int(sys.argv[3])
start_time = datetime.today()
yesterday_datetime = (datetime.today() - timedelta(num_days)).strftime('%Y-%m-%d %H:%M:%S+00:00')

# Used to bulk update the CVE's due dates
base_uri3 = 'vulnerabilities/bulk'
url3 = ''.join([base_url, base_uri3])

# Map of the CVE_IDs for a specific CVE_Name
cve_id = {}

# Parameters created to validate if there are any CVEs to change
cve_id_exist = ''
cve_id_exist3 = []
cves_numbers_v1 = 0
cves_numbers_v3 = 1
cve_check = 0

# Function to bulk update the CVE IDs and add the needed comments
def bulk_func(d_id,d_cve_id, d_url, d_headers, d_num_days, d_list2, d_start_time):
    print("....")
    print("==========================================================================================================")
    print("Removing the due_date from the needed vulnerabilities.")
    
    if d_id == 1:
        data2 = '{ "vulnerability_ids" : ' + str(d_cve_id) + ', "vulnerability" : { "due_date": "" } }'
    elif d_id == 2:
        data2 = '{ "vulnerability_ids" : [' + str(d_cve_id) + '], "vulnerability" : { "due_date": "" } }'

    return_data = requests.put(d_url, headers=d_headers, data=data2)
    print("....")
    print("URL3:     " + d_url)
    print("Data:     " + data2)
    print("Response: " + str(return_data))
    print("....")

# Setup Data Dump
headers = {
    'X-Risk-Token':  RiskToken,
    'Content-type': 'application/json',
}

data = '{ "status" : ["open"], "search_id" : ' + str(RiskMeter) + ', "export_settings" : { "format": "json", "model": "vulnerability" } }'
base_uri = '/data_exports'
url = ''.join([base_url, base_uri])
response = requests.post(url, headers=headers, data=data)
if response.status_code != 200:
    print(f"Data export API error: {response.status_code}")
    sys.exit(1)

data = json.loads(response.content)
search_id = data['search_id']

# Beginning of the Comments
print(".")
print(".")

# Pull Data Dump
headers = {
    'X-Risk-Token': RiskToken ,
}

params = (
    ('search_id', search_id),
)

# Retrieve the export data.
response = requests.get(url, headers=headers, params=params)

# Loop because of possible HTTP 429 (Too Many Requests) error.
while True:
    if (response.status_code != 200):
        print("Waiting 15 Seconds For Data Dump.")
        time.sleep(15)
        response = requests.get(url, headers=headers, params=params)
    if (response.status_code == 200):
            break

with open("kenna_asset_export.gzip", mode='wb') as localfile: 
    localfile.write(response.content)

with gzip.open('kenna_asset_export.gzip', 'rb') as f:
    file_content = f.read()

data = json.loads(file_content)
data = data['vulnerabilities']
df = pd.json_normalize(data)
df_cve = df[df['cve_id'].str.contains("CVE-")]
df_cve = df_cve['cve_id']
df_cve = df_cve.drop_duplicates()

# Will get all the CVE_IDs for specific CVE_Names
for i in data:
    try:
        cve_id[i['cve_id']] = cve_id[i['cve_id']] + ',' + str(i['id'])
    except KeyError:
        cve_id[i['cve_id']] = str(i['id'])

# Create a sorted list of (cve_name, cve_ids) pairs
cve_id_v2 = sorted(cve_id.items(),key=lambda x: x[1], reverse=True)

# Getting CVEs to check
cves = df_cve.values.tolist()

df = pd.DataFrame() 

print("==========================================================================================================")
print("Number of CVE's to check (after removing duplicated CVEs): ", len(cves))
print("==========================================================================================================")

# Where the fun begins
base_uri2 = 'vulnerability_definitions/history?cves='
history_url = base_url + base_uri2

for cve in cves:
    cve_data_temp = []
    url2 = history_url + cve
    cves_numbers_v1 += 1

    # Provide some sort of logs, so the end-user knows that the script is runnning
    if (cves_numbers_v1 == cves_numbers_v3):
        print("....")
        print("URL - Find History per CVE:    ", url2)
        print("Number of CVEs checked so far: ", cves_numbers_v1)
        print("Time now: " + str(datetime.today()))
        print("....")
        cves_numbers_v3 += 500
    
    response = requests.get(url2, headers=headers)

    # Loop because of possible HTTP 429 (Too Many Requests) error.
    while True:
        if (response.status_code != 200):
            print("API Time Out, Taking A 15 Second Break")
            time.sleep(15)
            response = requests.get(url2, headers=headers, params=params)
        if (response.status_code == 200):
            data = json.loads(response.content)
            break

    risk_meter_score = json.dumps(data[cve]['risk_meter_score'])
    risk_meter_score_history_record= json.dumps(data[cve]['risk_meter_score_history'])
    individual_risk_meter_score_history_records = re.findall(r'\{([^}]+)\}', risk_meter_score_history_record)
    for irisk_meter_score_history_record in individual_risk_meter_score_history_records:
        risk_meter_score_history_changed = irisk_meter_score_history_record[risk_meter_score_history_record.find(": \"20")+1:risk_meter_score_history_record.find("Z")] 
        risk_meter_score_history_from = re.search('\"from\": (\d+)', irisk_meter_score_history_record)
        if risk_meter_score_history_from is not None:
            risk_meter_score_history_from = risk_meter_score_history_from.group(0)
        else:
            risk_meter_score_history_from = print("nochange")

        risk_meter_score_history_to = re.search('\"to": (\d+)', irisk_meter_score_history_record)
        if risk_meter_score_history_to is not None:
            risk_meter_score_history_to = risk_meter_score_history_to.group(0)
        else:
            risk_meter_score_history_to = print("nochange")
        
        # Process created to check if the score changed in the last X days
        if risk_meter_score_history_changed >= yesterday_datetime:
            for cve_name, cve_id_number in cve_id_v2:
                if cve_name == cve and cve_check != cve_id_number:
                    print("CVE: " + cve + " / CVE ID: " + cve_id_number + " - Last change happened during the last " + str(num_days) + " day(s). Changed on: ", risk_meter_score_history_changed)
                    cve_check = cve_id_number
                    if cve_id_exist == '':
                        cve_id_exist = str(cve_id_number)
                    else:
                        cve_id_exist = cve_id_exist + ',' + str(cve_id_number)
                    break
        # End of the score change validation

        x_data_temp = []
        x_data_temp.append(cve)
        x_data_temp.append(risk_meter_score)
        x_data_temp.append(risk_meter_score_history_changed)
        x_data_temp.append(risk_meter_score_history_from)
        x_data_temp.append(risk_meter_score_history_to)
        df = df.append({'CVE': cve, 'Kenna Risk Score': risk_meter_score, 'Date Changed': risk_meter_score_history_changed, "Old Score": risk_meter_score_history_from, "New Score": risk_meter_score_history_to}, ignore_index=True)

# Beginning of the bulk update | will update all the needed CVEs IDs
headers2 = {
    'X-Risk-Token':  RiskToken,
    'Content-type': 'application/json',
    }

# Check if there are any CVEs to be updated
if len(cve_id_exist) > 0:
    list1=list(cve_id_exist.split(","))
    list2=list(map(int,list1))

    # If there are a large set of CVEs to be updated, we will split that in sets of 2000 CVE IDs per API call
    if len(list2) > 2000:
        for cves in list2:
            cve_id_exist3.append(cves)

            if len(cve_id_exist3) == 2000:
                bulk_func(1,cve_id_exist3, url3, headers2, num_days, list2, start_time)
                cve_id_exist3.clear()
                time.sleep(2)
        
        # After the above loop ends ("for cves in list2") we will check if there are any left CVEs to be updated...
        # ... that were not able to be updated due to the 2000 limitation
        if len(cve_id_exist3) > 0:
            bulk_func(1,cve_id_exist3, url3, headers2, num_days, list2, start_time)
            cve_id_exist3.clear()
    
    # In case that the initial list has less than 2000 CVE IDs to be updated       
    elif len(list2) > 0:
        bulk_func(2,cve_id_exist, url3, headers2, num_days, list2, start_time)
        
else:
    print("....")
    print("==========================================================================================================")
    print("------ DONE! NO DUE_DATE removed from CVEs! NO score changed in the last " + str(num_days) + " day(s).")
    print("------ Number of CVEs where the due_date was removed: 0")
    print("------ START TIME: " + str(start_time) + " - END TIME: " + str(datetime.today()))
    print("==========================================================================================================")

if len(cve_id_exist) > 0:
    print("==========================================================================================================")
    print("------ DONE! DUE_DATE removed from CVEs that had a scores changed in the last " + str(num_days) + " day(s).")
    print("------ Number of CVEs where the due_date was removed: " ,len(list2))
    print("------ START TIME: " + str(start_time) + " - END TIME: " + str(datetime.today()))
    print("==========================================================================================================")
# End of the process to Bulk update the CVEs

df['Date Changed'] = df['Date Changed'].map(lambda x: x.lstrip('+-').rstrip('"'))
df['Old Score'] = df['Old Score'].str.replace(r'"from":', '')
df['New Score'] = df['New Score'].str.replace(r'"to":', '')
df = df[['CVE', 'Kenna Risk Score', 'Date Changed', 'New Score', 'Old Score']]
df["Kenna Risk Score"] = pd.to_numeric(df["Kenna Risk Score"])
df["Date Changed"] = pd.to_datetime(df["Date Changed"])
df = df.sort_values(by=['Date Changed'], ascending=False)
df.to_csv("opencves.csv", index=False)