import requests
import pandas as pd 
import json
import gzip
import time
import re
from tqdm.auto import tqdm

# Small Demo
RiskToken = "PasteAPIKeyHere"

# Setup Data Dump
headers = {
    'X-Risk-Token':  RiskToken,
    'Content-type': 'application/json',
}

data = '{ "status" : ["open"], "export_settings" : { "format": "json", "model": "vulnerability" } }'

response = requests.post('https://api.kennasecurity.com/data_exports', headers=headers, data=data)
data = json.loads(response.content)
search_id = data['search_id']

# Pull Data Dump
headers = {
    'X-Risk-Token': RiskToken ,
}

params = (
    ('search_id', search_id),
)

response = requests.get('https://api.kennasecurity.com/data_exports', headers=headers, params=params)
while True:
    if (response.status_code != 200):
        print("Waiting 15 Seconds For Data Dump.")
        time.sleep(15)
        response = requests.get('https://api.kennasecurity.com/data_exports', headers=headers, params=params)
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

# Getting CVEs to check
cves = df_cve.values.tolist()

cve_data = []

df = pd.DataFrame() 

# Checking CVES
headers = {
          'X-Risk-Token': RiskToken,
          }

for cve in tqdm(cves):
    cve_data_temp = []
    base_url = 'https://api.kennasecurity.com/vulnerability_definitions/history?cves='
    url = ''.join([base_url, cve])

    def getList(dict): 
            return dict.keys() 
    
    response = requests.get(url, headers=headers)
    data = json.loads(response.content)
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

        x_data_temp = []
        x_data_temp.append(cve)
        x_data_temp.append(risk_meter_score)
        x_data_temp.append(risk_meter_score_history_changed)
        x_data_temp.append(risk_meter_score_history_from)
        x_data_temp.append(risk_meter_score_history_to)
        df = df.append({'CVE': cve, 'Kenna Risk Score': risk_meter_score, 'Date Changed': risk_meter_score_history_changed, "Old Score": risk_meter_score_history_from, "New Score": risk_meter_score_history_to}, ignore_index=True)

df['Date Changed'] = df['Date Changed'].map(lambda x: x.lstrip('+-').rstrip('"'))
df['Old Score'] = df['Old Score'].str.replace(r'"from":', '')
df['New Score'] = df['New Score'].str.replace(r'"to":', '')
df = df[['CVE', 'Kenna Risk Score', 'Date Changed', 'New Score', 'Old Score']]
df["Kenna Risk Score"] = pd.to_numeric(df["Kenna Risk Score"])
df["Date Changed"] = pd.to_datetime(df["Date Changed"])
df = df.sort_values(by=['Date Changed'], ascending=False)
df.to_csv("opencves.csv", index=False)
print(df)
