import requests
import pandas as pd 
import json
import gzip
import time
import re
from tqdm.auto import tqdm

# Small Demo
RiskToken = "RjUZkf6sir2s4nXyz_zVjAaMf5VQVg9nCokWs6_1xfBQpe7HrUbSr5_m9GkrL-41"

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
    rms = json.dumps(data[cve]['risk_meter_score'])
    rmshr = json.dumps(data[cve]['risk_meter_score_history'])
    irmshrs = re.findall(r'\{([^}]+)\}', rmshr)
    for irmshr in irmshrs:
        rmshc = irmshr[rmshr.find(": \"20")+1:rmshr.find("Z")] 
        rmshf = re.search('\"from\": (\d+)', irmshr)
        if rmshf is not None:
            rmshf = rmshf.group(0)
        else:
            rmshf = print("nochange")

        rmsht = re.search('\"to": (\d+)', irmshr)
        if rmsht is not None:
            rmsht = rmsht.group(0)
        else:
            rmsht = print("nochange")

        x_data_temp = []
        x_data_temp.append(cve)
        x_data_temp.append(rms)
        x_data_temp.append(rmshc)
        x_data_temp.append(rmshf)
        x_data_temp.append(rmsht)
        df = df.append({'CVE': cve, 'Kenna Risk Score': rms, 'Date Changed': rmshc, "Old Score": rmshf, "New Score": rmsht}, ignore_index=True)

df['Date Changed'] = df['Date Changed'].map(lambda x: x.lstrip('+-').rstrip('"'))
df['Old Score'] = df['Old Score'].str.replace(r'"from":', '')
df['New Score'] = df['New Score'].str.replace(r'"to":', '')
df = df[['CVE', 'Kenna Risk Score', 'Date Changed', 'New Score', 'Old Score']]
df["Kenna Risk Score"] = pd.to_numeric(df["Kenna Risk Score"])
df["Date Changed"] = pd.to_datetime(df["Date Changed"])
df = df.sort_values(by=['Date Changed'], ascending=False)
df.to_csv("opencves.csv", index=False)
print(df)