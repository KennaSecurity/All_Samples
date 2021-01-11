import gzip
import json
import os
import shutil
import pandas as pd
import requests

headers = {
    'X-Risk-Token': 'Copy_API_Token_Here',
    'Content-type': 'application/gzip',
}

params = (
    ('start_date', '2021-01-01'),
    ('end_date', '2021-01-09'),
)

response = requests.get('https://api.kennasecurity.com/audit_logs', headers=headers, params=params)

response.raise_for_status()

with open("audit_log.gz", "wb") as f:
    f.write(response.content)

with gzip.open('audit_log.gz', 'rb') as f_in:
    with open('audit_log.json', 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)

with open('audit_log.json') as f:
    lines = f.read().splitlines()

df_inter = pd.DataFrame(lines)
df_inter.columns = ['json_element']
df_inter['json_element'].apply(json.loads)
audit_log_df = pd.json_normalize(df_inter['json_element'].apply(json.loads))
audit_log_df.to_csv(r'audit_log.csv')