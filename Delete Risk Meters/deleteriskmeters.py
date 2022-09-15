import requests
import pandas as pd
import sys

token = sys.argv[1]
file = sys.argv[2]

headers = {"Accept": "application/json", "X-Risk-Token": token}

base_url = "https://api.kennasecurity.com"
rm_url= base_url + "/asset_groups/"

df = pd.read_csv(file, header=None)
rm_list = df.values.tolist()
rm_list_count = len(rm_list)
rm_deleted = 0

for x in rm_list:
    rm_id = str(x)[1:-1]
    request_url = rm_url + rm_id
    deletion_response = requests.delete(request_url, headers=headers)
    #print(deletion_response)
    rm_deleted+=1

if rm_list_count == rm_deleted:
    print(f'{rm_list_count} risk meters have been successfully deleted from Kenna.')
else:
    print(f'{rm_deleted} risk meters were deleted, but {rm_list_count} IDs were provided.')
