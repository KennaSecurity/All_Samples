import requests
import pandas as pd
import sys

token = sys.argv[1]
file = sys.argv[2]

headers = {"Accept": "application/json", "X-Risk-Token": token}

base_url = "https://api.kennasecurity.com"
users_url= base_url + "/users/"

df = pd.read_csv(file, header=None)
user_list = df.values.tolist()
user_list_count = len(user_list)
users_deleted = 0

for x in user_list:
    user_id = str(x)[1:-1]
    request_url = users_url + user_id
    deletion_response = requests.delete(request_url, headers=headers)
    #print(deletion_response)
    users_deleted+=1

if user_list_count == users_deleted:
    print(f'{user_list_count} users have been successfully deleted from Kenna.')
else:
    print(f'{users_deleted} users were deleted, but {user_list_count} IDs were provided.')
