import requests
import pandas as pd
import json
import sys
import datetime
from pandas import json_normalize  

def flatten_json(nested_json, exclude=['roles']):
    """Flatten json object with nested keys into a single level.
        Args:
            nested_json: A nested json object.
            exclude: Keys to exclude from output.
        Returns:
            The flattened json object if successful, None otherwise.
    """
    out = {}
    def flatten(x, name='', exclude=exclude):
        if type(x) is dict:
            for a in x:
                if a not in exclude: flatten(x[a], name + a + '_')
        elif type(x) is list:
            i = 0
            for a in x:
                flatten(a, name + str(i) + '_')
                i += 1
        else:
            out[name[:-1]] = x

    flatten(nested_json)
    return out

token = sys.argv[1]
# increase per_page to get more data per request
per_page = 10
base_url = "http://api.kennasecurity.com"
users_url= base_url + "/users?per_page=" + str(per_page)
roles_url = base_url + "/roles"

#print(users_url)

headers = {"Accept": "*/*", "X-Risk-Token":token, "User-Agent": 'PostmanRuntime/7.42.0'}

#print(users_response)
writer = pd.ExcelWriter('kenna_user_audit.xlsx', engine='xlsxwriter', date_format='m/d/yyyy')
pages = -1
page = 1
users_df = pd.DataFrame()

while True:
    paged_url = users_url + "&page=" + str(page)
    print("Requesting data from", paged_url)
    users_response = requests.get(paged_url, headers=headers).json()
    users_df = pd.concat([users_df, pd.DataFrame(json_normalize([flatten_json(x) for x in users_response['users']]))], ignore_index=True)   
    # do this once
    if 'meta' in users_response and pages == -1:
        pages = users_response['meta']['pages']
    if page >= pages:
        break
    page += 1

users_df = users_df.rename(columns={"id":"user_id","created_at":"user_created_at","updated_at":"user_updated_at"})

users_df['user_created_at'] = pd.to_datetime(users_df['user_created_at'], format='%Y-%m-%d', errors='coerce').dt.date
users_df['last_sign_in_at'] = pd.to_datetime(users_df['last_sign_in_at'], format='%Y-%m-%d', errors='coerce').dt.date

print('Printing Users data sample:')
print(users_df.head(2))
users_df.to_excel(writer, sheet_name='Users')
#remove comments to troubleshoot columns
#for col in users_df.columns:
    #print(col)

#print(roles_url)

roles_response = requests.get(roles_url, headers=headers).json()

roles_df = pd.DataFrame(json_normalize([flatten_json(x) for x in roles_response['roles']]))
roles_df = roles_df.rename(columns={"id": "role_id","created_at":"role_created_at","updated_at":"role_updated_at","name":"role_name"})

print('Printing Roles data sample:')
print(roles_df.head(2))

#remove comments to troubleshoot columns
#for col in roles_df.columns:
    #print(col)

workbook = writer.book

roles_df.to_excel(writer, sheet_name='Roles')

red_format = workbook.add_format({'bg_color': '#FFC7CE','font_color': '#9C0006'})
yellow_format = workbook.add_format({'bg_color': '#FFEB9C','font_color': '#9C6500'})

users_sheet = writer.sheets['Users']

#Conditional formatting resources to apply new rules/formats:
#https://www.extendoffice.com/documents/excel/2196-excel-conditional-formatting-dates-older-than.html
#https://xlsxwriter.readthedocs.io/working_with_conditional_formats.html

users_sheet.conditional_format('$J$2:$J$99999', {'type': 'blanks', 'format': red_format})
users_sheet.conditional_format('$J$2:$J$99999', {'type': 'formula', 'criteria': '=J2<TODAY()-30', 'format': yellow_format})

writer.close()

print('User and role data has been saved to the file kenna_user_audit.xlsx.')
print('Users that have never logged in are highlighted in red. Users that have not logged in for over 30 days are highlighted in yellow.')
