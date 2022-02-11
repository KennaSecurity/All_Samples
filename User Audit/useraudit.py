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
base_url = "https://api.kennasecurity.com"
users_url= base_url + "/users"
roles_url = base_url + "/roles"

#print(users_url)

headers = {"Accept": "application/json", "X-Risk-Token":token}

users_response = requests.get(users_url, headers=headers).json()

#print(users_response)

users_df = pd.DataFrame(json_normalize([flatten_json(x) for x in users_response['users']]))
users_df = users_df.rename(columns={"id":"user_id","created_at":"user_created_at","updated_at":"user_updated_at"})

users_df['user_created_at'] = pd.to_datetime(users_df['user_created_at'], format='%Y-%m-%d', errors='coerce').dt.date
users_df['last_sign_in_at'] = pd.to_datetime(users_df['last_sign_in_at'], format='%Y-%m-%d', errors='coerce').dt.date

print('Printing Users data sample:')
print(users_df.head(2))

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

writer = pd.ExcelWriter('kenna_user_audit.xlsx', engine='xlsxwriter', date_format='m/d/yyyy')

workbook = writer.book

users_df.to_excel(writer, sheet_name='Users')
roles_df.to_excel(writer, sheet_name='Roles')

red_format = workbook.add_format({'bg_color':   '#FFC7CE',
                               'font_color': '#9C0006'})
yellow_format = workbook.add_format({'bg_color':   '#FFEB9C',
                               'font_color': '#9C6500'})

users_sheet = writer.sheets['Users']

#Conditional formatting resources:
#https://www.extendoffice.com/documents/excel/2196-excel-conditional-formatting-dates-older-than.html
#https://xlsxwriter.readthedocs.io/working_with_conditional_formats.html

users_sheet.conditional_format('$J$2:$J$99999', {'type': 'blanks', 'format': red_format})
users_sheet.conditional_format('$J$2:$J$99999', {'type': 'formula', 'criteria': '=J2<TODAY()-30', 'format': yellow_format})

writer.save()

print('User and role data has been saved to the file kenna_user_audit.xlsx.')
print('Users that have never logged in are highlighted in red. Users that have not logged in for over 30 days are highlighted in yellow.')
