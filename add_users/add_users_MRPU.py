# kenna-bulk-custom-field-update
import requests
import json
import csv


# These are the arguments we are expecting to get - header file can be send as third parameter if not included as row 1 in csv
token = input("Enter your Kenna token: ")
csv_file = input("Enter the path to your CSV file: ")
# fname_col = input("Enter the column number for the first name: ")
# lname_col = input("Enter the column number for the last name: ")
# roles_col = input("Enter the column number for the roles: ")
# email_col = input("Enter the column number for the email: ")


# Variables we'll need later
post_url = 'https://api.kennasecurity.com/users'
headers = {'content-type': 'application/json', 'User-Agent':'add_user_MRPU.py/1.0.0', 'X-Risk-Token': token}


num_lines = sum(1 for line in open(csv_file))
print(f"Found {num_lines} lines.")


# Iterate through CSV
with open(csv_file, 'r') as csvfile:
    reader = csv.reader(csvfile, delimiter=',')
    for row in reader:
        # "Reading line {}".format(current_line)
        current_line = reader.line_num

        email = row[0]
        fname = row[1]
        lname = row[2]
        phone = row[3]
        roles = row[4].replace(' ','').split(',')

        # print(roles) [remove comment for troubleshooting]

        # Build JSON payload
        json_data = {
            "user": {
                "firstname": fname,
                "lastname": lname,
                "email": email,
                "phone": phone,
                "roles": roles
            }
        }

        # print(json_data) [remove comment for troubleshooting]

        # Builds API request and sends it to the platform
        try:
            response = requests.post(post_url, headers=headers, data=json.dumps(json_data))
            print(f"Request successful. Status code: {response.status_code}")
        except Exception as e:
            print(e.message)
            print(e.backtrace.inspect)

print("Complete!")