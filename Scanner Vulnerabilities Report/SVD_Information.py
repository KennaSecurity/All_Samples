import ijson
import csv
from datetime import datetime


# Get the current date
today = datetime.today().strftime("%Y-%m-%d")

# Generate the CSV file name with the date
csv_file_name = f"output_vulns_{today}.csv"

# Write to CSV
outFile = open(csv_file_name, mode='w', newline='')
writer = csv.writer(outFile)
writer.writerow(['Vulnerability ID', 'Details Connector Name', 'Details Value', 'CVE'])

# Initialize a list to store the selected values
count = 0
# Read the JSON file
with open('export_<DATE>.json') as file:
    for record in ijson.items(file, "vulnerabilities.item"):
        vulnerability = record
        vulnerability_id = vulnerability['id']
        details = vulnerability['details']
        scanner_vulnerabilities = vulnerability['scanner_vulnerabilities']
        connectors = vulnerability['connectors']
        cve = vulnerability['cve_id']

        if len(connectors) > len(details):
            if len(details) > 0:
                details_connector_name = details[0]['connector_name']
                details_value = details[0]['value']
            count += 1
            writer.writerow([vulnerability_id, details_connector_name, details_value, cve])
            if count % 100 == 0:
                print ("Count is", count)

outFile.close()

print(f"CSV file '{csv_file_name}' has been generated.")
