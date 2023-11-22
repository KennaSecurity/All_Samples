# Create CSV with scanner vulnerabilities which are open by a scanner

## Introduction
If you are bringning data from multiple connectors and have locator order updated to merge assets and vulnerabilities, then scanner vulnerabilities from multiple connectors get tied to a single vulnerability ID. 
In order to close the vulnerability in Kenna, scanner vulnerability from all the connector sources should get validated and closed.

This script helps to create a list of vulnerabilities which are kept open by one of the connector but closed by the other connector(s). 
This can help you validate the scanning from the respective scanner keeping the detection open.

  
## Usage
Python SVD_Information.py


## Steps to perform before running the script

### Step 1:
Export vulnerabilities from data export endpoint - https://apidocs.kennasecurity.com/reference/request-data-export using the following fields/options:

    "format": "json",
    "model": "vulnerability",
    "slim": false,
    "fields": 
      "details",
      "scanner_vulnerabilities",
      "connectors",
      "cve_id"

### Step 2:
Retrieve the export and unzip the json.gz file to get the json which will be used to run the script.
Command to retrieve the file:
'https:// BASE URL/data_exports?search_id=INSERT_EXPORT_ID_HERE' --header 'X-Risk-Token: INSTERT_API_TOKEN_HERE ' -o export_DATE.json.gz --header 'accept: application/gzip'

#### Note: 
export_DATE.json file will be read by the script. So, plugin the file name for the latest file identified by date in the SVD_Information.py-

line 20 - *with open('export_DATE.json') as file:*


### Step 3:
Run the Script as mentioned in the usage section.

## Requirements
* python
* rest-client
* ijson
* csv
