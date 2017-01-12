#!/usr/bin/env python

import sys, requests, json
from bs4 import BeautifulSoup

token = sys.argv[1]
file = sys.argv[2]

LOCATOR_DELIMITER = ":"
API_ENDPOINT_ASSETS = "https://api.kennasecurity.com/assets"
API_ENDPOINT_VULNS = "https://api.kennasecurity.com/vulnerabilities"
headers = {'content-type': 'application/json', 'X-Risk-Token': token}

asset_urls_dict = {}
CWE_WAS_DICT = {
    "77": "19",
    "552": "16",
    "248": "13",
    "287" : "01", "642" : "01", "259" : "01",
    "284" : "02", "285" : "02",
    "190" : "03", "682" : "03",
    "311" : "04", "319" : "04", "523" : "04", "614" : "04", "310" : "04",
    "98" : "05", "426" : "05",
    "134" : "6",
    "119" : "7",  "120" : "7",
    "79" : "8",  "80 " : "8",  "0" : "08",
    "352" : "9",
    "400" : "10", "404" : "10",
    "330" : "11", "331" : "11", "340" : "11",
    "345" : "12",
    "200" : "13", "209" : "13", "525" : "13", "359" : "13",
    "16 " : "14", 
    "548" : "16",
    "250" : "17", "280" : "17", "732" : "17",
    "20 " : "20", 
    "799" : "21", "804" : "21",
    "116" : "22", "117" : "22",
    "330" : "18",
    "89" : "19",
    "91" : "23",
    "93" : "24",
    "113" : "25",
    "444" : "26",
    "436" : "27",
    "158" : "28",
    "90" : "29",
    "88" : "30",
    "78" : "31",
    "300" : "32", "441" : "32",
    "22" : "33", "73" : "33", "426" : "33",
    "425" : "34", "530" : "34",
    "789" : "35",
    "97" : "36",
    "384" : "37", 
    "601" : "38",
    "643" : "39",
    "691" : "40",
    "400" : "41", "405" : "41",
    "227" : "42",
    "611" : "43",
    "776" : "44",
    "205" : "45",
    "652" : "46",
    "613" : "47", "615" : "47",
    "612" : "48",
    "640" : "49"
}


handler = open(file).read()
soup = BeautifulSoup(handler)

# Input (xml):
#<Query>
#    <Result>
#        <Path>
#            <PathNode>
#                <Line>
#                <Column>
#                <Snippet>
#                    <Line>
#                        <Number>
#                        <Code>

# Output (json):
# {
#   "vulnerability": {
#     "wasc_id": the_wasc_id,
#     "primary_locator": "file",
#     "file": the_filename
#   }
# }


## Iterate through Checkmarx XML and pull out vuln info, then create new vulns/assets via API_ENDPOINT_VULNS
##
try:
    for query in soup.find_all('query'):
        # get cwe/wasc
        the_cwe_id = query['cweid']
        the_wasc_id = CWE_WAS_DICT[the_cwe_id]
    
    # iterate through result nodes
        for result in query.find_all('result'):
            the_filename = str(result['filename'])
            the_url = str(result['deeplink'])

            # iterate through path/pathnode nodes to get line:column
            for path in result.find_all('path'):
                for pathnode in path.find_all('pathnode'):
                    the_line = pathnode.line.string
                    the_column = pathnode.column.string
                    the_snippet = pathnode.snippet.line.code.string

                    the_locator = the_filename + LOCATOR_DELIMITER + the_line + LOCATOR_DELIMITER + the_column
                    vuln_json = {
                        "vulnerability": {
                            "wasc_id" : "WASC-" + the_wasc_id,
                            "primary_locator" : "file",
                            "file" : the_locator,
                            "notes" : "Detected in " + the_filename + ", line " + the_line + ", column " + the_column + ": " + the_snippet
                        }
                    }

                    # POST new vuln/asset, get back asset_id
                    vuln_post = requests.post(API_ENDPOINT_VULNS, data=json.dumps(vuln_json), headers=headers)
                    response = vuln_post.json()
                    the_asset_id = str(response['vulnerability']['asset_id'])
except KeyError:
    print("Unable to map CWE to WAS-C. Update array in script with new mapping, save and re-run script.")  
    raise             