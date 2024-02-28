# Create an Excel sheet with list of vulnerabilities with the count of assets affected

## Introduction
This script can be used to generate an excel with vulnerabilities and number of assets affected by each of the vulnerability in question. This script can be run in 2 ways for 3 scenarios:
1) By providing list of CVEs in comma separated format
2) For a particular Risk Meter by providing the Risk Meter ID
3) For all the vulnerabilities in the Platform by providing the Risk Meter ID of the "All Assets" group/risk meter

Output will be generated as *vulns_with_counts.xlsx* with two sheets; *Full List* will have the entire export and *CVE Asset Counts* will have the vulnerabilities 
with their score and asset counts.

### Note:
The script does an export of vulnerabilities in "open" by default.
  
## Usage
```python vulns_and_assets.py```


Sample script run with Risk Meter ID as input:
```
Script prompt - Enter '1' to use Risk Meter ID or '2' to use CVE List: 1

Script prompt - Enter the Risk Meter ID: 1234

Data export initiated...
```


Sample script run with list of CVEs as input:
```
Script prompt - Enter '1' to use Risk Meter ID or '2' to use CVE List: 2

Script prompt - Enter the CVEs in a comma separated format (if more than one): CVE-2014-0781,CVE-2014-0782

Data export initiated...
```


## Updates/Edits needed to execute the script

### 1: Update the base_url 
By default, https://api.kennasecurity.com/ is being used. Update it to w.r.t your environment.

### 2: API Key Token
Set an environment variable named API_KEY with your actual API key as its value from Cisco Vulnerability Management Platform. The way you do this can vary depending on your operating system and the interface you're using (command line, graphical interface, etc.).
#### Windows:
You can set an environment variable in Windows using the setx command in the command prompt:
*setx API_KEY "your-api-key"*

#### Mac OS or Linux:
In macOS or Linux, you can set an environment variable in the terminal using the export command:
*export API_KEY=your-api-key*

### 3: Input for CVE or Risk Meter ID
By default the script waits for 90 seconds to get a user input, if no input is received within the stipulated time period then the script will exit out. If need be, 
this time can be increased and/or decreased on Line#39 based on user experience needed.

## Requirements
* python
* requests
* pandas
