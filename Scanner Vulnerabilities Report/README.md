# Create CSV with scanner vulnerabilities which are open by a scanner

## Introduction
If you are bringning data from multiple connectors and have locator order updated to merge assets and vulnerabilities, then scanner vulnerabilities from multiple connectors get tied to a single vulnerability ID. 
In order to close the vulnerability in Kenna, scanner vulnerability from all the connector sources should get validated and closed.

This script helps to create a list of vulnerabilities which are kept open by one of the connector but closed by the other connector(s). 
This can help you validate the scanning from the respective scanner keeping the detection open.

### Note:
The script does an export of vulnerabilities in "open", "risk accepted" and "false positive" status from your environment to determine which connector is keeping them open.
  
## Usage
python SVD_Information.py

## Updates/Edits needed to execute the script

### 1: Update the base_url 
By default, https://api.kennasecurity.com/ is being used. Update it to w.r.t your environment.

### 2: API Key Token
Set an environment variable named KENNA_API_KEY with your actual API key as its value. The way you do this can vary depending on your operating system and the interface you're using (command line, graphical interface, etc.).
#### Windows:
You can set an environment variable in Windows using the setx command in the command prompt:
*setx KENNA_API_KEY "your-api-key"*

#### Mac OS or Linux:
In macOS or Linux, you can set an environment variable in the terminal using the export command:
*export KENNA_API_KEY=your-api-key*

### 3: Wait time for Export
By default the script waits for maximum time of 90 minutes to get the export from the customer's environment, in case your export is big and needs more time, 
please update the *max_wait_time=5400*  (in seconds) parameter on line #52 to accomodate your export.
Note: The scipt was tested with maximum time of 5400 seconds (90 minutes) with record count of ~24M and it executed successfully in 44 minutes.

## Requirements
* python
* ijson
* csv
