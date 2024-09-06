# Add a Custom Field for Age on vulnerabilities

## Introduction
Our customers wanted to see the number of days and a range of date on the vulnerability since it was open from first found date. 
This script calculates the number of days since the vulnerability is open from first found date until today and is displayed in the UI on vulnerabilities tab and also under the vulnerability filters.
  
## Usage
python age_custom_field.py

## Updates/Edits needed to execute the script

### 1: Create Custom Field 
Create two custom fields in Cisco Vulnerability Management and select faceted search option to show these as filter option  :
1) *custom_field_id* ; This field populates the exact # of days
2) *custom_field_id_range* ; This field shows the range of days

### 2: Update the base_url 
By default, https://api.kennasecurity.com/ is being used on line #18. Update it to w.r.t your environment.

### 3: API Key Token
Set an environment variable named API_KEY with your actual API key as its value. The way you do this can vary depending on your operating system and the interface you're using (command line, graphical interface, etc.).
#### Windows:
You can set an environment variable in Windows using the setx command in the command prompt:
*setx API_KEY "your-api-key"*

#### Mac OS or Linux:
In macOS or Linux, you can set an environment variable in the terminal using the export command:
*export API_KEY=your-api-key*

### 4: Custom Field ID
Update *custom_field_id* on line #19 and custom_field_id_range* on Line #20 in the code, with custom field id numbers from your environment as created in step #1 above. 

### 5: Wait time for Export
By default the script waits for maximum time of 120 minutes to get the export from the customer's environment, in case your export is big and needs more time, 
please update the *max_wait_time=7200* on Line #53 (in seconds) to accomodate your export.
Note: The scipt was tested with 1200 seconds (20 minutes) with record count of ~2M and it executed successfully.

### 6: Date Range for Reporting
By default the script has the following ranges listed below, but these can be edited & customized to meet customer's reporting requirement.
  "<= 30 days"
  "31 - 60 days"
  "61 - 90 days"
  "91 - 180 days"
  "> 180 days"

## Requirements
* python
* json
* csv
