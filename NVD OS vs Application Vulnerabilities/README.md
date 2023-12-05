# Tag CVEs with Custom Field for Vulnerability Type (OS, Application, Hardware or Network)

## Introduction
Our customers wanted the ability to identify & filter vulnerabilities by their classification like OS & Application. 
Full working process on how this can be done using the custom field option can be found documented in the attached Vulnerability Type Custom Field.

This script handles the step#2 listed on the document, where a CSV is required as an input with the CVEs and their classification. 
NVD database was referenced to get this information by following the steps below:

1.	Access the CVE API of NVD to get the details - https://nvd.nist.gov/developers/vulnerabilities
2.	For each CVE entry, check the 'criteria' field in the 'configurations' section. This field contains a URI that identifies the affected product and version. (explained below in CPE section)
3.	The 'criteria' URI is composed of several components, each separated by a colon. The second component indicates the product type - an application ('a') or an operating system ('o').
4.	By examining this component, you can categorize the CVE either as application-related or OS-related.

Types of product type:
1.	a: (Application): This is used to denote that the component is an application. An example would be cpe:2.3:a:microsoft:internet_explorer:8.0.7600.16385:*:*:*:*:*:*:*.
2.	o: (Operating System): This is used to denote that the component is an operating system. An example would be cpe:2.3:o:microsoft:windows_7:-:*:*:*:*:*:*:*.
3.	h: (Hardware): This is used to denote that the component is a piece of hardware. An example would be cpe:2.3:h:dell:poweredge_2950:-:*:*:*:*:*:*:*.
4.	n: (Network): This is used to denote that the component is network. An example would be cpe:2.3:n:tls:example_tls:-:*:*:*:*:*:*:*.

  
## Usage
python nvd_os_app_custom_field.py


## Updates/Edits needed to execute the script

### 1: Update the base_url 
By default, https://api.kennasecurity.com/ is being used. Update it to w.r.t the customer's environment.

### 2: API Key Token
Set an environment variable named API_KEY with your actual API key as its value. The way you do this can vary depending on your operating system and the interface you're using (command line, graphical interface, etc.).
#### Windows:
You can set an environment variable in Windows using the setx command in the command prompt:
*setx API_KEY "your-api-key"*

#### Mac OS or Linux:
In macOS or Linux, you can set an environment variable in the terminal using the export command:
*export API_KEY=your-api-key*

### 3: Custom Field ID
Update *custom_field_id = 4* with the custom field id from your customer's environment

### 4: Wait time for Export
By default the script waits for maximum time of 20 minutes to get the export from the customer's environment, in case your export is big and needs more time, 
please update the *max_wait_time=1200* parameter (in seconds) to accomodate your export.
Note: The scipt was tested with 1200 seconds (20 minutes) with record count of ~8M and it executed successfully.

## Requirements
* python
* json
* csv
