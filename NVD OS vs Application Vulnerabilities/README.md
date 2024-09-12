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

#### Disclaimer: "This script uses the NVD API but is not endorsed or certified by the NVD."

  
## Usage
The customer has the flexibility to use the script in multiple ways using a flag beacause there will be instances where one vulnerability will have multiple product types (application, os, hardware & network) :

1) Default method - By this way the script will use 'application' as the precedence in case there are multiple products

   *python nvd_os_app_custom_field.py*

3) Using the *multi* flag - By this way, the script will list all the available products on the vulnerability

   *python nvd_os_app_custom_field.py --multi*

5) Using the OS *'o'* preference flag - By this way, customer can select OS as the precedence & add 'os' as the custom field in case a vulnerability has multiple product types

   *python nvd_os_app_custom_field.py --preference o*

7) Using the Application *'a'* preference flag - By this way, customer can select Application as the precedence & add 'application' as the custom field in case a vulnerability has multiple product types

   *python nvd_os_app_custom_field.py --preference a*

## Updates/Edits needed to execute the script

### 1: Create Custom Field  
Create a custom field with name *'Vuln Type'* in your platform and note the ID number to be used in step #4. Details on 'How' to create custom field can be found in the attached *Vulnerability Type Custom Field.pdf*

### 2: Update the base_url 
By default, https://api.kennasecurity.com/ is being used on Line #19. Update it to w.r.t your environment.

### 3: API Key Token
Set an environment variable named KENNA_API_KEY with your actual API key as its value. The way you do this can vary depending on your operating system and the interface you're using (command line, graphical interface, etc.).
#### Windows:
You can set an environment variable in Windows using the setx command in the command prompt:
*setx KENNA_API_KEY "your-api-key"*

#### Mac OS or Linux:
In macOS or Linux, you can set an environment variable in the terminal using the export command:
*export KENNA_API_KEY=your-api-key*

### 4: Custom Field ID
Update *custom_field_id = 4* on line #81 in the code, with custom field id number from your environment as created in step #1 above. 

### 5: Wait time for Export
By default the script waits for maximum time of 20 minutes to get the export from the customer's environment, in case your export is big and needs more time, 
please update the *max_wait_time=1200* parameter (in seconds) to accomodate your export.
Note: The scipt was tested with 1200 seconds (20 minutes) with record count of ~2M and it executed successfully.

## Requirements
* python
* json
* csv

## Recommendation
Uisng the screenshot *UI Example of Various Options* as a reference, customers can run the script with *multi* flag in tandem with default or reference flag to compare what products are available on the vulnerability and then do further triage based on the organization needs & patching preference.
