# Risk Meter Audit Script
Risk meters are an important concept in Kenna, and due to how useful they are, and the many applications of risk meters, the number of created risk meters can increase very quickly. 
Administrators of a Kenna instance may like to have a view of how these risk meters are used. This could be just for the hygiene of their platform so that risk meters no longer being used can be deleted, or to gain insights if the created risk meters are valuable to their users. 

This script helps to provide a view of your organization's risk meters, when they were last used, and what was the type of access (Web or API). 

Note that users would first need to have downloaded the log file using the API, and extracted it to produce the json file which is the basis of this audit. Download the audit file for the period you would like the review done e.g. last 30 days, 60 days etc. 
For users unfamiliar with any part of this download process, please see details in the Kenna help article here - https://help.kennasecurity.com/hc/en-us/articles/360030658612-Audit-Logs. 

The additional item required is the risk meter list for that environment. This can be downloaded during script execution by providing an API key with relevant permissions using the (-t) option, or by specifying a file (using the -r option) with the list of risk meters. 
A sample of the file with the accepted format is provided here.  


## Usage
The script contains Help documentation on how the script can be used. Some additional formatting is provided here to aid visibility.

```
ruby .\rmaudit.rb --help

Risk Meter Audit Script. Usage: rmaudit.rb [options]
    -r, --risk_meters=RMFILE         Optional argument. A csv file with a listing of risk meter IDs and names
                                     If this is not specified, then you must provide a token using the (-t) parameter. This takes precedence
                                     
    -t, --token=TOKEN                Optional argument. API token for the account making API calls.
                                     If this is not specified, then you must provide a source csv file using the (-r) parameter with your risk meters
                                     
    -f, --filename=FILENAME          Mandatory argument. Filename of the audit log file should be provided
    
    -d, --document_header=YES|NO     Optional argument (yes | no)- confirms if the risk meter file (-r option) has a header or not.
                                     If none is specified, the default is "yes"
                                     

```

Some things to note
- If a token (-t) and a risk meter file (-r) is provided, the script gives preference to the risk meter file. 
- Required columns in the risk meter file are risk meter ID, and risk meter name. See sample provided for any clarification.  
- The script tracks usage of visits to Risk meter pages, as well as API to risk meters and doesn't track visits to 'Reporting' and 'Top Fixes' pages for risk meters



## Examples
Here are some examples that can serve to guide users on how to utilize the scripts many switches. 

- Search using an account token 

`ruby rmaudit.rb -f "C:\Users\audit_file.json" -t <account_token>`


- Search using a local file with the list of risk meters in the organization  

`ruby rmaudit.rb -f "C:\Users\audit_file.json" -r "C:\Users\risk_meter_source.csv"`


- Search using a local file with the list of risk meters in the organization, specifying that the file has headers. This is the default if the -d option is not specified.

`ruby rmaudit.rb -f "C:\Users\audit_file.json" -r "C:\Users\risk_meter_source.csv" -d yes`


- Search using a local file with the list of risk meters in the organization, specifying that the file does not have headers  

`ruby rmaudit.rb -f "C:\Users\audit_file.json" -r "C:\Users\risk_meter_source.csv" -d no`


## Requirements
### Language
- Ruby

### Gems/Classes
- json
- csv
- optparse
- rest-client
- cgi
