# Kenna Audit Log Parser
The Kenna platform has extensive logging which customers can obtain portions of the logs by querying the relevant API endpoints that they are authorized to. 
While the log files offer rich detail about activities on the platform, customers may struggle with parsing the logs for relevant information of interest. 

This Kenna Audit Log parser aims to provide a tool by which customers can glean relevant information from the log files fairly easily. 
Search flags are modularized and can be easily chained to produce very fine-grained information from the log files. 

Note that users would first need to have downloaded the log file using the API, and extracted it to produce the json file which can then be parsed. 
For users unfamiliar with any part of this download process, please see details in the Kenna help article here - https://help.kennasecurity.com/hc/en-us/articles/360030658612-Audit-Logs. 

To get users familiar with the way to use / chain these search parameters, various samples are provided further down in this README.  


## Usage
The script contains Help documentation on how the script can be used. Some additional formatting is provided here to aid visibility.

```
ruby .\audit_parser.rb --help

Kenna Audit Logs Parser. Usage: audit_parser.rb [options]
    -d, --date=DATE                  Narrow search to a particulate date. Format: YYYY-MM-DD
    
    -i, --id=ID                      Search by a given user ID; has higher priority than username
    
    -f, --filename=FILENAME          Mandatory argument. Filename should be provided for reading the log file
    
    -u, --username=USERNAME          Search by a given user account
    
    -k, --kenna_object=KENNA_OBJECT  Kenna object to be searched. Valid Kenna objects are (without the quotes):
                                     "risk_meters", "assets", "vulns", "users", "risk_score_overides", "user_logins", "api_keys", "connectors", "exports"
                                     
                                     Valid operations (-o flag) for each Kenna object are captured below:
                                     **risk_meters** - operations: "created", "updated", "deleted", "all"
                                     
                                     **assets** - operations: this option is not applicable and will be ignored if used
                                     
                                     **vulns** - operations: "human", "dynamic", and "all"
                                     
                                     **users** - operations: "created", "updated", "deleted", and "all"
                                     
                                     **risk_score_overides** - operations: this is not applicable and so will be ignored
                                     
                                     **connectors** - operations: "created", "updated", "deleted", and "all"
                                     
                                     **user_logins** - operations: this is not applicable and so will be ignored
                                     
                                     **api_keys** - operations: "created", "revoked", and "all"
                                     
                                     **exports** - operations: "created", "retrieved", "all", "allexports_ui", "allexports_api"
                                     
                                     
    -o, --operation=OPERATION        Operation to search for on a Kenna object. see applicable operations for the various kenna objects above
    
    -r, --reference_id=REFERENCE     A Reference value/id used (where applicable) to narrow search e.g. risk meter ID, user ID
                                     applicable for the following kenna objects: "risk_meters", "users", "connectors", and "assets"
                                     
    -s, --save                       Save script output to a file. Useful for full automation so user is not prompted to save
                                     By default, script provides a 10-second window for the user to save results to file.
                                     
    -a, --asset_extras=              Used with Asset search. Search for an asset using it's locator
                                     Example: netbios_locator,asset_netbios

```

Some things to note
- Searches can be done using a combination of short/and/or long options (see samples below)
- By default, the script provides a 10-second timeframe for which the user is prompted to save the results into a CSV file. Type 'y' and enter to save the results, or 'n' and enter to avoid saving. If not input is given within the 10-second window, the program exists. 
- Use the -s option to prevent having the program prompt you to save. This is good for automations so the output of a search can be saved without any user interaction
- Various samples are provided for searches to track risk meter, vuln status and asset status changes / updates. 



## Examples
Here are some examples that can serve to guide users on how to utilize the scripts many switches. 


**Risk meter Update Searches**

- Search for all risk meters captured in the log files for the period

`ruby .\audit_parser.rb -f "C:\Users\audit_file.json" -k risk_meters -o all`


- Search for all risk meters created by user account with user ID 398456

`ruby .\audit_parser.rb -f "C:\Users\audit_file.json" --kenna_object risk_meters -o created -i 398456`


- Search for the risk meter with risk meter ID 352896, created by a certain user account

`ruby .\audit_parser.rb --filename "C:\Users\audit_file.json" --kenna_object risk_meters --operation created --username casey -r 352896`


- Search for all risk meters that were created on a certain date

`ruby .\audit_parser.rb --filename "C:\Users\audit_file.json" -k risk_meters --operation created --date 2022-02-09`


- Search for all risk meters created on the 9th of February. Save the results to a csv file without prompting the user. Great for automations

`ruby .\audit_parser.rb -f "C:\Users\audit_file.json" -k risk_meters -o created -d 2022-02-09 -s`



**Asset Update Searches**

- Search for all asset updates

`ruby .\audit_parser.rb -f "C:\Users\audit_file.json" -k assets`


- Search for all asset updates; narrow results by a user with user ID 398456

`ruby .\audit_parser.rb -f "C:\Users\audit_file.json" -k assets -i 398456`


- Search for all asset updates; narrow results by user email (you can use part of the email)

`ruby .\audit_parser.rb -f "C:\Users\audit_file.json" -k assets -u casey`


- Search for all asset updates; narrow results by asset details (note: search is case insensitive)

`ruby .\audit_parser.rb -f "C:\Users\audit_file.json" -k assets -a netbios_locator,stilldontexist`


- Search for all asset updates; narrow results by user ID and by asset details

`ruby .\audit_parser.rb -f "audit_file.json" -k assets -u casey -a netbios_locator,stilldontexist`



**Vuln Status Searches**

- Find all vuln status changes

`ruby .\audit_parser.rb -f "audit_file.json" -k vulns -o all`


- Find all vuln status changes made by a user 

`ruby .\audit_parser.rb -f "audit_file.json" -k vulns -o all -u casey`


- Search for all human-initiated vuln status changes

`ruby .\audit_parser.rb -f "audit_file.json" -k vulns -o human`


- Search for all human-initiated vuln status changes by a certain user account

`ruby .\audit_parser.rb -f "audit_file.json" -k vulns -o human -u casey`


- Search for all dynamically initiated vuln status changes

`ruby .\audit_parser.rb -f "audit_file.json" -k vulns -o dynamic`


- Dynamically initiated vuln status changes by a user account using user ID search

`ruby .\audit_parser.rb -f "audit_file.json" -k vulns -o dynamic -i 398456`



## Requirements
### Language
- Ruby

### Gems/Classes
- json
- csv
- optparse
- rest-client
