# Kenna - Zap Vulnerability Upload

This script will search for a provided directory for zap results and loop through all to create vulnerabilities in Kenna. 

Script requires 4 custom fields:

- riskcode = custom field for risk code
- confidence = custom field for confidence
- riskdesc = custom field for risk description
- scandata = custom field for the scanner identification field

The default "notes" fields will be populated with Attack, Evidence and Param data. 

Paramters:

- Kenna token
- directory which contains the scan files
- custom field ID to hold the risk code
- custom field ID to hold the confidence
- custom field ID to hold the risk description
- custom field ID to hold the scan data



Usage:

```
kenna-zap-upload.rb <Kenna API token> <folder location where vuln exports are located> cust_field_id1 cust_field_id2 cust_field_id3 cust_field_id4
```

Tested on:

- ruby 2.3.0p0 (2015-12-25 revision 53290) [x86_64-darwin15]

Required Ruby classes/gems:


- 'rest-client'
- 'json'
- 'nokogiri'
