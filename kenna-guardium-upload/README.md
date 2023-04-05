# Kenna - Guardium vuln upload

This script will search for a provided directory for Guardium export results and loop through all <host> elements to create vulnerabilities in Kenna. 

Script requires three custom fields:

- scanner (type String)
- vendor (type String)

Recommended that at least scanner and vendor fields be selected for search capability. 

scanner will always = Guardium, vendor will be populated by the data from the XML

The default "notes" fields will be populated with Port, ServiceName and Version. 

Paramters:

-Kenna token
-directory which contains the scan files
-custom field ID to hold the Scanner data ("Guardium")
-custom field ID to hold the Vendor data
-case change option for hostname = upcase, downcase or nochange



Usage:

```
kenna-guardium-upload.rb <Kenna API token> <folder location where vuln exports are located>
```

Tested on:

- ruby 2.3.0p0 (2015-12-25 revision 53290) [x86_64-darwin15]

Required Ruby classes/gems:


- 'rest-client'
- 'json'
- 'nokogiri'
