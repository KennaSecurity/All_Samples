# Kenna - Guardium vuln upload

This script will search for a provided directory for Guardium export results and loop through all <host> elements to create vulnerabilities in Kenna. 

Script requires three custom fields:

- scanner (type String)
- lastSeen (type Date)
- vendor (type String)

Recommended that at least scanner and vendor fields be selected for search capability. 

scanner will always = Guardium, the other two fields will be populated by the data from the XML

#Script must be changed to use Custom Field id's which will be different for each Kenna customer.

The default "notes" fields will be populated with Port, ServiceName and Version. 


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
