# Kenna External Vuln uploader API script

This script will upload vulnerabilities to Kenna. Vulnerabilities must be designated with a CVE, CWE or WASC identifier.
Extra data may be included as custom field data or merged into the Kenna notes field using meta files as displayed
in the included sample files.

Usage:

```
kenna-asset-tagger.rb <Kenna API token> <CSV file of vulns> <CSV file with custom field ids> <primary locator type> <primary locator column> 
<vulnerability type> <vulnerability column> <CVS file with columns for notes field> <preferred case for hostname><last seen column> <first found column> 
<due date column>
```

Parameters:
-data_file = CSV of vulnerability data to be uploaded into Kenna
-custom_field_meta = CSV of column names in data and what custom field to put them in 
-primary_locator = static string either hostname or ip_address or url or application
-locator_column = column in csv that has primary locator info (actual ip, hostname or url)
-vuln_type = cve or cwe or wasc
-vuln_column = column that holds the vuln key for each row
-notes_meta = CSV of column names to be included in notes and prefix to denote the various items
-hostcase = forced case for hostname (upcase, downcase) or nochange (recommended)
-last_seen_column = column in CSV which contains the last seen date of the vulnerability
-first_found_column = column in CSV which contains the first found data of the vulnerability
-due_date_column = column in CSV which contains the due date for the vulnerability

Debug flag available in ruby code to flip on detailed debugging code. 


Tested on:

- ruby 2.0.0p648 (2015-12-16 revision 53162) [universal.x86_64-darwin15]

Required Ruby classes/gems:

- [`rest-client`](https://github.com/rest-client/rest-client)
- [`json`](http://ruby-doc.org/stdlib-2.0.0/libdoc/json/rdoc/JSON.html)
- [`csv`](http://ruby-doc.org/stdlib-2.0.0/libdoc/csv/rdoc/CSV.html)
