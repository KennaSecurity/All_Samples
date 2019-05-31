# KDI Generic Transformer

This script will transform csv files into json that can be consumed by the Kenna Data Importer

##  Usage
```
csv_KDI_json.rb source_vuln_file.csv has_header? metafile.csv date_format skip_autoclose? output.json
```
csv_KDI_json.rb => name of the script; note depending on Ruby installation, you may need to prefix name with "ruby"
source_vuln_file.csv => comma delimited file containing vulnerability data to be ingested (note that non-specific header and titles need to be removed)
                        - ensure CVE, CWE, WASC fields mapped have valid entries or be blank (ie. no "-" in the column)
has_header? => either "true" or "false"; defaults to true, does the source csv file have a header row? used to map the columns in metafile.csv
metafile.csv => file used to map source_vuln_file.csv columns; more doc available in that file  
date_format => format of dates in the source file ('%m-%d-%Y %H:%M')
skip_autoclose? => defaults to false, set to false if processing only assets
output.json => name of file that the script writes the final JSON output 


## Meta Data file

Notes are includes regarding fields that are required. Column can reference the column name if the source data file has headers or the column index if there are no headers.

locator column is required and is used to deduplicate data in the script itself. Additional deduplication may occur in Kenna after the upload depend on the set locator preference order.



