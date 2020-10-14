# KDI Findings Transformer

This script will transform csv files into json that can be consumed by the Kenna Data Importer - specifically importing to the findings model in Kenna.Appsec. 

##  Usage
```
csv_KDI_json.rb source_vuln_file.csv has_header? metafile.csv skip_autoclose? output.json
```
 
- has_header? => either "true" or "false"; defaults to true, does the source csv file have a header row? used to map the columns in metafile.csv

- skip_autoclose? => defaults to false, set to false if processing only assets.
- output.json => name of file that the script writes the final JSON output 


## Meta Data file

Notes are included regarding fields that are required. Column can reference the column name if the source data file has headers or the column index if there are no headers.

locator column is required and is used to deduplicate data in the script itself. Additional deduplication may occur in Kenna after the upload depend on the set locator preference order.



