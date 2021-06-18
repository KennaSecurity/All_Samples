# KDI Transformer and file uploader
This script does two tasks:
1) It will transform csv files into json that can be consumed by the Kenna Data Importer.
2) It will process all the files in a given folder and upload them, one at a time, to a specific connector.



##  Usage
```
CSV_KDI_json_connector_import.rb source_vuln_file.csv has_header? metafile.csv skip_autoclose? output.json assets_only? domain_suffix?
KennaAPItoken folder_name connector_id file_extension
```

- has_header? => either "true" or "false"; defaults to true, does the source csv file have a header row? used to map the columns in metafile.csv

- skip_autoclose? => defaults to false, set to true if processing only assets because you want to skip the auto_close function which will close vulns when they are not reported on the asset.
- output.json => name of file that the script writes the final JSON output 
- assets_only? => OPTIONAL parameter to indicate to translate ONLY ASSET DATA. Either "true" or "false"; defaults to false
- domain_suffix? => OPTIONAL parameter to provide a domain suffix to append to hostnames. (Still experimental)
- KennaAPItoken Pass your Kenna API token on the command line, or alter the script to read @token from another source as needed.
- foldername: where the converted json file exists
- file_extension:json



## Meta Data file

Notes are includes regarding fields that are required. Column can reference the column name if the source data file has headers or the column index if there are no headers.

locator column is required and is used to deduplicate data in the script itself. Additional deduplication may occur in Kenna after the upload depend on the set locator preference order.
