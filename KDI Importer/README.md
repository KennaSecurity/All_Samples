# KDI Generic Transformer

This script will transform csv files into json that can be consumed by the Kenna Data Importer. This copy has been updated to optionally import asset data only.

**UPDATE: This has been updated from our original KDI Transformer script that has been updated to help with Asset-Only imports.**

Note: This script can still be used like the original, but just omitting the last two parameters when running.

##  Usage
```
csv_KDI_json.rb source_vuln_file.csv has_header? metafile.csv skip_autoclose? output.json assets_only? domain_suffix?
```
 
- has_header? => either "true" or "false"; defaults to true, does the source csv file have a header row? used to map the columns in metafile.csv

- skip_autoclose? => defaults to false, set to true if processing only assets because you want to skip the auto_close function which will close vulns when they are not reported on the asset.
- output.json => name of file that the script writes the final JSON output 
- assets_only? => OPTIONAL parameter to indicate to translate ONLY ASSET DATA. Either "true" or "false"; defaults to false
- domain_suffix? => OPTIONAL parameter to provide a domain suffix to append to hostnames. (Still experimental)


## Meta Data file

Notes are includes regarding fields that are required. Column can reference the column name if the source data file has headers or the column index if there are no headers.

locator column is required and is used to deduplicate data in the script itself. Additional deduplication may occur in Kenna after the upload depend on the set locator preference order.



