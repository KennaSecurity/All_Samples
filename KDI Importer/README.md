# KDI Generic Transformer

This script will transform csv files into json that can be consumed by the Kenna Data Importer

##  Usage
```
csv_KDI_json.rb source_vuln_file.csv has_header? metafile.csv skip_autoclose?
```
 
has_header? => defaults to true, does the source csv file have a header row? 
skip_autoclose? => defaults to false, set to false if processing only assets


## Meta Data file

Notes are includes regarding fields that are required. Column can reference the column name if the source data file has headers or the column index if there are no headers. 

locator column is required and is used to deduplicate data in the script itself. Additional deduplication may occur in Kenna after the upload depend on the set locator preference order. 



