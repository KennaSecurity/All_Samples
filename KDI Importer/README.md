# KDI Generic Transformer

This script will transform csv files into json that can be consumed by the Kenna Data Importer

##  Usage
```
csv_KDI_json.rb source_vuln_file.csv has_header? metafile.csv date_format skip_autoclose?
```
 
has_header? => defaults to true, does the source csv file have a header row? 
date_format => format of dates in the source file ('%m-%d-%Y %H:%M')
skip_autoclose? => defaults to false, set to false if processing only assets

