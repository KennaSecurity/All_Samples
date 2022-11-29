# KDI Generic Transformer

These scripts will transform CSV files into JSON that can be consumed by the
[Kenna Data Importer (KDI)](https://help.kennasecurity.com/hc/en-us/articles/360026413111-Kenna-Data-Importer-JSON-Connector-).. 
This copy has been updated to optionally import asset data only.

## Ruby Usage
```ruby
ruby csv_KDI_json.rb source_vuln_file.csv has_header? metafile.csv skip_autoclose? output.json assets_only? domain_suffix?
```
 
- has_header? => either "true" or "false"; defaults to true, does the source csv file have a header row? used to map the columns in metafile.csv

- skip_autoclose? => defaults to false, set to true if processing only assets because you want to skip the auto_close function which will close vulns when they are not reported on the asset.
- output.json => name of file that the script writes the final JSON output 
- assets_only? => OPTIONAL parameter to indicate to translate ONLY ASSET DATA. Either "true" or "false"; defaults to false
- domain_suffix? => OPTIONAL parameter to provide a domain suffix to append to hostnames. (Still experimental)

## Python Usage
```python
python csv_to_kdi.py [input_file] [option]...

positional arguments:
  csv_in                CSV to be converted to KDI JSON.

optional arguments:
  -h, --help            show this help message and exit
  -a, --assets_only     Create a KDI file with only assets, not vulnerabilities.
  --domain_suffix DOMAIN_SUFFIX
                        Optional domain suffix for hostnames.
  -m META_FILE_NAME, --meta_file META_FILE_NAME
                        File to map input to Kenna fields. Default is '<input_file_name_root>_meta.csv'
  -o OUTPUT_FILE_NAME, --output_file OUTPUT_FILE_NAME
                        Output file containing KDI JSON. Default is '<input_file_name_root>_kdi.json'
  -p, --precheck        Use this parameter to precheck parameters and input file. (Not currently implemented.)
  -s, --skip_autoclose  If vulnerability not in scan, do you want to close the vulnerability?
```

### Python Examples

Get help:
`python csv_to_kdi.py --help`

Process CSV input, `input_data.csv`. Defaults meta file to `input_data_meta.csv` and KDI output to `input_data_kdi.json`.
- `python csv_to_kdi.py input_data.csv`

Process CSV input specifying meta and output files.
- `python csv_to_kdi.py input_data.csv -m meta_map.csv -o kdi_output.json`

Process CSV input specifying meta and output files with assets only.
- `python csv_to_kdi.py input_data.csv -m meta_map.csv -o kdi_output.json -a`

Process CSV input specifying meta and output files with domain suffix.
- `python csv_to_kdi.py input_data.csv -m meta_map.csv -o kdi_output.json --domain_suffix dune.gal`

## Meta Data file

Notes are includes regarding fields that are required. Column can reference the column name if the source data file has headers or the column index if there are no headers.

locator column is required and is used to deduplicate data in the script itself. Additional deduplication may occur in Kenna after the upload depend on the set locator preference order.

