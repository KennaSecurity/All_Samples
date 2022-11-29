# Ruby and Python CSV to KDI JSON Tests

This directory contains tests that compare the KDI JSON output between the Ruby and CSV to KDI JSON
transformers.  The `execute_test` bash script executes `csv_KDI_json.rb` and `csv_to_kdi.py` with
specific inputs and compares the outputs.

## Inputs

Each test directory must contain:

- input_data.csv - The input data to be transformed.
- meta_map.csv - Maps the input data headers to KDI headers.

Optionally there is `params.config` which contains the optional parameters to be used in the test.

## Outputs

If the script run successfully, the following outputs are produced:

- ruby_kdi.json
- py_kdi.json

## Comparison

The diff is done by executing `diff_json.py`, which loads the JSON from `ruby_kdi.json` and
`py_kdi.json`, orders it, and compares the ordered JSON.

## Execution

`./execute_test <test_directory>`

Example:
`./execute_test no_tags`

