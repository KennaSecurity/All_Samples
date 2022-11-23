import os
import sys
import re
import csv
import json
import argparse
from datetime import datetime

# Global constants
DATE_FORMAT_KDI = "%Y-%m-%d-%H:%M:%S"

# Global variable
verbose = 0

def print_json(json_obj):
    print(json.dumps(json_obj, sort_keys=True, indent=2))

def print_verbose(fence, line):
    if verbose >= fence:
        print(line)
 
# Obtain the command line arguments.
def get_command_line_options():

    # Create the argument parser with a description.
    arg_parser = argparse.ArgumentParser(description="CSV to KDI JSON.")

    # Add the arguments.  The CSV input file is the only required positional parameter.
    arg_parser.add_argument("csv_in",
                            help="CSV to be converted to KDI JSON.")
    arg_parser.add_argument("-a", "--assets_only",
                            dest='assets_only',
                            required=False,
                            action='store_true', help="Create a KDI file with only assets, not vulnerabilities.")
    arg_parser.add_argument("--domain_suffix",
                            dest='domain_suffix',
                            required=False,
                            default="",
                            help="Optional domain suffix for hostnames.")
    arg_parser.add_argument("-m", "--meta_file",
                            dest='meta_file_name',
                            required=False,
                            help="File to map input to Kenna fields.  Default is '<input_file_name_root>_meta.csv'")
    arg_parser.add_argument("-o", "--output_file",
                            dest='output_file_name',
                            required=False,
                            help="Output file containing KDI JSON.  Default is '<input_file_name_root>_kdi.json'")
    arg_parser.add_argument("-p", "--precheck",
                            dest='precheck',
                            required=False,
                            action='store_true',
                            help="Use this parameter to precheck parameters and input file.  (Not currently implemented.)")
    arg_parser.add_argument("-s", "--skip_autoclose",
                            dest='skip_autoclose',
                            required=False,
                            action='store_true',
                            help="If vulnerability not in scan, do you want to close the vulnerability?")
    arg_parser.add_argument("-v", "--verbose",
                            type=int,
                            required=False,
                            default=0,
                            help="Output verbosity level.")

    # Parse and return results.
    args = arg_parser.parse_args()
    return args

# Set the asset tag field base on tags and tag prefixes.
def set_tag_value(asset, row, tags, tag_prefixes):
    if tags is None or len(tags) == 0:
        return False

    prefix_exists = not(tag_prefixes is None or len(tag_prefixes) == 0)

    asset_tags = [] 
    #tags_in_row = set(row).intersection(tags)
    for tag in tags:
        for column in row.keys():
            column = re.sub(r"\A['\"]+|['\"]+\Z", "", column)
            if column != tag:
                continue
            tag_value = row[column]
            if tag_value == None or tag_value == "":
                continue
            if prefix_exists:
                asset_tags.append(tag_prefixes[tags.index(tag)] + tag_value)
            else:
                asset_tags.append(tag_value)

    # If there are no tags
    if len(asset_tags) > 0:
        asset['tags'] = asset_tags
    return True

# Create arrays for tags and tag prefixes from comma separated strings.
def process_tags(field_map):
    if field_map['tags'] is None or field_map['tags'] == "":
        return ([], [])

    tags_array = field_map['tags'].split(',')
    tags_array_len = len(tags_array)

    if field_map['tag_prefix'] is None or field_map['tag_prefix'] == "":
        return (tags_array, [])

    tag_prefix_array = field_map['tag_prefix'].split(',')
    if len(tag_prefix_array) != tags_array_len:
        print(f"WARNING: tags array and tags prefix array lengths are not equal: (len{tag_prefix_array}, {tags_array_len}).")

    return (tags_array, tag_prefix_array)
      
# Read and process the meta mapping file into a dictionary (hash).
def map_fields(mapping_csv_file):
    
    field_map = {}

    # Read the meta mapping map into the field_map dictionary.
    try:
        with open(mapping_csv_file, newline='') as mapping_file:
            reader = csv.reader(mapping_file, delimiter=',')
            for row in reader:
                field_map[row[0]] = row[1]
    except FileNotFoundError:
        print(f"ERROR: Mapfile file, {mapping_csv_file} not found.")
        sys.exit(1)

    # Tags and tag prefixes are a list of strings.  Join them into an array of strings.
    (field_map['tags'], field_map['tag_prefix']) = process_tags(field_map)

    # Mappings within score_map
    if field_map['score_map'] is None or field_map['score_map'] == "":
        print_verbose(1, "score_map is empty")
    else:
        field_map['score_map'] = json.loads(field_map['score_map'])

    # Mappings within status_map
    if field_map['status_map'] is None or field_map['status_map'] == "":
        print_verbose(1, "status_map is empty")
    else:
        field_map['status_map'] = json.loads(field_map['status_map'])

    return field_map

# If the field in the field map has no value, return False.
# If the mapped field does not have a value, print error and return False.
def verify_value(row, field_map, a_field):
    if not a_field in field_map:
        return False
    if field_map[a_field] is None or field_map[a_field] == "":
        return False
    if not field_map[a_field] in row:
        print_verbose(1, f"{field_map[a_field]} is not a CSV row column (key).")
        return False
    if row[field_map[a_field]] is None:
        print_verbose(1, f"{row[field_map[a_field]]} has no value.")
        return False
    
    return True

# Set a value in a dictionary from a field in a field map.
def set_value(a_dict, row, field_map, a_field, to_field=None):
    if not verify_value(row, field_map, a_field):
        return None

    # if the to_field is present, use it instead of a_field.
    to_field = a_field if to_field is None else to_field
    a_dict[to_field] = row[field_map[a_field]] 
    return a_dict[to_field]

# Set a datetime value in a dictionary from a field in a field map.
def set_datetime_value(a_dict, row, field_map, a_field, to_field=None):
    if not verify_value(row, field_map, a_field):
        return None

    # Make a date.
    date_time_in = datetime.strptime(row[field_map[a_field]], field_map['date_format'])
    kdi_date = date_time_in.strftime(DATE_FORMAT_KDI)

    to_field = a_field if to_field is None else to_field
    a_dict[to_field] = kdi_date
    return a_dict[to_field]

# Remove white space and verify against a constant in a list in a dictionary.
# Set a cononical list in the dictionay.
def standardize_and_verify(a_dict, a_field, validating_constant):
    try:
        a_list = a_dict[a_field]
    except KeyError:
        return

    verified_list = []
    a_list_elements = a_list.split(",")

    for element in a_list_elements:
        element =  element.strip()
        if element.startswith(validating_constant):
            verified_list.append(element)

    a_dict[a_field] = ','.join(verified_list)

# Check if an asset exists in the array of assets in the KDI JSON.
# Asset validation occurs when locator type and primary locator match.
# Note: This could be a dictionary, but decided against it, because the
#       dictionary would have to be coverted to an array chewing up more
#       space.  We have CPU cycles to burn.
def asset_exists(locator_type, primary_locator, assets):
    for asset in assets:
        if asset[locator_type] == primary_locator:
            return asset
    return None

# Add a vulnerability to an asset.
def add_vuln_to_asset(asset_vulns, row, field_map):
    vuln = {}

    # The field scanner_type is a special case.
    if field_map['scanner_source'] == "static":
        vuln['scanner_type'] = field_map['scanner_type']
    else:
        set_value(vuln, row, field_map, "scanner_type")
    
    set_value(vuln, row, field_map, "scanner_id", "scanner_identifier")
    set_value(vuln, row, field_map, "details")
    set_datetime_value(vuln, row, field_map, "created", "created_at")

    # The scanner_score field is a special case using score_map.
    try:
        if field_map['score_map'] is None or field_map['score_map'] == "":
            set_value(vuln, row, field_map, "scanner_score")
        else:
            score_map = field_map['score_map']
            vuln['scanner_score'] = score_map[row[field_map['scanner_score']]]
    except KeyError:
        print(f"ERROR: scanner_score key error, {row[field_map['scanner_score']]}.")
        sys.exit(1)
    except ValueError:
        print(f"ERROR: scanner_score value, {row[field_map['scanner_score']]}, is not a integer.")
        sys.exit(1)

    set_datetime_value(vuln, row, field_map, "last_fixed", "last_fixed_on")
    if field_map['last_seen'] == "":
        vuln['last_seen'] = datetime.now().strftime(DATE_FORMAT_KDI)
    else:
        set_datetime_value(vuln, row, field_map, "last_seen", "last_seen_at")

    # The status field is a special case using status_map.
    try:
        if field_map['status_map'] is None or field_map['status_map'] == "":
            set_value(vuln, row, field_map, "status")
        else:
            status_map = field_map['status_map']
            vuln['status'] = status_map[row[field_map['status']]]
    except KeyError:
        print(f"ERROR: status key error, {row[field_map['status']]}.")
        sys.exit(1)
    
    set_datetime_value(vuln, row, field_map, "closed", "closed_at")
    set_value(vuln, row, field_map, "port")

    asset_vulns.append(vuln)

# Create an asset entry in the KDI JSON dictionary.
def create_asset(row, kdi_json, field_map, host_domain_suffix, assets_only):
    asset = {}

    set_value(asset, row, field_map, "file")
    set_value(asset, row, field_map, "ip_address")
    set_value(asset, row, field_map, "mac_address")
    hostname = set_value(asset, row, field_map, "hostname")
    #if hostname != None and hostname != "" and host_domain_suffix != None and host_domain_suffix != "":
    #    asset['hostname'] += f".{host_domain_suffix }"
    if (hostname == None or hostname == "") and (host_domain_suffix == None or host_domain_suffix == ""):
        pass
    else:
        asset['hostname'] = f"{hostname}.{host_domain_suffix }"

    set_value(asset, row, field_map, "ec2")
    set_value(asset, row, field_map, "netbios")
    set_value(asset, row, field_map, "url")
    set_value(asset, row, field_map, "fqdn")
    set_value(asset, row, field_map, "external_id")
    set_value(asset, row, field_map, "database")
    set_value(asset, row, field_map, "container_id")
    set_value(asset, row, field_map, "image_id")
    
    # Get the locator from the field map. and set the value.
    locator_type = field_map['locator']
    if locator_type == None or locator_type == "":
        print(f"ERROR: no locator in field map (meta map)")
        sys.exit(1)

    # Check if the asset has a valid primary asset.
    #primary_locator = set_value(asset, row, field_map, locator_type)
    primary_locator = asset[locator_type]
    if primary_locator == None or primary_locator == "":
        print(f"ERROR: No primary locator specified for locator type {locator_type}.")
        sys.exit(1)
    
    # Check if the asset exists.
    possible_asset = asset_exists(locator_type, primary_locator, kdi_json['assets'])
    if possible_asset == None:
        # The tag field is not mapped.  The value is an array of tags.
        set_tag_value(asset, row, field_map['tags'], field_map['tag_prefix'])
    
        set_value(asset, row, field_map, "application")
        set_value(asset, row, field_map, "owner")
        set_value(asset, row, field_map, "os")
        set_value(asset, row, field_map, "os_version")
        set_value(asset, row, field_map, "priority")

        # Append new asset into the KDI and initialize the vulns section.
        kdi_json['assets'].append(asset)
        asset['vulns'] = []

    else:
        asset = possible_asset

    if not assets_only:
        add_vuln_to_asset(asset['vulns'], row, field_map)


# Check if a vulnerability exists in the array of vuln_defs in the KDI JSON.
# Vulnerability validation occurs when both the scanner type and scanner ID match.
# Note: This could be a dictionary, but decided against it, because the
#       dictionary would have to be coverted to an array chewing up more
#       space.  We have CPU cycles to burn.
def vuln_exists(scanner_type, scanner_id, vuln_defs):
    for vuln_def in vuln_defs:
        if vuln_def['scanner_type'] == scanner_type and vuln_def['scanner_identifier'] == scanner_id:
            return vuln_def
    return None

# Create a vulnerabilitiy definition entry in the KDI JSON dictionary.
def create_vuln_def(row, kdi_json, field_map):
    vuln_def = {}

    if field_map['scanner_source'] == "static":
        vuln_def['scanner_type'] = field_map['scanner_type']
    else:
        set_value(vuln_def, row, field_map, "scanner_type")
    scanner_id = set_value(vuln_def, row, field_map, "scanner_id", "scanner_identifier")
    
    # If vulnerability already exists, then don't add it to the vuln_def array.
    possible_vuln = vuln_exists(vuln_def['scanner_type'], scanner_id, kdi_json['vuln_defs'])
    if possible_vuln != None:
        return

    set_value(vuln_def, row, field_map, "cve_id", "cve_identifiers")
    standardize_and_verify(vuln_def, "cve_identifiers", "CVE")

    set_value(vuln_def, row, field_map, "wasc_id", "wasc_identifiers")
    standardize_and_verify(vuln_def, "wasc_identifiers", "WASC")

    set_value(vuln_def, row, field_map, "cwe_id", "cwe_identifiers")
    standardize_and_verify(vuln_def, "cwe_identifiers", "CWE")

    set_value(vuln_def, row, field_map, "name")
    set_value(vuln_def, row, field_map, "description")
    set_value(vuln_def, row, field_map, "solution")

    kdi_json['vuln_defs'].append(vuln_def)

# Process the CSV input file into a KDI JSON dictionary.
def process_input_file(csv_input_file_name, kdi_json, field_map, host_domain_suffix, assets_only):

    try:
        with open(csv_input_file_name, newline='') as input_file:
            reader = csv.DictReader(input_file, delimiter=',')
            for row in reader:
                create_asset(row, kdi_json, field_map, host_domain_suffix, assets_only)
                if assets_only:
                    continue
                create_vuln_def(row, kdi_json, field_map)
    except FileNotFoundError:
        print(f"ERROR: CSV input file, {csv_input_file_name} not found.")
        sys.exit(1)

if __name__ == "__main__": 
    args = get_command_line_options()

    # Get the input and output file names.
    csv_input_file_name = args.csv_in
    csv_input_file_root = os.path.splitext(csv_input_file_name)[0]

    # Get the meta file name and the host domain suffix.
    json_output_file_name = csv_input_file_root + "_kdi.json" if not args.output_file_name else args.output_file_name
    meta_file_name = csv_input_file_root + "_meta.csv" if not args.meta_file_name else args.meta_file_name
    host_domain_suffix = args.domain_suffix

    # Get the flags.
    skip_autoclose = args.skip_autoclose
    assets_only = args.assets_only
    precheck = args.precheck
    verbose = args.verbose

    print_verbose(1, f"Input CSV: {csv_input_file_name}  Output JSON: {json_output_file_name}")
    print_verbose(1, f"Meta Input File: {meta_file_name}  Domain Suffix: {host_domain_suffix}")
    print_verbose(1, f"skip_autoclose: {skip_autoclose}  assets_only: {assets_only}  precheck: {precheck}")
    print_verbose(1, "")

    field_map = map_fields(meta_file_name)
    if verbose >= 2:
        print(f"Field map:")
        print_json(field_map)

    # Create a KDI JSON dictionary. Since there is no `version`, it is version 1.
    kdi_json = {}
    kdi_json['skip_autoclose'] = skip_autoclose
    kdi_json['assets'] = []
    kdi_json['vuln_defs'] = []

    process_input_file(csv_input_file_name, kdi_json, field_map, host_domain_suffix, assets_only)

    kdi_output = json.dumps(kdi_json, indent=2)

    with open(json_output_file_name, 'w') as writer:
        writer.write(kdi_output)
