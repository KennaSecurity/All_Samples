import os
import sys
import json

def print_help(prog_name):
    print(f"{prog_name} <json_file1> <json_file2>")
    sys.exit(1)

# Dumps ordered json data into a file.
def dump_ordered_json(ordered_json_data, file_path):
    (file_name, suffix) = os.path.splitext(file_path)
    ordered_json_file = f"{file_name}_ordered{suffix}" 

    with open(ordered_json_file, 'w') as ojf_fp:
        json.dump(ordered_json_data, ojf_fp, sort_keys=True, indent=2)

    return ordered_json_file

# Process None for an item or tuple.
def none_sorter(item):
    if item is None:
        return ""
    if isinstance(item, tuple) and item[1] is None:
        return (item[0], "")
    return item

# Recursively sorts any lists it finds (and convert dictionaries to 
# lists of (key, value) pairs so that they're orderable):
# From: https://stackoverflow.com/questions/25851183/how-to-compare-two-json-objects-with-the-same-elements-in-a-different-order-equa
def ordered(obj):
    # This check for None allowed the `sorted((ordered(x) for x in obj), key=none_sorter)`
    # to not get a TypeError.  I think the statement ends the recursion.
    if obj is None:
        return ""

    if isinstance(obj, dict):
        return sorted(((k, ordered(v)) for k, v in obj.items()), key=none_sorter)
    if isinstance(obj, list):
        return sorted((ordered(x) for x in obj), key=none_sorter)
    else:
        return obj

if __name__ == "__main__": 
    if len(sys.argv) != 3:
        print(f"{sys.argv[0]} should have 2 arguments.  It has {len(sys.argv)}")
        print_help(sys.argv[0])

    # Get the file names and intialisze dictionaries.
    json_file1 = sys.argv[1]
    json_file2 = sys.argv[2]
    json_data1 = {}
    json_data2 = {}

    # Open file 1 and decode.
    try:
        with open(json_file1, 'r') as jf1:
            json_data1 = json.load(jf1)
    except json.JSONDecodeError as jde:
        print(f"JSON decode error: {jde.msg}")
        print(f"file: {jde.doc}")
        print(f"At line {jde.lineno}, position {jde.pos}, column {jde.colno}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"{json_file1} not found")
        sys.exit(1)

    if len(json_data1) == 0:
        print("No JSON in {json_file1")
        sys.exit(1)
        
    # Open file 2 and decode.
    try:
        with open(json_file2, 'r') as jf2:
            json_data2 = json.load(jf2)
    except json.JSONDecodeError as jde:
        print(f"JSON decode error: {jde.msg}")
        print(f"file: {jde.doc}")
        print(f"At line {jde.lineno}, position {jde.pos}, column {jde.colno}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"{json_file2} not found")
        sys.exit(1)

    if len(json_data2) == 0:
        print("No JSON in {json_file2")
        sys.exit(1)

    # Let's do a length compare for grins.
    if len(json_data1) != len(json_data2):
        print(f"Data length {len(json_data1)} from {json_file1} is not equal to data length {len(json_data2)} from {json_file2}")
        print(f"Continuing with diff")

    ordered_json_data1 = ordered(json_data1)

    ordered_json_data2 = ordered(json_data2)
    
    # Now diff the JSON data.
    if ordered_json_data1 != ordered_json_data2: 
        ordered_json_file1 = dump_ordered_json(ordered_json_data1, json_file1)
        ordered_json_file2 = dump_ordered_json(ordered_json_data2, json_file2)
        print(f"{json_file1} and {json_file2} have diferences.")
        print(f"Please manually check {ordered_json_file1} and {ordered_json_file2}")
        sys.exit(1)

    # Files match!
    sys.exit(0)
