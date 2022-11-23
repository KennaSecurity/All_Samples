import sys
import json

def print_help(prog_name):
    print(f"{prog_name} <json_file1> <json_file2>")
    sys.exit(1)

# Recursively sorts any lists it finds (and convert dictionaries to 
# lists of (key, value) pairs so that they're orderable):
# From: https://stackoverflow.com/questions/25851183/how-to-compare-two-json-objects-with-the-same-elements-in-a-different-order-equa
def ordered(obj):
    if isinstance(obj, dict):
        return sorted((k, ordered(v)) for k, v in obj.items())
    if isinstance(obj, list):
        return sorted(ordered(x) for x in obj)
    else:
        return obj

if __name__ == "__main__": 
    if len(sys.argv) != 3:
        print(f"Argument length should be 3 ({len(sys.argv)})")
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

    ordered_json_data1 = ordered(json_data1)
    ordered_json_data2 = ordered(json_data2)
    if ordered_json_data1 != ordered_json_data2: 
        print(f"{json_file1} and {json_file2} have diferences.  Please manually check.")
        sys.exit(1)

    # Files match!
    sys.exit(0)
