# Download Kenna Fixes sorted by total risk score

Kenna's user interface sorts Fixes by commonality, or the number of assets needing the fix. This is helpful for patching purposes, but the default sorting does not lend itself well to risk reduction acivities.

This script will download each of your fixes in Kenna, multiply the count of vulnerabilities associated with the fix by the highest risk score of any of those vulnerabilities, then sorts the list of fixes by the calculated risk amount.

Please note that due to the complexities of Kenna's scoring algorithm, applying these fixes may not immediately drive a direct correlation to reduced risk meter scores in Kenna. This script will, however, give you a general sense of overall risk reduction for each fix in your environment. You can use this sorted list as a "next best action" guide which over time will deliver serious risk score reduction in your risk meters.

## Dependencies

### Environment

The API token must be defined as a system environment variable `KENNA_API_KEY`

[Linux/Mac Instructions](https://phoenixnap.com/kb/set-environment-variable-mac)

[Windows Instructions](https://docs.oracle.com/en/database/oracle/machine-learning/oml4r/1.5.1/oread/creating-and-modifying-environment-variables-on-windows.html)

### Language

Python 3

## Usage Instructions

#### Requirements Installation

`pip3 install -r requirements.txt`

### Run Script

`python sorted_fixes.py`
