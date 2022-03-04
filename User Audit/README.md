# Kenna User Audit

This Python script will output all of the users and roles for the client into a single Excel spreadsheet. Users which have never logged in are highlighted in red, while users who have not logged in over the past 30 days are highlighted in yellow.

The script assumes standard US date formatting for use in Excel (i.e. m/d/YYYY). Users with European or other default date formats will want to modify the date format in the script to their locale.

Tested on Python version 3.9.6. Please see requirements.txt for full dependency list.

## Installation

`pip install -r requirements.txt`

## Usage

`python useraudit.py <API_TOKEN>`
