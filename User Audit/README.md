# Kenna User Audit

Python script - `useraudit.py` will output all of the users and roles for the client into a single Excel spreadsheet. Users which have never logged in are highlighted in red, while users who have not logged in over the past 30 days are highlighted in yellow.

The script assumes standard US date formatting for use in Excel (i.e. m/d/YYYY). Users with European or other default date formats will want to modify the date format in the script to their locale.

Python script - `audit_test_full.py` will perform all the actions listed in the 'useraudit.py' script above in addition to providing the details on users that have "source" as "API" in "Audit Logs" and used their key in the stipulated audit period listed as step #3 in the *updates/edits needed to execute the script* section below.

Tested on Python version 3.9.6. Please see requirements.txt for full dependency list.

## Installation

`pip install -r requirements.txt`

## Usage

`python useraudit.py <API_TOKEN>`

`python audit_test_full.py`

## Updates/Edits needed to execute the "audit_test_full.py" script

### 1: Update the base_url 
By default, https://api.kennasecurity.com/ is being used. Update it to w.r.t your environment.

### 2: API Key Token
Set an environment variable named API_KEY with your actual API key as its value. The way you do this can vary depending on your operating system and the interface you're using (command line, graphical interface, etc.).
#### Windows:
You can set an environment variable in Windows using the setx command in the command prompt:
*setx API_KEY "your-api-key"*

#### Mac OS or Linux:
In macOS or Linux, you can set an environment variable in the terminal using the export command:
*export API_KEY=your-api-key*

### 3: Fetch Audit Logs 
Update the start_date (Line #70) and end_date (Line #71) in the script as per the time period you want to pull the logs for. Based on this time period, the script will check which user used their API keys in that time frame.
