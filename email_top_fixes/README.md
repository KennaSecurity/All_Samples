# Email Top Fixes

This script will generate a CSV of Top Fixes for each risk meter listed and will optionally email the CSV files to a list of recipients and add a due date and optional custom field values to each vulnerability associated with the top fixes. 

Email Top Fixes mimics the report you get the UI today but can optionally add scanner id and fix published date.

Usage:

email_top_fixes.rb KennaAPItoken email\_meta\_file include\_extra\_columns due\_date\_column custom\_field\_meta top\_fix\_count\_column send\_mail? smtp\_mail\_server smtp\_port smtp\_user smtp\_password email\_from\_address

- Kenna API token
- email meta file = data file with minimum of risk meter id (col1)
- include extra columns = true to include patch_published_date and scanner\_ids in output
- due date column = column in email meta file that holds number of days ahead that should be used to set due date when email is sent current data + value stated in column
- custom field meta = csv file with any extra columns that should be put into custom fields 1st is column in email meta file that holds the data and 2nd is custom field id.
- top fix count column = column in the email meta file which says how many top fix groups to send starting 3 returns 1st 3, 5 returns 1st 5
- send email = true or false. if false no other params needed
- recipient column (optional) = column in email meta file that holds the email address to receive the csv file for a specific risk meter. Multiple email addresses can be separate with a semi-colon. 
- mail server (optional) = mail server location
- port (optional) = port on mail server for sending mail
- user name (optional) = user name for mail server
- password (optional) = passwordfor mail server
- from address (optional) = email address to be used in from field

Tested on:

ruby 2.3.0

Required Ruby classes/gems:

rest-client
json
csv
mail

# Summary Export is a per-Fix report without email

Usage:

email\_top\_fixes.rb KennaAPItoken email\_meta\_file (risk meter ids only) 
