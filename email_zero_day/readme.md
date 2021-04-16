# Email Top Fixes

This script will generate a CSV of Zero Days for a few specific Risk Meters, and will optionally email the CSV files to a list of recipients.
The Risk Meter that contains only Zero Days must have already bein manualy created - More information can be found in our Kenna Defenders Platform. 

Usage:

zero_day_email.rb <KennaAPItoken> report\_meta\_sample.csv <true or false> SMTP\_information.csv <recipients column name from the report_meta_sample.csv> <from address>

- Kenna API token
- report meta sample.csv = data file with the Risk Meter ID and the email recipients for each Risk Meter
- send email = true or false. if false no other params needed
- recipient column (optional) = column in email meta file that holds the email address to receive the csv file for a specific risk meter. Multiple email addresses can be separate with a semi-colon. 
- from address (optional) = email address to be used in from field

Tested on:

ruby 2.7.2

Required Ruby classes/gems:

rest-client
json
csv
mail

# Summary Export is a per-Fix report without email

Usage:

email\_top\_fixes.rb HudsUHi68UHsnkjn report\_meta\_sample.csv true SMTP\_information.csv email_recipients test@test.com
