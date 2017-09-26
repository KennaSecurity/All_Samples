# Email Top Fixes

This script will email CSV files of Top Fixes for each risk meter listed

Email Top Fixes mimics the report you get the UI today. 

Email Top Fixes Plus addes Patch Published Date and Scanner IDs to the csv file. Extra API calls so report generation will take slightly longer. 

Usage:

email_top_fixes.rb KennaAPItoken email_meta_file smtp_mail_server smtp_port smtp_user smtp_password email_from_address

Tested on:

ruby 2.3.0

Required Ruby classes/gems:

rest-client
json
csv
mail

# Plus version adds Scanner IDs and fix pubish date
# Export is the per-Asset report without email
# Summary Export is a per-Fix report without email
