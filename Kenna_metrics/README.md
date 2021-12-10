# Kenna_metrics

This script will loop through all existing Risk Meters (or a defined list) and output 
1. Risk Meter score 
2. Scores and diffs for week, month and 90 days ago
2. MTTR based on input date range parameter

Usage:

get_metrics.rb KennaAPItoken csvfilename meterlist daterange

csvfilename: desired output filename and location will append existing file if it already exists

meterlist: csv where first column is risk meter id. Script with pull data for each risk meter listed.

daterange: See API page for formatting of daterange data or use keyword: previous_month to automatically set the date range for the previous month. 

Tested on:

ruby 2.6.3p62 (2019-04-16 revision 67580) [universal.x86_64-darwin19]

Required Ruby classes/gems:

rest-client
json
csv
