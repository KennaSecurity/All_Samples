# Kenna_metrics

This script will loop through all existing Risk Meters and output 
1. Risk Meter score 
2. MTTR based on input date range parameter

Usage:

get_metrics.rb KennaAPItoken csvfilename daterange

daterange:

See API page for formatting of daterange data or use keyword: previous_month to automatically set the date range for the previous month. 

Tested on:

ruby 2.0.0p648 (2015-12-16 revision 53162) [universal.x86_64-darwin15]

Required Ruby classes/gems:

rest-client
json
csv
