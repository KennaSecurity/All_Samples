# Kenna-Bulk-Custom-Field-Update

Kenna CVS import to custom data fields

This script will process a CSV file, retrieve vulnerabilities, then update a custom field on each vulnerability. 

Usage:

    custom_field_update.rb <Kenna API token> <Import data CSV file>
    
    
Tested on:

    ruby 2.0.0p648 (2015-12-16 revision 53162) [universal.x86_64-darwin15]
    
    
Required Ruby classes/gems:

    rest-client
    json
    csv
    ipaddr
