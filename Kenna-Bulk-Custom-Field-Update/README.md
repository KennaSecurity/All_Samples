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


# Kenna-Bulk-Custom-Field-Update-mt

Kenna CVS import to custom data fields using multi-threading

This script will process a CSV file, retrieve vulnerabilities, then update a custom field on each vulnerability. 

Usage:

    custom_field_update.rb <Kenna API token> <Import data CSV file> <meta file for custom fields> <vuln type> <vuln column in data file> <host lookup type> <IP column in data file> <hostname column in data file> 
    
    
Tested on:

    ruby 2.0.0p648 (2015-12-16 revision 53290) [universal.x86_64-darwin15]
    
    
Required Ruby classes/gems:

    rest-client
    json
    csv
    ipaddr
    thread
    monitor
    
Expected Parameters:

    @token = ARGV[0] #kenna customer API token
    @csv_file = ARGV[1] #source data
    @data_column_file = ARGV[2] #custom field id's and names of corresponding columns in source data
    @vuln_type = ARGV[3] # cve or cwe or wasc or scanner_id or vuln_id or empty string
    @vuln_column = ARGV[4] # column that holds the vuln key or empty string
    @host_search_field = ARGV[5] #field to use first for asset match ip_address or hostname or empty string
    @ip_address = ARGV[6] #column name in source file which holds the ip data or empty string
    @hostname = ARGV[7] #column name in source file which holds the hostname data or empty string
    
Available for Modification on the code:

    @debug #set to true to have additional debug lines sent to the console
    thread_count #set to 8 by default. Too high and code will be inefficient due to retries (max API calls 3/second), too low max API limit won't be hit. 
