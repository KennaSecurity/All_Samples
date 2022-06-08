# Vuln Updater Multi-threaded

Kenna CSV import to update vulns using multi-threading

This script will process a CSV file, retrieve vulnerabilities, then update data, including custom fields on each vulnerability targeted. 

Example Usage:

    Kenna-vuln-updater.rb <Kenna API token> <Import data CSV file> <meta file for custom fields> <vuln type> <vuln column in data file> <host lookup type> <IP column in data file> <hostname column in data file> <notes type> <notes value> <duedate> <status type> <status value> <vuln status> <base url>
    
    
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

    @token = ARGV[0]
    @csv_file = ARGV[1] #source data
    @data_column_file = ARGV[2] #custom field id's and columns with data
    @vuln_type = ARGV[3] # cve or cwe or wasc or scanner_id or vuln_id or empty string
    @vuln_column = ARGV[4] # column that holds the vuln key or empty string
    @host_search_field = ARGV[5] #field to use first for asset match ip_address or hostname or empty string
    @ip_address = ARGV[6] #column name in source file which holds the search field data or empty string
    @hostname = ARGV[7] #column name in source file which holds the hostname data or empty string
    @notes_type = ARGV[8] #where notes value will come from - static, column or empty string
    @notes_value = ARGV[9] #set notes based on previous param - value, column name or empty string 
    @due_date = ARGV[10] #column with due date or empty string
    @status_type = ARGV[11] #where status value will come from - static, column or empty string for setting new data
    @status_value = ARGV[12] #set status based on previous param - value, column name or empty string for setting new data
    @vuln_status = ARGV[13] #vuln status all, open or other for retrieval 
    ARGV.length == 15 ? @base_url = ARGV[14] : @base_url = "https://api.kennasecurity.com/"
    
Available for Modification on the code:

    @debug #set to true to have additional debug lines sent to the console
    thread_count #set to 8 by default. Too high and code will be inefficient due to retries (max API calls 3/second), too low max API limit won't be hit. 
