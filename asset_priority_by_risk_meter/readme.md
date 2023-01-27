# Asset Priority By Risk Meter

Set All Assets in a given Risk Meter to a priority

This script will process a CSV file to set all assets in each listed risk meter to the specified priority.
It is multi-threaded.

Usage

    kenna-priority-by-risk-meter.rb <Kenna API token> <CSV file> [<risk meter ID column name> <risk meter priority column name>]
    
    <risk meter ID column name> is optional and defaults to "rmid".
    <risk_meter priority column name> is optional and defaults to "priority".
    
Tested on:

    ruby 2.6.10p210 (2022-04-12 revision 67958) [universal.x86_64-darwin22]
    
Required Ruby classes/gems:

    rest-client
    json
    csv
    ipaddr
    thread
    monitor

