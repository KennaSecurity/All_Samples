# Asset Inactivation By Risk Meter

Set All Assets in a given Risk Meter set to inactive

This script will process a meta data file to set all assets in each listed risk meter to inactive

Usage:

    asset_inacivation-by-risk-meter.rb <Kenna API token> <risk meter meta data.csv> risk_meter_column
    
Tested on:

    ruby 2.0.0p648 (2015-12-16 revision 53162) [universal.x86_64-darwin15]
    
    
Required Ruby classes/gems:

    rest-client
    json
    csv
    ipaddr
    thread
    monitor

