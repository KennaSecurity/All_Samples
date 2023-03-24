# Asset Inactivation By Risk Meter

Set All Assets in a given Risk Meter set to inactive.

This script uses a metadata CSV file that contains one or more risk meter IDs at a specified column.  Using the risk meter ID, the assets that are in the risk meter are inactived.

## Usage:

    asset_inacivation-by-risk-meter.rb <Kenna API token> <risk meter meta data.csv> risk_meter_column
    
### Tested on:

    ruby 2.6.10p210 (2022-04-12 revision 67958) [universal.x86_64-darwin22]
    
### Required Ruby classes/gems:

    rest-client
    json
    csv
    ipaddr
    thread
    monitor

