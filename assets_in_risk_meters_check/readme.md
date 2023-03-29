# Assets in risk meter check

Generate a tag for all assets in a risk meter.

This script will process a metadata CSV file to create tags for all assets in requested risk meters. From the UI, a search can then be done to find all asset NOT in a risk meter. It is recommended that the same prefix be used for all tags. Example: RM:1, RM:2, RM:3. This will allow for easier removal of tags and easiers searching in the UI. If tag\_reset feature is turned on for the connector, they tags will be automatically cleared for all active assets. If not the Tag Remover script can be run to remove the tag from all assets.  

## Usage:

    assets_in_risk_meters_check.rb <Kenna API token> <risk meter meta data.csv> <risk_meter_column> <tagname_column>
    
### Tested on:

    ruby 2.6.10p210 (2022-04-12 revision 67958) [universal.x86_64-darwin22]
    
### Required Ruby classes/gems:

    rest-client
    json
    csv
    thread
    monitor

