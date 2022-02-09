# Risk Meter Listing

The script pulls details of the risk meters available to an account, and saves this information in a csv file.  

## Usage Instructions 
Use the --help or -h argument to call the help page below.

```
Usage: risk_meter_listing_extract.rb -t your_API_token
    -t, --token=TOKEN                Mandatory argument. API token for the account making API calls
```

The -t, --token argument is mandatory for making the API calls. The script creates a file called 'risk_meter_listing.csv' in the same directory. 


### Sample output
```
ruby risk_meter_listing_extract.rb -t your_api_token

The details of 55 risk meters over 2 pages will now be downloaded
Querying page 1 of 2
Querying page 2 of 2
Script completed successfully! Check file 'risk_meter_listing.csv' for your report
```

## Dependencies
### language
- ruby

### gems/classes
- json
- rest-client
- csv
- optparse
