# Average Risk Meter scores for Time Period

This script queries the Cisco VM API, and for the provided risk meter ID, retrieves the historical risk meter scores for a time period and calculates the average risk meter score for that time period.   

## Usage Instructions 
Use the --help or -h argument to view the help page below.

```
Usage: risk_meter_average.rb -t YOUR_API_TOKEN -i ASSET_GROUP_ID [options]
    -t, --token=TOKEN       Mandatory argument. API token for the account making API calls
    -i, --id=ID             Mandatory argument. Asset group ID for querying risk meter scores
    -b, --base_url=URL      Optional argument. Custom base URL (e.g., api.kennasecurity.com)
    -s, --start_date=DATE   Optional argument. Custom start date (YYYY-MM-DD)
    -e, --end_date=DATE     Optional argument. Custom end date (YYYY-MM-DD)
```

The `-t`, `--token` and `-i`, `--id` arguments are mandatory for running the script. By default, the script calculates the average risk meter score for the specified risk meter for the last 7 days, however, you can also provide a start and an end date for the calculation. The API endpoint defaults to 'api.kennasecurity.com' but you can provide your applicable base API URL using the '-b' parameter. 


### Sample output
**Running the script without optional parameters **
```
ruby risk_meter_average.rb -t YOUR_API_TOKEN -i ASSET_GROUP_ID

# Output:
Average risk meter score for the period YYYY-MM-DD to YYYY-MM-DD: SCORE

```

**Running the script with a custom base URL and custom date range **
```
ruby risk_meter_average.rb -t YOUR_API_TOKEN -i ASSET_GROUP_ID -b api.customurl.com -s 2025-04-02 -e 2025-04-09

# Output:
Average risk meter score for the period 2025-04-02 to 2025-04-09: SCORE

```

**Running the script for a risk meter with no results in the time-frame **
```
# Output: 
Risk meter does not have any results for the specified date range YYYY-MM-DD to YYYY-MM-DD.

```


## Dependencies
### language
- ruby

### gems/classes
- json
- rest-client
- optparse
- date
