# Run Connectors

This script will schedule a run of all connectors, by getting a list of connectors from the api, then requesting each to run by id. The connector url is printed as each run is enqueued.

Pass your  Kenna API token on the command line, or alter the script to read @token from another source  as needed.

##  Usage
```
API_run_Connectors.rb KennaAPItoken
```


# Run Connectors Multiple files

This script will process all the files in a given folder and upload them, one at a time, to a specific connector. 

Pass your  Kenna API token on the command line, or alter the script to read @token from another source  as needed.

##  Usage
```
API_run_Connector_multiple_files.rb(or .py) KennaAPItoken folder_name connector_id
```

## API Docs
Connectors endpoint is described at [Kenna](https://api.kennasecurity.com/connector-docs)
