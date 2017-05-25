# Run Connectors

This script will schedule a run of all connectors, by getting a list of connectors from the api, then requesting each to run by id. The connector url is printed as each run is enqueued.

Pass your  Kenna API token on the command line, or alter the script to read @token from another source  as needed.

##  Usage
```
API_run_Connectors.rb KennaAPItoken
```

## API Docs
Connectors endpoint is described at [Kenna](https://api.kennasecurity.com/connector-docs)
