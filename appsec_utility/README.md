# Kenna AppSec Utility
This script is has been updated to provide some desired functionality when working with Kenna's AppSec product. The functionality includes
Application download
Application consolidation and 
Application Deletion

These functions have been tested with the Findings AppSec model. We do recommend testing out with a small set of applications to determine the script provides the functionality as you would want.  


## Usage
The script contains Help documentation on how the script can be used. Some additional formatting is provided here to aid visibility.

```
ruby .\app_util.rb --help


[!] Utility for the Kenna AppSec Product
[!] The utility can be used for the following purposes
[!] - Download your applications in a CSV format
[!] - Consolidate your application identifiers under one application
[!] - Delete applications no longer wanted in your environment
[!] Please note this is not a Kenna official release
[!] As with all scripts in this repository, test to ensure this helps with the intended functionality as desired


Script Usage: ruby app_util.rb -t your_API_token -o [download | consolidate | delete] [-f csv_meta_file]
    -t, --token=TOKEN                Mandatory argument. API token for the account making API calls

    -o, --operation=OPERATION        Parameter used to specify listing or update functionality
                                     valid operations for the -o flag are "download", "consolidate", and "delete" as defined below

                                     download - option used for downloading all applications. this is the default operation

                                     consolidate - option used to consolidate your applications as specified in the provided file (-f)

                                     delete - option used to delete the application(s) as specified in the profided file (-f)


    -f, --filename=FILENAME          Input file with details of application changes. Required in "consolidate" and "delete" operations

```

Some things to note
- The 'download' operation is the default operation if no options are provided. All applications will be downloaded. 

- A sample metafile for the 'delete' and 'consolidate' operations are provided in this directory. 

- For the 'delete' operation, only the first two columns of the meta file (obsolete_app_name and obsolete_app_id) need to be populated. 

- For the consolidate operation, all fields need to be populated. 

- The metafile is not required for the download operation.

- If you need a list of your application names and ID for use with the consolidate or delete functions, you can download your entire application list, and then obtain the information for the applications you need. 



## Examples

- Download a list of applications in your environment 
`ruby app_util.rb -t your_API_token -o download`


- Delete applications in your environment
`ruby app_util.rb -t your_API_token -o delete -f appsec_meta.csv` 

- Consolidate apps in your environment (deletion of the standalone/obosolete apps will happen as part of the consolidation process)
`ruby app_util.rb -t your_API_token -o consolidate -f appsec_meta.csv` 



## Requirements
### Language
- Ruby

### Gems/Classes
- json
- csv
- optparse
- rest-client
