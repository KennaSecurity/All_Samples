This script will help you bulk create new applications 


All you need is 
1) The script
2) API token
3) csv file that has two columns ( Application name and application identifiers).
4)  NB the application identifiers are comma separated. I attached a sample csv file for your reference ( application_listing)
 
Here is the command line that you can use to run the script:
ruby bulk_application_create.rb <API token> application_list_source_file.csv
