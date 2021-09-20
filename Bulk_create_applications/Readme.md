This script will help you bulk create new applications 


All you need is 
1) The script
2) API token
3) csv file that has two columns ( Application name and application identifiers).
4)  NB the application identifiers are comma separated. 
5)  A sample csv file of application + identifier is attached for reference
6)  If the applications in the csv exist, no application will be created, only new applications.
 
Here is the command line that you can use to run the script:

ruby bulk_create_applications.rb <API token> <application_list_source_file.csv>
