This script can be used for many purposes


  1) Bulk Create new applications if they don't exist in Kenna instance
  2) If the application name exists in the csv file
     a) If the application name exists in Kenna instance, the script will compare the identifier in the csv file vs the one in the instance
     b) If the identifier are the same, then no action
     c) If the identifiers are different, then will append the new identifier to the old one(s)
  3) If the identifier is blank in the application_listing.csv, the application won’t get created. An identifier is a must to create the application ( This is how Kenna works)
  4) The script can also delete the existing applications if the application name is same as identifier name
  5) 

The script is written in Ruby.
To run the script, use this command line as an example

# These are the arguments we are expecting to get.
@token = ARGV[0]
@csv_file = ARGV[1]
@create_apps = ARGV[2] #true or false
@Delete_apps_with_name_same_as_identifier = ARGV[3] #true or false


ruby bulk_application_create_delete_apps_same_identifier_update_identifiers_v2.rb <token> Application_listing.csv <true/false> <true/false>
