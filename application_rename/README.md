This script will help rename applications in bulk in such a way that applications and assets are not duplicated, as well as preserving the reporting history of those applications. 

The script takes in a csv file which holds the application IDs of those applications, as well as the proposed name changes for the application name (folder structure) as well as the application identifier. In most scenarios, application name and application identifier name will be the same. 

Usage: "ruby appsec_application_rename.rb <API_token> rm_change_file.csv"

Requirements: 
language: ruby
modules: rest-client, json, csv 
