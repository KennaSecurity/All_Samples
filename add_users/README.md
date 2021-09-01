# Add Users

This script will create users from a csv file. Kenna began to role out support for assigning up to five different roles to a single user on September 1st, 2021. If you have not yet received this update please use the legacy_add_users.rb script instead of add_users_MRPU.rb

Usage:

add_users_MRPU.rb KennaAPItoken usersample.csv

Legacy Usage:

legacy_add_users.rb KennaAPItoken singlerole.csv fname, lname, role, email

Tested on:

ruby 2.0.0p648 (2015-12-16 revision 53162) [universal.x86_64-darwin15]

Required Ruby classes/gems:

rest-client
json
csv
