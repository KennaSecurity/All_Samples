This script will create risk meters from a csv file. Each risk meter must define a name and an unencoded query string. API base URL is api.kennasecurity.com. Edit the code if this is not the correct base URL for you. URL explanations can be found in the API documentation, or by contacting your account representative/support.

Usage: "add_risk_meters.rb <API Token> csvfilename.csv"

Requirements:

ruby
rest-client
json
csv

Tested on: ruby 2.7.2p137 (2020-10-01 revision 5445e04352) [x64-mingw32]
