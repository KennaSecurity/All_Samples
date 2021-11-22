This script will create child risk meters from a csv file. Each child risk meter must define a parent risk meter id, name and an unencoded query string. API base URL is api.kennasecurity.com. Edit the code if this is not the correct base URL for you. URL explanations can be found in the API documentation, or by contacting your account representative/support.

Usage: "add_child_risk_meters.rb <API Token> csvfilename.csv"

Requirements:

ruby
rest-client
json
csv


