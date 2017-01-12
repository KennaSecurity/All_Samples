# Qualys API call using tags then updating Kenna Assets to Inactive

Script sends a call to the Qualys 2.0 API to get a hosts list by tag

Return xml is parsed to get IP addresses

IP addresses are used to get Kenna Asset ID

Asset ID is used to set asset to inactive. 


qualys_to_Kenna_direct.rb Kenna_API_token qualys_user qualys_pass qualys_tagname_encoded 

Tested on:
ruby 2.0.0p648 (2015-12-16 revision 53162) [universal.x86_64-darwin15]

Required Ruby classes/gems:

rest-client
json
nokogiri
