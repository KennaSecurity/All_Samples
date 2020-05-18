# clear due dates

These Scripts will clear out all due dates from an instance

clear due date = uses data extract to retrieve all vulns - good for smaller data sets
clear due date via assets = uses list of assets to portion out updates into batches for better performance on larger files

Usage:

clear_due_date.rb KennaAPItoken
clear_due_date_via_assets.rb KennaAPItoken numberofassets

number of assets: int number of assets to be pulled in each group. Number should be low enough to that vuln pull is less than 20 pages. Error will be thrown if vuln pull exceeds 20 pages. Expected range 15-30 assets. 


Tested on:

ruby 2.6.3p62 (2019-04-16 revision 67580) [universal.x86_64-darwin19]

Required Ruby classes/gems:

rest-client
