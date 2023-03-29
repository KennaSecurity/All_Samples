# Clear Due Dates

These scripts will clear out all due dates from an instance:

* `clear_due_date.rb`: uses data exports to retrieve all vulnerabilities - good for smaller data sets
* `clear_due_date_via_assets.rb`: uses list of assets to portion out updates into batches for better performance on larger files

Data export APIs are used to obtain the data.

## Usage:

    clear_due_date.rb <KennaAPItoken>
    clear_due_date_via_assets.rb <KennaAPItoken> <number-of-assets>

number of assets: int number of assets to be pulled in each group. Number should be low enough to that vuln pull is less than 20 pages. Error will be thrown if vuln pull exceeds 20 pages. Expected range 15-30 assets. 

### Tested on:

    ruby 2.6.10p210 (2022-04-12 revision 67958) [universal.x86_64-darwin22]

### Required Ruby classes/gems:

    rest-client
    json
