# Kenna asset tagging API script

This script will add tags and meta data to Kenna assets

Usage:

```
kenna-asset-tagger_mt.rb <Kenna API token> <CSV file of assets and tags> <file of tag columns in CSV to apply or nil><search_field><ip_address><hostname><notes_type><notes_value><owner_type><owner_value><alt_locator><priority_column>
```

Parameters:
 - token = Kenna Application token
 - csv_file = source data file
 - tag_column_file = tag meta data file - column from source file and tag prefix - or nil 
 - search_field = field to use first for asset match ip_address or hostname or application(*) or netbios(*)
 - ip_address = column name in source file which holds the search field data or empty string
 - hostname = column name in source file which holds the hostname data or empty string
 - notes_type = where notes value will come from - static, column or empty string
 - notes_value = set notes based on previous param - value, column name or empty string
 - owner_type = where owner value will come from - static, column or empty string for setting new data
 - owner_value = set owner based on previous param - value, column name or empty string for setting new data
 - alt_locator = (*) column that holds data for either application or netbios in search_field
 - Optional - @priority_column = column that holds priority setting

Tested on:

- ruby 2.0.0p648 (2015-12-16 revision 53162) [universal.x86_64-darwin15]

Required Ruby classes/gems:

- [`rest-client`](https://github.com/rest-client/rest-client)
- [`json`](http://ruby-doc.org/stdlib-2.0.0/libdoc/json/rdoc/JSON.html)
- [`csv`](http://ruby-doc.org/stdlib-2.0.0/libdoc/csv/rdoc/CSV.html)
- [`ipaddr`](http://ruby-doc.org/stdlib-2.0.0/libdoc/ipaddr/rdoc/IPAddr.html)
- [`thread`](https://ruby-doc.org/core-2.2.0/Thread.html)
- [`monitor`](https://ruby-doc.org/stdlib-2.1.2/libdoc/monitor/rdoc/Monitor.html)
