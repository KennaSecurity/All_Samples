# Kenna asset tagging API script

This script will add tags to Kenna assets

Usage:

```
kenna-asset-tagger.rb <Kenna API token> <CSV file of assets and tags> <(optional) file of tag columns in CSV to apply>
```

Tested on:

- ruby 2.0.0p648 (2015-12-16 revision 53162) [universal.x86_64-darwin15]

Required Ruby classes/gems:

- [`rest-client`](https://github.com/rest-client/rest-client)
- [`json`](http://ruby-doc.org/stdlib-2.0.0/libdoc/json/rdoc/JSON.html)
- [`csv`](http://ruby-doc.org/stdlib-2.0.0/libdoc/csv/rdoc/CSV.html)