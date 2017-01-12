# Kenna/Archer vulnerability metadata API script

This script will search for existing Kenna vulnerabilities and apply specific metadata based on specific input.

Usage:

```
kenna-cvs-archer-sync.rb <Kenna API token> <Archer vulnerability metadata CSV export file>
```

Tested on:

- ruby 2.0.0p648 (2015-12-16 revision 53162) [universal.x86_64-darwin15]

Required Ruby classes/gems:

- [`rest-client`](https://github.com/rest-client/rest-client)
- [`json`](http://ruby-doc.org/stdlib-2.0.0/libdoc/json/rdoc/JSON.html)
- [`csv`](http://ruby-doc.org/stdlib-2.0.0/libdoc/csv/rdoc/CSV.html)