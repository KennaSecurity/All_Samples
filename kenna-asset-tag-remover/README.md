# kenna-asset-tag-remover

This script will remove specific tags from all assets. 

Input is a CSV file with the tag(s) that should be removed with the first tag being added to the search parameters. 

Example: csv data = ["DMZ","External","EXT OPS"]

The script will look for all active assets with tags that start with DMZ. The script adds a wildcard to the end of each item. 

https://api.kennasecurity.com/assets/search?status%5B%5D=active&q=tag%3A%22DMZ*%22

The script will then loop through those assets and remove all the tags referenced in the CSV file. 

For each asset remove tags that start with "DMZ" or "External" or "EXT OPS". 

Required Ruby classes/gems:

rest-client json csv

Usage: kenna-asset-tag-remover.rb applicationkey tags_to_remove.csv

Log file will be created in the current directory.
