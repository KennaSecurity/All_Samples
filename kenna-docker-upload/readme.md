# Kenna Docker Upload

Uploads Docker Vulnerbilities as File assets with all associated vulnerabilities

This script will process one or more Docker vulnerability json files from a named directory

Usage:

    kenna-docker-upload.rb <Kenna API token> <folder holding Docker vuln files>
    
    
Tested on:

    ruby 2.3.0p0 (2015-12-25 revision 53290) [x86_64-darwin15]
    
    
Required Ruby classes/gems:

    rest-client
    json
