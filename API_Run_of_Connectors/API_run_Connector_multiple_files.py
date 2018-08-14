#!/usr/bin/env python

import sys, requests, json, os, time, urllib, pycurl

token = sys.argv[1]
folder = sys.argv[2]
connector_id = sys.argv[3]
file_extension = sys.argv[4]


LOCATOR_DELIMITER = ":"
API_ENDPOINT_CONNECTOR = "https://api.kennasecurity.com/connectors"
headers = {'content-type': 'application/json', 'X-Risk-Token': token}



for filename in os.listdir(folder):
    abspath = ''

    if filename.endswith(file_extension):
        pathname = os.path.join(folder, filename)
        abspath = os.path.abspath(pathname)
        try:

            conn_url = API_ENDPOINT_CONNECTOR + "/" + connector_id + "/data_file?run=true"

            print conn_url

            c = pycurl.Curl()
            c.setopt(c.URL, conn_url)
            c.setopt(c.POST, 1)
            c.setopt(c.HTTPPOST, [("file", (c.FORM_FILE, abspath))])
            c.setopt(pycurl.HTTPHEADER, ['content-type:application/json'])
            c.setopt(pycurl.HTTPHEADER, ['X-Risk-Token:'+token])
            c.setopt(c.VERBOSE, 0)
            c.perform()
            c.close()

            running = True

            while running:

                time.sleep(15)
                vuln_post = requests.get(API_ENDPOINT_CONNECTOR + "/" + connector_id, headers=headers)
                #print vuln_post.status_code
                response = vuln_post.json()
                print response
                running = response['connector']['running']


        except KeyError:
            print("unable to run connector")  
            raise   
          