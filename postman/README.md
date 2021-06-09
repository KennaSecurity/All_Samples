# Kenna Security API Postman Collection

## Introduction

This repository contains a Postman collection for Kenna Security APIs.  The collection can be used in
the Postman app or in the browser environment.

## Import Collection

You can import via Postman's GitHub interface or you can clone the `All_Samples` repository and import
`postman/Kenna_API_postman_collection.json`.  To import via GitHub, do:

1. Click the "Import" button.
1. Click "Code Respository"
1. You will have to give Postman access to GitHub via a pop-up web page.
1. Select the following:
   1. For __GitHub organization__, Kenna Security
   1. For __repository__, All Samples
   1. For __branch__, master
1. Click "Continue"
1. Select the collection, and click "Import"

You should be ready to go.

## Set Authorization

With Postman, authorization can be set for each API or for the whole collection. To set the
authorization for the entire collection, do:

1. Click on the collection.
1. Click on the "Authorization" tab.
1. In the "Type" pulldown, select "API Key".
1. Type in "X-Risk-Token" in the "Key" text box.
1. Copy your API key in the "Value" text box.
1. In the "Add to" puldown, select "Header".
1. Click "Save". (Located between "Run" and "Share" to the right.)

## Set Base URL

The Kenna Security API collection defaults `API_URL` to "api.kennasecurity.com".  If this is not
correct, then do:

1. Click on the collection.
1. Click on the "Variables" tab.
1. Change the "Current Value" to desire base URL.
1. Click "Save". (Located between "Run" and "Share" to the right.)

## List Assets

Test the set-up, on the left side menu:
1. on the left side menu: Click "Assets" and then "GET List Assets".
1. Verify that under the "Authorization" tab, the "Type" value is "Inherit auth from parent".
1. If desired, verify the header by clicking "Header" and verify "X-Risk-Token".
1. Click the blue "Send" button on the right.

Success is indicated by a list assets.
