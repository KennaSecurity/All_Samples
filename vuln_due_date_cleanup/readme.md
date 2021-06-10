# Remove DueDate from CVE IDs

What is it for:
- We all know that the Vulnerability Score changes over time, but not the SLA DUE_DATE.
- Once a DUE_DATE is granted to a Vulnerability, even if the Vulnerability Score change, the DUE_DATE will not change.
- When the Vulnerability Score change, the DUE_DATE should change and follow the SLA setting configured on your system.
- This script is a work-around and will remove the DUE_DATE of all the Vulnerabilities within a specific Risk Meter that changed score in the last X days.
- Every night Kenna runs an internal process that will grant a new DUE_DATE to those vulnerabilities that meet your SLA configuration.
- So, after removing the needed DUE_DATE using this script, you might need to wait a day for the vulnerabilities to receive a new one.

# Kenna is not responsible for maintaining this script or any harm that it may cause.

This POC python script has two outcomes:
- Will generate a CSV (opencves.csv) with the score history for any open CVE within a specific Risk Meter.
- Will bulk update all the CVE IDs that changed score in the last X days within a specific Risk Meter.

## How It Does It

- Starts A Full Data Export Of All Open Vulnerabilities
- Waits For Data Export To Be Complete And Downloads Zip.
- Coverts JSON File to Pandas DataFrame.
  - Creates a new list with the CVE_Name and its CVE_IDs.
    - CVE-2019-1234 | 4587, 8547, 4695, ...
    - CVE-2016-1234 | 5698, 1579, 2587, ...
    - ...
  - Deduplicates the main list.
- Uses the history endpoint to grab CVE scores.
  - Check which CVE IDs should be updated
- Builds a clean DataFrame with those scores.
  - Bulk update all the CVE IDs where the CVE changed score in the last X days
- Exports the DataFrame to ovsh.csv.

## How to Use It

Update this line to point to your Kenna API URL:

```base_url = "https://api.kennasecurity.com/"```

Install the needed python requirements.

```pip3 install -r requirements.txt```

Run the script:
- PasteKennaAPIKEyHere = the API Key that you can get on your Kenna UI
  - Settings > API Key > Find your name and click "Copy Key"
- PasteTheRiskMeterIDHere = the Risk Meter ID
  - You can get that by opening any Risk Meter reporting
  - At the top, in the URL entry, you will see the Risk Meter ID. Something like the following:
    - https://YourInstanceName.kennasecurity.com/dashboard/risk_meter/271636
  - The 271636 number above is the Risk Meter ID
- PasteTheNumberOfDaysToLookBack = max look back is 7 days. You can choose any number between 1 and 7.

```python3 due_date_cleanup.py PasteKennaAPIKEyHere PasteTheRiskMeterIDHere PasteTheNumberOfDaysToLookBack```
