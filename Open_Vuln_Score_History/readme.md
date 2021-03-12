# Open Vulnerability Score History

This POC python script will generate a CSV (ovsh.csv) with the score history for any open CVE in your Kenna Environment.

## How It Does It

- Starts A Full Data Export Of All Open Vulnerabilities
- Waits For Data Export To Be Complete And Downloads Zip.
- Coverts JSON File to Pandas DataFrame.
  - Deduplicates the list.
- Uses the history endpoint to grab CVE scores.
- Builds a clean DataFrame with those scores.
- Exports the DataFrame to ovsh.csv.

## How to Use It

Update this line to point to your Kenna API URL:

```base_url = "https://api.kennasecurity.com/"```

Update this line to include your Kenna API key:

```RiskToken = "PasteKennaAPIKEyHere"```

Install the needed python requirements.

```pip3install -r requirements.txt```

Run the scipt.

```python3 OVSH.py```
