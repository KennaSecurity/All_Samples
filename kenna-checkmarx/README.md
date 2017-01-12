# Kenna/Checkmarx API script

This script will inject Checkmarx asset/vulnerability information into the Kenna platform, via the Kenna API.

Usage:

```
kenna-checkmarx.py <Kenna API token> <checkmarx XML filename>
```

Once the asset and vulnerability information has been added to Kenna, each asset will appear in the following format:

```
/filename.extension:line_number:column_number
```

...for example:

```
/index.asp:54:6
```

Each individual vulnerability page within Kenna will also include the affected code snippet within a "Notes" tab, in addition to the in-depth CWE/WASC vulnerability information.

Tested on Python 2.7.6 with BeautifulSoup4