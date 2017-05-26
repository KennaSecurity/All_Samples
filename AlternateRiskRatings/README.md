# Alternate Risk Ratings

## Rationale

If vulnerabilities exist in Kenna, but need additional fields added, we can run this script to assign custom fields.
See https://blog.kennasecurity.com/2012/01/special-orders-dont-upset-us/ for a brief discussion of custom fields,
which have been in Kenna for a considerable amount of time.

## File Format
The CSV file should have the following format
- header row
  Vulnerability,Type,Determination

- body rows
  -- Vulnerability: A vulnerability name or pattern
  -- Type: either Config or Vulnerability
  -- Determination: new priority level to assign. Possible values are Informational or Actionable for Config items, Low, Med, or High for Vulnerabilities

### Example body rows:

```
*Buffer Overflow*,Vulnerability,High
CGI Generic Cookie Injection Scripting,Vulnerability,High
```


# Execution strategy

The program will read the csv file to generate a work queue. Each row in the csv corresponds to one worker in the pool.
The API is queried to find 0 scored vulnerabilities by name (first column).
For each found vulnerabilty, update (via PUT) the custome fields to include the csv row data (second and third columns).

Error handling is done during the update steps to check for
 bad requests (logged and abandoned), a busy service (continue trying),  and other errors (logged, fail).