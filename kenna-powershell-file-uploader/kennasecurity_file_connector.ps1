# Upload and run file-based connector using Kenna Security API

# Client-specific variable information
$api_key = ''
$connector_id = ''
$file_export_path = ""
$file_export_filename = ""

$file_export = "${file_export_path}${file_export_filename}"

# Generate URLs and header
$api_host = 'api.kennasecurity.com'
$url_connector = "https://${api_host}/connectors/${connector_id}"
$url_upload = "${url_connector}/data_file"
$url_run = "${url_connector}/run"
$header = @{"X-Risk-Token" = $api_key}

# Encode file for upload
$fileBytes = [IO.file]::ReadAllBytes($file_export)
$enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")
$fileEnc = $enc.GetString($fileBytes)
$boundary = [System.Guid]::NewGuid().ToString()
$LF = "`r`n"
$bodyLines = (
  "--$boundary",
  "Content-Disposition: form-data; name=file; filename=${file_export_filename}",
  "Content-Type: application/octet-stream$LF",
  $fileEnc,
  "--$boundary--"
  ) -join $LF

# Upload file export to connector
# Call:
#   curl -H "X-Risk-Token: <token>" https://api.kennasecurity.io/connectors/1/data_file -X POST -F "file=@somefile"
# Response:
#   {"success":"true","run_url":"https://api.kennasecurity.io/connectors/1/run"}

Invoke-RestMethod -Uri $url_upload -Method Post -Header $header -ContentType "multipart/form-data; boundary=`"$boundary`"" -TimeoutSec 600 -Body $bodyLines

# Run connector
# Call:
#  curl -H "X-Risk-Token: <token>" https://api.kennasecurity.io/connectors/1/run -X GET
# Response:
#   {"success":"true"}

Invoke-RestMethod -Uri $url_run -Header $header -Method Get
