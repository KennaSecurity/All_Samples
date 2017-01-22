# kenna-archer-sync
require 'rest-client'
require 'json'
require 'csv'

@token = ARGV[0]
@file_name = ARGV[1]

@vuln_api_url = 'https://api.kennasecurity.com/vulnerabilities'
@search_url = @vuln_api_url + '/search?q='
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json'}
@max_retries = 5

# Encoding characters
enc_colon = "%3A"
enc_dblquote = "%22"
enc_space = "%20"

start_time = Time.now
output_filename = "kenna-archer-sync_log-#{start_time.strftime("%Y%m%dT%H%M")}.txt"

## Iterate through CSV
CSV.foreach(@file_name, :headers => true) do |row|
  log_output = File.open(output_filename,'a+')
  log_output << "Reading line #{$.}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
  log_output.close
  #puts "Reading line #{$.}... "

  ## Pull from CSV
  tm_record = row['Scan Record ID']
#  platform = row['Platform']
  archer_status = row['Vulnerability Status']
  #ip_str = row['Qualys IP Address']
  qid_str = row['QID']
  dns_hostname = row['Qualys DNS Hostname']
  ip_str = row['Qualys IP Address']

  if !ip_str.nil?
    ## Build query string/URL
    api_query = "ip#{enc_colon}#{ip_str}#{enc_space}AND#{enc_space}scanner_id#{enc_colon}#{qid_str}"  
  elsif !dns_hostname.nil? 
    ## Build query string/URL
    api_query = "hostname#{enc_colon}#{dns_hostname}#{enc_space}AND#{enc_space}scanner_id#{enc_colon}#{qid_str}"
  else
    next    
  end
    
  query_url = "#{@search_url}#{api_query}"

  ## Query API with query_url
  vuln_id = nil
  begin
    query_response = RestClient::Request.execute(
      method: :get,
      url: query_url,
      headers: @headers
    )
      rescue RestClient::UnprocessableEntity 
        log_output = File.open(output_filename,'a+')
        log_output << "Unable to get vulns - UnprocessableEntity: #{query_url}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
        log_output.close
        puts "Unable to get vulns: #{query_url}"
        next
      rescue URI::InvalidURIError
        log_output = File.open(output_filename,'a+')
        log_output << "Unable to get vulns - InvalidURI: #{query_url}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
        log_output.close
        puts "Unable to get vulns: #{query_url}"
        next
      rescue RestClient::Exception
        @retries ||= 0
        if @retries < @max_retries
          @retries += 1
          sleep(15)
          retry
        else
          log_output = File.open(output_filename,'a+')
          log_output << "General RestClient error #{query_url}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
          log_output.close
          puts "Unable to get vulns: #{query_url}"
          next
        end
      end 
  query_response_json = JSON.parse(query_response)["vulnerabilities"]


  query_response_json.each do |item|
    vuln_id = item["id"]
    if !vuln_id.nil?
      #puts "Found Kenna vuln_id: #{vuln_id}, updating..."
      log_output = File.open(output_filename,'a+')
      log_output << "Found Kenna vuln_id: #{vuln_id}, updating...\n"
      log_output.close
      vuln_url = "#{@vuln_api_url}/#{vuln_id}"

      ## update vuln ID with data
      vuln_update_json = {
        'vulnerability' => {
          'status' => 'false_positive_by_human',
          'notes' => 'updated by Kenna script',
          'custom_fields' => {
          4050 => tm_record,
          4055 => archer_status
 #         4048 => platform   # add this row to 
 #test eviron
          # 1199 => tm_record,
          # 4037 => archer_status,
          # 4138 => platform
        }
      }
    }
    begin
    update_response = RestClient::Request.execute(
      method: :put,
      url: vuln_url,
      headers: @headers,
      payload: vuln_update_json
    )
      rescue RestClient::UnprocessableEntity 
        log_output = File.open(output_filename,'a+')
        log_output << "Unable to update - UnprocessableEntity: #{vuln_url}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
        log_output.close
        puts "Unable to update: #{vuln_url}"

      rescue RestClient::BadRequest
        log_output = File.open(output_filename,'a+')
        log_output << "Unable to update - BadRequest: #{vuln_url}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
        log_output.close
        puts "Unable to update: #{vuln_url}"
      rescue RestClient::Exception
        @retries ||= 0
        if @retries < @max_retries
          @retries += 1
          sleep(15)
          retry
        else
          log_output = File.open(output_filename,'a+')
          log_output << "General RestClient error #{vuln_url}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
          log_output.close
          puts "Unable to update: #{vuln_url}"

        end
      end
  end
end
end
