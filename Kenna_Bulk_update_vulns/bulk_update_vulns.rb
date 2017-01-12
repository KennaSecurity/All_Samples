# kenna-asset-tagger
require 'rest-client'
require 'json'


@token = ARGV[0]
@query_string = ARGV[1]
@new_status = ARGV[2]
ARGV.length == 4 ? @due_date = ARGV[3] : @due_date = nil

@vuln_url = 'https://api.kennasecurity.com/vulnerabilities'
@vuln_api_url = "#{@vuln_url}/search?#{@query_string}"
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json'}
@debug = false

start_time = Time.now
output_filename = "kenna_bulk_status_update_log-#{start_time.strftime("%Y%m%dT%H%M")}.txt"

  
  if @debug then 
    puts "Vuln api url...#{@vuln_api_url}"
  end

  meta_response = RestClient::Request.execute(
    method: :get,
    url: @vuln_api_url, 
    headers: @headers
  )

  meta_response_json = JSON.parse(meta_response.body)["meta"]
  tot_vulns = meta_response_json.fetch("total_count")
  tot_pages = meta_response_json.fetch("pages")

  if tot_vulns > 0 then
    log_output = File.open(output_filename,'a+')
    log_output << "Processing page count of #{tot_pages}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
    log_output.close
    puts "Processing page count of #{tot_pages}"
  end
  endloop = tot_pages + 1
  (1...endloop).step(1) do |i|
    log_output = File.open(output_filename,'a+')
    log_output << "Currently processing page #{i} of #{tot_pages}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
    log_output.close
    puts "Currently processing page #{i} of #{tot_pages}"
    query_url = "#{@vuln_api_url}&page=#{i}"
    if @debug then 
      puts "loop query string...#{query_url}"
    end
    query_response = RestClient::Request.execute(
      method: :get,
      url: query_url,
      headers: @headers
    )
    # Build URL to set the custom field value for each vulnerability

    query_response_json = JSON.parse(query_response.body)["vulnerabilities"]
      if @debug then 
          puts "returned json size from vuln query..." + query_response_json.size
      end
      query_response_json.each do |item|
   
          vuln_id = item["id"]
          post_url = "#{@vuln_url}/#{vuln_id}"
          if @debug then 
            puts "post url for single vuln...#{post_url}"
          end
          json_data = {
            'vulnerability' => {
              'status' => "#{@new_status}",
              "due_date" => "#{@due_date}"
            }
          }
          if @debug then 
            puts "json data...#{json_data}"
          end
          begin
            query_post_return = RestClient::Request.execute(
              method: :put,
              url: post_url,
              payload: json_data,
              headers: @headers
            )
          rescue RestClient::UnprocessableEntity 

          rescue RestClient::BadRequest
            log_output = File.open(output_filename,'a+')
            log_output << "Unable to update: #{post_url}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
            log_output.close
            puts "Unable to update: #{post_url}"

          end
       end
    endloop +=1
  end



  

