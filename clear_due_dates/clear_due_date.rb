# frozen_string_literal: true

# kenna-bulk-custom-field-update
require 'rest-client'
require 'json'

# These are the arguments we are expecting to get
@token = ARGV[0]

# Variables we'll need later
@post_url = 'https://api.kennasecurity.com/vulnerabilities/bulk'
@data_url = 'https://api.kennasecurity.com/data_exports'
@headers = { 'Content-type' => 'application/json', 'X-Risk-Token' => @token }

@max_retries = 5

start_time = Time.now
@output_filename = Logger.new("clear_due_date-#{start_time.strftime('%Y%m%dT%H%M')}.txt")
@debug = false

# Encoding characters
enc_colon = '%3A'
enc_dblquote = '%22'
enc_space = '%20'

def bulkUpdate(vulnids)
  puts 'starting bulk update' if @debug
  json_string = nil
  json_string = "{\"vulnerability_ids\": #{vulnids}, "
  json_string = "#{json_string}\"vulnerability\": {"
  json_string = "#{json_string}\"due_date\": \" \"}}"

  puts json_string if @debug

  # post_url = "https://api.kennasecurity.com/vulnerabilities/bulk"

  begin
    query_post_return = RestClient::Request.execute(
      method: :put,
      url: @post_url,
      payload: json_string,
      headers: @headers
    )
  rescue RestClient::TooManyRequests => e
    retry
  rescue RestClient::UnprocessableEntity => e
  rescue RestClient::BadRequest => e
    @output_filename.error("Async BadRequest: #{post_url}...#{e.message} (time: #{Time.now}, start time: #{start_time})\n")
    puts "Async BadRequest: #{e.message}"
  rescue RestClient::Exception => e
    @retries ||= 0
    if @retries < @max_retries
      @retries += 1
      sleep(15)
      retry
    else
      @output_filename.error("Async General RestClient error #{post_url}... #{e.message}(time: #{Time.now}, start time: #{start_time})\n")
      puts "Async Unable to get vulns: #{e.message}"
    end
  rescue Exception => e
    @output_filename.error("Unable to get vulns - general exception: #{e.backtrace.inspect}... (time: #{Time.now}, start time: #{start_time})\n")
    puts "Unable to get vulns: #{e.message} #{e.backtrace.inspect}"
  end
  @output_filename.error("bulk vuln update status: #{JSON.parse(query_post_return.body)}... time: #{Time.now}\n")
end

bulk_query_json_string = '{"status": ["open"], '
bulk_query_json_string = "#{bulk_query_json_string} \"q\": \"_exists_:due_date\", \"export_settings\": {\"format\": \"json\", "
bulk_query_json_string = "#{bulk_query_json_string}\"compression\": \"gzip\", \"model\": \"vulnerability\" }}"

puts bulk_query_json_string if @debug

bulk_query_json = JSON.parse(bulk_query_json_string)

begin
  query_response = RestClient::Request.execute(
    method: :post,
    url: @data_url,
    headers: @headers,
    payload: bulk_query_json_string
  )

  query_response_json = JSON.parse(query_response.body)
  searchID = query_response_json.fetch('search_id')
  puts "searchID = #{searchID}" if @debug
  # searchID = "37935"
  # output_results = "myoutputfile_#{searchID}.json"
  searchComplete = false

  while searchComplete == false

    status_code = RestClient.get("https://api.kennasecurity.com/data_exports/status?search_id=#{searchID}",
                                 @headers).code

    puts "status code =#{status_code}" if @debug
    if status_code != 200
      puts 'sleeping for async query' if @debug
      sleep(60)
      next
    else
      puts 'ansyc query complete' if @debug
      searchComplete = true
      output_results = "myoutputfile_#{searchID}.json"
      File.open(output_results, 'w') do |f|
        block = proc { |response|
          response.read_body do |chunk|
            f.write chunk
          end
        }
        RestClient::Request.new(method: :get,
                                url: "https://api.kennasecurity.com/data_exports?search_id=#{searchID}", headers: @headers, block_response: block).execute
      end
      gzfile = open(output_results)
      gz = Zlib::GzipReader.new(gzfile)
      results_json = JSON.parse(gz.read)['vulnerabilities']
      id_array = []
      results_json.each do |item|
        id_array << item['id']
      end
      id_array.each_slice(5000) do |list|
        bulkUpdate(list)
      end
    end
  end
rescue RestClient::TooManyRequests => e
  retry
rescue RestClient::UnprocessableEntity => e
  @output_filename.error("UnprocessableEntity: ...#{e.message} (time: #{Time.now}, start time: #{start_time})\n")
  puts "UnprocessableEntity: #{e.message}"
rescue RestClient::BadRequest => e
  @output_filename.error("BadRequest: ...#{e.message} (time: #{Time.now}, start time: #{start_time})\n")
  puts "BadRequest: #{e.message}"
rescue RestClient::Exception => e
  @retries ||= 0
  if @retries < @max_retries
    @retries += 1
    sleep(15)
    retry
  else
    @output_filename.error("General RestClient error #{e.message}(time: #{Time.now}, start time: #{start_time})\n")
    puts "Unable to get vulns: #{e.message}"
  end
rescue Exception => e
  @output_filename.error("Unable to get vulns - general exception: #{e.backtrace.inspect}... (time: #{Time.now}, start time: #{start_time})\n")
  puts "Unable to get vulns: #{e.backtrace.inspect}"
end
