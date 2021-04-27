# frozen_string_literal: true

# kenna run connectors
require 'rest-client'
require 'json'

@token = ARGV[0]
@folder = ARGV[1]
@connector_id = ARGV[2]
@file_extension = ARGV[3]

@LOCATOR_DELIMITER = ':'
@API_ENDPOINT_CONNECTOR = 'https://api.kennasecurity.com/connectors'
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json' }

@debug = false

def directory_exists?(directory)
  Dir.exist?(directory)
end

start_time = Time.now
output_filename = "kenna-runConnector_log-#{start_time.strftime('%Y%m%dT%H%M')}.txt"
log_output = File.open(output_filename, 'a+')
log_output << "Start time: time: #{Time.now}\n"

puts 'Directory not found' unless directory_exists?(@folder)

Dir.entries(@folder.to_s).each do |abspath|
  puts abspath
  next unless abspath.end_with? @file_extension.to_s

  fname = File.basename(abspath, @file_extension.to_s)

  conn_url = "#{@API_ENDPOINT_CONNECTOR}/#{@connector_id}/data_file?run=true"
  puts conn_url if @debug

  begin
    query_response = RestClient::Request.execute(
      method: :post,
      url: conn_url,
      headers: @headers,
      payload: {
        multipart: true,
        file: File.new("#{@folder}/" + abspath, 'rb')
      }
    )

    query_response_json = JSON.parse(query_response.body)

    puts query_response_json.fetch('success') if @debug

    running = true

    conn_check_url = "#{@API_ENDPOINT_CONNECTOR}/#{@connector_id}"

    while running

      sleep(15)
      conn_check = RestClient::Request.execute(
        method: :get,
        url: conn_check_url,
        headers: @headers
      )

      conn_check_json = JSON.parse(conn_check)['connector']
      puts conn_check_json if @debug
      running = conn_check_json.fetch('running')
    end
  rescue RestClient::UnprocessableEntity => e
    log_output = File.open(output_filename, 'a+')
    log_output << "UnprocessableEntity: #{e.message}... (time: #{Time.now}, start time: #{start_time})\n"
    log_output.close
    puts "UnprocessableEntity: #{e.message}"
  rescue RestClient::BadRequest => e
    log_output = File.open(output_filename, 'a+')
    log_output << "BadRequest: #{e.message}... (time: #{Time.now}, start time: #{start_time})\n"
    log_output.close
    puts "BadRequest: #{e.message}"
  rescue RestClient::Exception => e
    puts "i hit an exception #{e.message}"

    @retries ||= 0
    if @retries < @max_retries
      @retries += 1
      sleep(15)
      retry
    else
      log_output = File.open(output_filename, 'a+')
      log_output << "General RestClient error #{e.message}... (time: #{Time.now}, start time: #{start_time})\n"
      log_output.close
      puts "Exception: #{e.message}"
    end
  end
  log_output = File.open(output_filename, 'a+')
  log_output << "End time: time: #{Time.now}\n"
end
