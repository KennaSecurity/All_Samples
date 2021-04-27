# frozen_string_literal: true

# kenna-asset-tagger
require 'rest-client'
require 'json'
require 'csv'
require 'ipaddr'

@token = ARGV[0]
@csv_file = ARGV[1]
@tag_column_file = ARGV[2]

def is_ip?(str)
  !IPAddr.new(str).nil?
rescue StandardError
  false
end

@asset_api_url = 'https://api.kennasecurity.com/assets'
@search_url = "#{@asset_api_url}/search?q="
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json' }
@max_retries = 5

tag_columns = []
tag_list = []
# Encoding characters
enc_colon = '%3A'
enc_dblquote = '%22'
enc_space = '%20'

## Set columns to use for tagging, if a @tag_column_file is provided

tag_columns = CSV.read(@tag_column_file)[0]
tag_columns.collect { |x| x.to_s.strip || x }

start_time = Time.now
output_filename = "kenna-asset-tagger_log-#{start_time.strftime('%Y%m%dT%H%M')}.txt"

num_lines = CSV.read(@csv_file).length
start_time = Time.now

log_output = File.open(output_filename, 'a+')
log_output << "Processing CSV total lines #{num_lines}... (time: #{Time.now}, start time: #{start_time})\n"
log_output.close

## Iterate through CSV
CSV.foreach(@csv_file, headers: true, encoding: 'UTF-8') do |row|
  current_line = $INPUT_LINE_NUMBER

  asset_identifier = nil
  asset_id = nil

  log_output = File.open(output_filename, 'a+')
  log_output << "Reading line #{$INPUT_LINE_NUMBER}... (time: #{Time.now}, start time: #{start_time})\n"
  log_output.close

  # Get 'asset' identifier and figure out if ip/hostname

  if !row['IP Address'].nil?
    asset_identifier = row['IP Address'].downcase
    api_query = "ip:#{enc_dblquote}#{asset_identifier}#{enc_dblquote}"
  elsif !row['Server Name'].nil?
    asset_identifier = row['Server Name'].downcase
    api_query = "hostname:#{enc_dblquote}#{asset_identifier}#{enc_dblquote}"
  else
    next
  end

  api_query = api_query.gsub(' ', enc_space)

  query_url = "#{@search_url}#{api_query}"

  log_output = File.open(output_filename, 'a+')
  log_output << "Query URL...#{query_url}\n"
  log_output.close
  begin
    query_response = RestClient::Request.execute(
      method: :get,
      url: query_url,
      headers: @headers
    )
  rescue RestClient::UnprocessableEntity
    log_output = File.open(output_filename, 'a+')
    log_output << "Unable to get vulns - UnprocessableEntity: #{query_url}... (time: #{Time.now}, start time: #{start_time})\n"
    log_output.close
    puts "Unable to get vulns: #{query_url}"
    next
  rescue URI::InvalidURIError
    log_output = File.open(output_filename, 'a+')
    log_output << "Unable to get vulns - InvalidURI: #{query_url}... (time: #{Time.now}, start time: #{start_time})\n"
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
      log_output = File.open(output_filename, 'a+')
      log_output << "General RestClient error #{query_url}... (time: #{Time.now}, start time: #{start_time})\n"
      log_output.close
      puts "Unable to get vulns: #{query_url}"
      next
    end
  end
  query_meta_json = JSON.parse(query_response)['meta']
  total_found = query_meta_json.fetch('total_count')
  if total_found.zero?
    log_output = File.open(output_filename, 'a+')
    log_output << "Asset not found - #{query_url}... (time: #{Time.now}, start time: #{start_time})\n"
    log_output.close
    next
  end
  query_response_json = JSON.parse(query_response)['assets']

  query_response_json.each do |item|
    asset_id = item['id']
    tag_list = []
    # if we find an asset id, retrieve all the tag values
    if tag_columns.count.positive?
      # only pull tag columns!
      tag_columns.each do |the_column|
        tag_string = row[the_column]
        unless tag_string.nil?
          tag_string = tag_string.strip
          tag_list << "ASD:#{tag_string}"
        end
      end
    end
    # pull other columns that need prefixes'

    tag_list << "ERR:#{row['Exposure Risk Rating'].strip}" unless row['Exposure Risk Rating'].nil?
    tag_list << "DR:#{row['DR Tier'].strip}" unless row['DR Tier'].nil?
    unless row['IT Manager First'].nil? then tag_list << "IT MGR:#{row['IT Manager First'].strip} #{row['IT Manager Last'].strip}" end
    unless row['IIT Director First'].nil? then tag_list << "IT DIR:#{row['IT Director First'].strip} #{row['IT Director Last'].strip}" end
    unless row['Bus Director First'].nil? then tag_list << "BUS DIR:#{row['Bus Director First'].strip} #{row['Bus Director Last'].strip}" end
    tag_list << "VP POC:#{row['VP POC First'].strip} #{row['VP POC Last'].strip}" unless row['VP POC First'].nil?
    tag_list << "IT VP:#{row['IT VP First'].strip} #{row['IT VP Last'].strip}" unless row['IT VP First'].nil?

    #   next if tag_list.count == 0
    #     assets_hash[asset_id] = tag_list

    # end

    ## Push tags to assets

    tag_api_url = "#{@asset_api_url}/#{asset_id}/tags"
    tag_string = ''
    tag_list.each { |t| tag_string << "#{t}," }
    tag_string = tag_string[0...-1]
    tag_update_json = {
      'asset' => {
        'tags' => tag_string.to_s
      }
    }

    log_output = File.open(output_filename, 'a+')
    log_output << "Post Asset URL...#{tag_api_url}\n"
    log_output << "Tags...#{tag_string}\n"
    log_output.close
    begin
      update_response = RestClient::Request.execute(
        method: :put,
        url: tag_api_url,
        headers: @headers,
        payload: tag_update_json
      )
    rescue RestClient::UnprocessableEntity
      log_output = File.open(output_filename, 'a+')
      log_output << "Unable to update - UnprocessableEntity: #{tag_api_url}... (time: #{Time.now}, start time: #{start_time})\n"
      log_output.close
      puts "Unable to update: #{tag_api_url}"
    rescue RestClient::BadRequest
      log_output = File.open(output_filename, 'a+')
      log_output << "Unable to update - BadRequest: #{tag_api_url}... (time: #{Time.now}, start time: #{start_time})\n"
      log_output.close
      puts "Unable to update: #{tag_api_url}"
    rescue RestClient::Exception
      @retries ||= 0
      if @retries < @max_retries
        @retries += 1
        sleep(15)
        retry
      else
        log_output = File.open(output_filename, 'a+')
        log_output << "General RestClient error #{tag_api_url}... (time: #{Time.now}, start time: #{start_time})\n"
        log_output.close
        puts "Unable to get vulns: #{tag_api_url}"

      end
    end
  end
  # }
end
