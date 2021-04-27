# frozen_string_literal: true

# kenna-asset-tagger
require 'rest-client'
require 'json'
require 'csv'

@token = ARGV[0]
@tag_column_file = ARGV[1]

@asset_api_url = 'https://api.kennasecurity.com/assets'
@search_url = "#{@asset_api_url}/search?"
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
output_filename = "kenna-asset-tag-remover_log-#{start_time.strftime('%Y%m%dT%H%M')}.txt"
keep_trying = true

query_url = "#{@search_url}status%5B%5D=active&q=tag:%22#{tag_columns[0]}*%22"
puts query_url

while keep_trying

  begin
    query_response = RestClient::Request.execute(
      method: :get,
      url: query_url,
      headers: @headers
    )
  rescue RestClient::UnprocessableEntity
    log_output = File.open(output_filename, 'a+')
    log_output << "Unable to get assets - UnprocessableEntity: #{query_url}... (time: #{Time.now}, start time: #{start_time})\n"
    log_output.close
    puts "Unable to get assets: #{query_url}"
  rescue URI::InvalidURIError
    log_output = File.open(output_filename, 'a+')
    log_output << "Unable to get assets - InvalidURI: #{query_url}... (time: #{Time.now}, start time: #{start_time})\n"
    log_output.close
    puts "Unable to get assets: #{query_url}"
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
      puts "Unable to get assets: #{query_url}"
    end
  end
  query_meta_json = JSON.parse(query_response)['meta']

  total_found = query_meta_json.fetch('total_count')
  puts "total_found = #{total_found}"
  if total_found.zero?
    keep_trying = false
    break
  end

  query_response_json = JSON.parse(query_response)['assets']
  tag_list = []
  query_response_json.each do |item|
    @asset_id = item['id']
    current_tags = []
    current_tags = item['tags']
    # if we find an asset id, retrieve all the tag values
    if tag_columns.count.positive?
      # only pull tag columns!
      tag_columns.each do |the_column|
        current_tags.each do |cur_tag|
          tag_list << cur_tag if cur_tag.start_with?(the_column)
        end
      end
    end

    ## Push tags to assets

    tag_api_url = "#{@asset_api_url}/#{@asset_id}/tags"
    tag_string = ''
    tag_list.each { |t| tag_string << "#{t}," }
    tag_string.chomp(',')
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
        method: :delete,
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
        puts "Unable to update vulns: #{tag_api_url}"

      end
    end
  end

end
