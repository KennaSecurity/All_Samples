# kenna-asset-tagger
require 'rest-client'
require 'json'
require 'csv'
require 'ipaddr'

@token = ARGV[0]
@csv_file = ARGV[1]
ARGV.length == 3 ? @tag_column_file = ARGV[2] : @tag_column_file = nil

def is_ip?(str)
  !!IPAddr.new(str) rescue false
end

@asset_api_url = 'https://api.kennasecurity.com/assets'
@search_url = @asset_api_url + '/search?q='
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json'}

tag_columns = []
assets_hash = {}

# Encoding characters
enc_colon = "%3A"
enc_dblquote = "%22"
enc_space = "%20"

## Set columns to use for tagging, if a @tag_column_file is provided

tag_columns = File.readlines(@tag_column_file).map{|line| line.strip}.uniq.reject(&:empty?) if !@tag_column_file.nil?
num_lines = CSV.read(@csv_file).length
#puts "time: #{Time.now}"
start_time = Time.now
puts "Found #{num_lines} lines."

## Iterate through CSV
CSV.foreach(@csv_file, :headers => true){|row|
  #puts "Reading line #{$.}... "
  current_line = $.
  tag_list = []
  asset_identifier = nil
  asset_id = nil

  # Get 'asset' identifier and figure out if ip/hostname
  next if row['asset'].nil?
  asset_identifier = row['asset'].downcase
  if is_ip?(asset_identifier) then
    api_query = "ip#{enc_colon}#{asset_identifier}"
  else
    api_query = "hostname#{enc_colon}#{enc_dblquote}#{asset_identifier}#{enc_dblquote}"
  end
  api_query = api_query.gsub(' ',enc_space)
  #print api_query

  query_url = "#{@search_url}#{api_query}"

  query_response = RestClient::Request.execute(
    method: :get,
    url: query_url,
    headers: @headers
  )
  query_response_json = JSON.parse(query_response)

  if query_response_json.has_key?("assets") then
    asset_key = query_response_json["assets"]
    if asset_key.count > 0 then
      if asset_key.first.has_key?("id") then
        asset_id = "#{asset_key.first["id"]}"
      end
    end
  end

  # query api to find kenna asset id
  #
  next if asset_id.nil?

  # if we find an asset id, retrieve all the tag values
  if tag_columns.count > 0 then
    # only pull tag columns!
    tag_columns.each{|the_column|
      tag_string = row[the_column].strip
      tag_list << "#{the_column}: #{tag_string}"
    }
  else
    # pull all columns except 'asset'
    puts "pull all columns except 'asset'"
    tag_list << "here's a tag"
  end
  next if tag_list.count == 0

  assets_hash[asset_id] = tag_list

  #if current_line % 100 == 0 then
    puts "Processed #{current_line} lines (#{Time.now}, start: #{start_time})..."
  #end
}

## Push tags to assets
assets_hash.each{|(id,tags)|
  tag_api_url = "#{@asset_api_url}/#{id}/tags"
  tag_string = ""
  tags.each{|t| tag_string << "#{t},"}
  tag_string = tag_string[0...-1]
  #puts "#{id}, #{tags}\n"
  tag_update_json = {
    'asset' => {
      'tags' => "#{tag_string}"
    }
  }

  puts tag_api_url
  update_response = RestClient::Request.execute(
    method: :put,
    url: tag_api_url,
    headers: @headers,
    payload: tag_update_json
  )
}
