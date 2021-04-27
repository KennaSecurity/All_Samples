# frozen_string_literal: true

require 'rest-client'
require 'json'
require 'csv'

# These are the arguments we are expecting to get
@token = ARGV[0]
@csv_file = ARGV[1]
@role_name_col = ARGV[2]
@access_level_col = ARGV[3]
@asset_groups_col = ARGV[4]
@separator_char = ARGV[5]

# Variables we'll need later
@post_url = 'https://api.kennasecurity.com/roles'
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token }

num_lines = CSV.read(@csv_file).length
puts "Found #{num_lines} lines."

## Iterate through CSV
CSV.foreach(@csv_file, headers: true) do |row|
  # "Reading line #{$.}... "
  current_line = $INPUT_LINE_NUMBER
  role_name = nil
  access_level = nil
  asset_groups = nil

  role_name = row[@role_name_col].strip.gsub(/\A\p{Space}*|\p{Space}*\z/, '')
  access_level = row[@access_level_col].strip.gsub(/\A\p{Space}*|\p{Space}*\z/, '')
  asset_groups = row[@asset_groups_col].strip.gsub(/\A\p{Space}*|\p{Space}*\z/, '')

  json_data = {
    'role' =>
      {
        'name' => role_name.strip,
        'access_level' => access_level.strip,
        'asset_groups' => asset_groups.split(@separator_char)
      }
  }
  puts json_data
  begin
    query_post_return = RestClient::Request.execute(
      method: :post,
      url: @post_url,
      payload: json_data,
      headers: @headers
    )
  rescue Exception => e
    puts e.message
    puts e.backtrace.inspect
  end
end
