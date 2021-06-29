# frozen_string_literal: false

# This script can be used for deleting applications in bulk. See README for more info

require 'rest-client'
require 'json'
require 'csv'

# These are the arguments we are expecting to get
@token = ARGV[0]
@csv_file = ARGV[1]

# Variables we'll need later
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token }

# Change the base URL to match your environment
@base_url = 'https://api.kennasecurity.com/'
@api_endpoint = 'applications/'
@update_app_url = "#{@base_url}#{@api_endpoint}"

num_lines = CSV.read(@csv_file).length
puts "Found #{num_lines - 1} application(s) for processing."
puts ''

# Iterate through CSV file
CSV.foreach(@csv_file, headers: true) do |row|
  application_id = row[0]
  puts ''

  puts "Working on Application: #{application_id}"

  # make the call to delete the application

  begin
    api_call_url = "#{@update_app_url}#{application_id}"
    RestClient::Request.execute(
      method: :delete,
      url: api_call_url,
      headers: @headers
    )
  rescue RestClient::Exception => e
    puts e.message
    puts e.backtrace.inspect
  end
end
