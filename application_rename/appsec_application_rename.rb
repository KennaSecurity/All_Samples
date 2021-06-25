# frozen_string_literal: false

# Script to bulk rename Applications in Kenna AppSec module
require 'json'
require 'csv'
require 'rest-client'

# These are the arguments we are expecting to get.
@token = ARGV[0]
@csv_file = ARGV[1]

# Variables we'll need later. Change base URL base to match your environment
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token }
@base_url = 'https://api.kennasecurity.com'

@search_endpoint = '/assets/search?application_id='
@asset_search_url = "#{@base_url}#{@search_endpoint}"

@update_endpoint = '/applications/'
@update_app_url = "#{@base_url}#{@update_endpoint}"

@asset_endpoint = '/assets/'
@update_assets_url = "#{@base_url}#{@asset_endpoint}"

num_lines = CSV.read(@csv_file).length
puts "Found #{num_lines - 1} application(s) for processing."
puts ''

# Iterate through the CSV file
CSV.foreach(@csv_file, headers: true) do |row|
  application_id = row[0]
  new_application_name = row[1]
  new_application_identifier = row[2]

  puts ''
  puts "Working on Application: #{new_application_name}"

  begin
    api_call_url = "#{@asset_search_url}#{application_id}"
    asset_search_response = RestClient::Request.execute(
      method: :get,
      url: api_call_url,
      headers: @headers
    )
  rescue RestClient::Exception => e
    puts e.message
    puts e.backtrace.inspect
  end

  found_assets = JSON.parse(asset_search_response.body)['assets']

  # Create a list of the asset IDs for updating their application identifiers

  asset_array = []
  found_assets.length.times do |n|
    asset_array.append(found_assets[n]['id'])
  end

  puts "The application identifiers for the following #{found_assets.length} \
  assets will be updated to #{new_application_identifier}"
  puts asset_array.join(',')
  puts ''

  # make the call to update the application folder name and application identifiers
  # attached to the application

  json_data = {
    "application": {
      "name": new_application_name.to_s,
      "identifiers": [new_application_identifier.to_s]
    }
  }

  begin
    api_call_url = "#{@update_app_url}#{application_id}"
    RestClient::Request.execute(
      method: :put,
      url: api_call_url,
      payload: json_data,
      headers: @headers
    )
  rescue RestClient::Exception => e
    puts e.message
    puts e.backtrace.inspect
  end

  # Finally, make the call to update each of the assets of that application

  json_data = {
    "asset": { "application": new_application_identifier.to_s }
  }

  begin
    asset_array.each do |asset_id|
      api_call_url = ''
      api_call_url = "#{@update_assets_url}#{asset_id}"
      puts "Call to #{api_call_url}, updating identifier of asset #{asset_id} to #{new_application_identifier}"
      RestClient::Request.execute(
        method: :put,
        url: api_call_url,
        payload: json_data,
        headers: @headers
      )
    end
  rescue RestClient::Exception => e
    puts e.message
    puts e.backtrace.inspect
  end
end
