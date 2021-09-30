# frozen_string_literal: false

# Script to bulk rename Applications in Kenna AppSec module
require 'json'
require 'csv'
require 'rest-client'
#require 'pry'
#require 'pry-byebug'

# These are the arguments we are expecting to get.
@token = ARGV[0]
@csv_file = ARGV[1]
@create_apps = ARGV[2]
@Delete_apps_with_name_same_as_identifier = ARGV[3]


# Variables we'll need later. Change base URL base to match your environment
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token }
@base_url = 'https://api.kennasecurity.com'


@application_endpoint = '/applications/'
@update_app_url = "#{@base_url}#{@application_endpoint}"

# work out the number of application pages of applications for the instance
unless @create_apps == "false"
  begin
    api_call_url = "#{@base_url}#{@application_endpoint}"
    asset_listing_response = RestClient::Request.execute(
      method: :get,
      url: api_call_url,
      headers: @headers
    )
  rescue RestClient::Exception => e
    puts e.message
    puts e.backtrace.inspect
  end

  no_of_pages = JSON.parse(asset_listing_response)['meta']['pages']

  # Now iterate through all the pages of the application and extract relevant info
  applications_present = []

  1.upto(no_of_pages) do |page_num|
    begin
      api_call_url = "#{@base_url}#{@application_endpoint}/?page=#{page_num}.to_s"
      asset_listing_response = RestClient::Request.execute(
        method: :get,
        url: api_call_url,
        headers: @headers
      )
    rescue RestClient::Exception => e
      puts e.message
      puts e.backtrace.inspect
    end

    apps_on_page = JSON.parse(asset_listing_response.body)['applications']
    #applications_present = []
    apps_on_page.each_index do |array_index|
      applications_present = applications_present.append("#{apps_on_page[array_index]['name']}")
    end
  end

  puts "Total number of applications in your environmnet"
  puts applications_present.count.to_s
  num_lines = CSV.read(@csv_file).length
  # puts "Found #{num_lines - 1} application(s) for processing."
  # puts ''
  # puts applications_present
  # puts ''

  # Iterate through the CSV file
  CSV.foreach(@csv_file, headers: true) do |row|
   #application_id = row[0]
    new_application_name = row[0]
    new_application_identifier = row[1]
    apps_on_page = JSON.parse(asset_listing_response.body)['applications']
    if applications_present.include? new_application_name
      #apps_on_page = JSON.parse(asset_listing_response.body)['applications']
      apps_on_page.each_index do |array_index|
        application_name = "#{apps_on_page[array_index]['name']}"
        identifier = "#{apps_on_page[array_index]['identifiers']}"
        application_id = "#{apps_on_page[array_index]['id']}"
        #require 'pry-byebug';binding.pry

        if new_application_name == application_name
          identifier = identifier.gsub(/"|\[|\]/, '')
          # identifier = identifier.delete(" ")
          unless identifier.delete(" ") == new_application_identifier.delete(" ")
            #require 'pry-byebug';binding.pry
            new_application_identifier = [identifier,new_application_identifier].join(', ')
            #new_application_identifier = new_application_identifier.delete(" ")
            puts "Updating Application identifier: #{new_application_name}"
            json_data = {
              "application": {
                "name": application_name.to_s,
                "identifiers": new_application_identifier.to_s.split(",")
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
          end
        end
      end

    else
      puts "Creating Application: #{new_application_name}"

      # require 'pry-byebug';binding.pry
      json_data = {
        "application": {
          "name": new_application_name.to_s,
          "identifiers": new_application_identifier.to_s.split(",")
        }
      }

      begin
        api_call_url = "#{@update_app_url}"
        RestClient::Request.execute(
          method: :post,
          url: api_call_url,
          payload: json_data,
          headers: @headers
        )
      rescue RestClient::Exception => e
        puts e.message
        puts e.backtrace.inspect
      end
      applications_present = applications_present.append("#{new_application_name}")
    end
  end
end

unless @Delete_apps_with_name_same_as_identifier == "false"
    begin
    api_call_url = "#{@base_url}#{@application_endpoint}"
    asset_listing_response = RestClient::Request.execute(
      method: :get,
      url: api_call_url,
      headers: @headers
    )
  rescue RestClient::Exception => e
    puts e.message
    puts e.backtrace.inspect
  end

  no_of_pages = JSON.parse(asset_listing_response)['meta']['pages']
  1.upto(no_of_pages) do |page_num|
    begin
      api_call_url = "#{@base_url}#{@application_endpoint}/?page=#{page_num}.to_s"
      asset_listing_response = RestClient::Request.execute(
        method: :get,
        url: api_call_url,
        headers: @headers
      )
    rescue RestClient::Exception => e
      puts e.message
      puts e.backtrace.inspect
    end

    apps_on_page = JSON.parse(asset_listing_response.body)['applications']
    #applications_present = []
    apps_on_page.each_index do |array_index|
      application_name = "#{apps_on_page[array_index]['name']}"
      identifier = "#{apps_on_page[array_index]['identifiers']}"
      application_id = "#{apps_on_page[array_index]['id']}"
      #require 'pry-byebug';binding.pry
      if application_name == identifier.gsub(/"|\[|\]/, '')
        puts "Deleting Application_name: #{application_name}"
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
    end
  end
end


