require 'json'
require 'csv'
require 'rest-client'
require 'optparse'

# Intro
puts ""
puts "[+] Utility for the Kenna AppSec Product"
puts "[+] The utility can be used for the following purposes"
puts "[+] - Download your applications in a CSV format"
puts "[+] - Consolidate your application identifiers under one application"
puts "[+] - Delete applications no longer wanted in your environment"
puts "[+] Please note this is not a Kenna official release"
puts "[+] As with all scripts in this repository, test to ensure this helps with the intended functionality as desired"
puts ""

# Initialize parser
@my_parser = OptionParser.new do |parser|
  parser.banner = "\nScript Usage: ruby app_util.rb -t your_API_token -o [download | consolidate | delete] [-f csv_meta_file]"
  parser.on '-t', '--token=TOKEN', 'Mandatory argument. API token for the account making API calls'
  parser.on '-o', '--operation=OPERATION', 'Parameter used to specify listing or update functionality',
                  'valid operations for the -o flag are "download", "consolidate", and "delete" as defined below',
                  'download - option used for downloading all applications. this is the default operation',
                  'consolidate - option used to consolidate your applications as specified in the provided file (-f)',
                  'delete - option used to delete the application(s) as specified in the profided file (-f)'
  parser.on '-f', '--filename=FILENAME', 'Input file with details of application changes. Required in "consolidate" and "delete" operations'
end

@options = {}
@my_parser.parse!(into: @options)
if @options.empty?
  abort(@my_parser.help)
elsif @options[:token].nil?
  puts "Missing token!\n"
  abort(@my_parser.help)
else
  @token = @options[:token]
end

@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token }
@base_url = 'https://api.kennasecurity.com'
@application_endpoint = '/applications/'

# Same URL, just initializing different variables to provide better context of the operation
# Might be better defining them when required
@asset_search_url = "#{@base_url}#{@application_endpoint}"
@update_app_url = "#{@base_url}#{@application_endpoint}"
@delete_app_url = "#{@base_url}#{@application_endpoint}"


def exit_msg
  puts "**Exiting program ..!"
  puts "Good bye"
  exit(0)
end

def download_applications()
	# work out the number of application pages of applications for the instance
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
  puts "Attempting to pull all applications across a total of #{no_of_pages} pages"

	# Now iterate through all the pages of the application and extract relevant info
	@csv_file = "application_listing_#{(Time.now).to_s.gsub(/\s+/,"").gsub(/:/, "")}.csv"
	csv_headers = ["App Name", "App ID", "Risk Score", "# of High Findings", "# of Medium Findings", "# of Low Findings", "Total Findings", "Application Identifier(s)"]
	csv = CSV.open(@csv_file, 'w')
	csv << csv_headers

	1.upto(no_of_pages) do |page_num|
    puts "Pulling applications on Page #{page_num} of #{no_of_pages}"
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

	  apps_on_page.each_index do |array_index|
      csv << ["#{apps_on_page[array_index]["name"]}",
        "#{apps_on_page[array_index]["id"]}",
        "#{apps_on_page[array_index]["risk_meter_score"]}",
        "#{apps_on_page[array_index]["open_vulnerability_count_by_risk_level"]["high"]}",
        "#{apps_on_page[array_index]["open_vulnerability_count_by_risk_level"]["medium"]}",
        "#{apps_on_page[array_index]["open_vulnerability_count_by_risk_level"]["low"]}",
        "#{apps_on_page[array_index]["open_vulnerability_count_by_risk_level"]["total"]}",
        "#{apps_on_page[array_index]["identifiers"]}"]
	  end
	end
  puts "All Applications downloaded and saved in #{@csv_file}\n"
end

def consolidate_applications
  if @options[:filename].nil?
    puts "Filename is required when using the 'consolidate' operation!\n"
    abort(@my_parser.help)
  else
    # abort("\n**The file doesn't exist. Please check the file and try again\n") unless File.file?(@options[:filename])
    abort("\n**The file doesn't exist. Please check the file and try again\n") unless File.exists?(@options[:filename])
    @csv_file = @options[:filename]
  end

# Determine how many records available for processing
  num_lines = CSV.read(@csv_file).length
  puts "Found #{num_lines - 1} application(s) for processing.\n"

# For each record, initialize variables you would need.
  CSV.foreach(@csv_file, headers: true) do |row|
    obsolete_app_name = row[0]
    obsolete_app_id = row[1]
    consolidating_app_name = row[2]
    consolidating_app_id = row[3]

    # ToDo: make a debug and non-debug version of the script.
    puts "\nGetting details for Application: #{obsolete_app_name} with App ID: #{obsolete_app_id}"

    begin
      api_call_url = "#{@asset_search_url}#{obsolete_app_id}"
      asset_search_response = RestClient::Request.execute(
        method: :get,
        url: api_call_url,
        headers: @headers
      )
    rescue RestClient::Exception => e
      puts e.message
      puts e.backtrace.inspect
    end

    moving_app_identifiers = JSON.parse(asset_search_response.body)['application']['identifiers']

    # Grab the app identifiers for the consolidating app
    puts "Getting existing identifiers for Consolidating App: #{consolidating_app_name} with App ID: #{consolidating_app_id}"
    begin
      api_call_url = "#{@asset_search_url}#{consolidating_app_id}"
      asset_search_response = RestClient::Request.execute(
        method: :get,
        url: api_call_url,
        headers: @headers
      )
    rescue RestClient::Exception => e
      puts e.message
      puts e.backtrace.inspect
    end

    consolidating_app_identifiers = JSON.parse(asset_search_response.body)['application']['identifiers']
    updated_app_identifiers = consolidating_app_identifiers.append(moving_app_identifiers).flatten

    # now update the app IDs for the consolidating app
    puts "... updating identifiers for Consolidating App: #{consolidating_app_name} with App ID: #{consolidating_app_id}"
    json_data = {
      "application": {
        "identifiers": updated_app_identifiers
      }
    }

    begin
      api_call_url = "#{@update_app_url}#{consolidating_app_id}"
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

    # Now delete the obsolete app_id
    puts "... deleting Application: #{obsolete_app_name} with App ID: #{obsolete_app_id}\n"
    begin
      api_call_url = "#{@delete_app_url}#{obsolete_app_id}"
      asset_search_response = RestClient::Request.execute(
        method: :delete,
        url: api_call_url,
        headers: @headers
      )
    rescue RestClient::Exception => e
      puts e.message
      puts e.backtrace.inspect
    end
  end
  puts "\nCompleted the consolidation of the application(s) in file"
end

def delete_applications
  if @options[:filename].nil?
    puts "Filename is required when using the 'delete' operation!\n"
    abort(@my_parser.help)
  else
    abort("\n**The file doesn't exist. Please check the file and try again\n") unless File.exists?(@options[:filename])
    @csv_file = @options[:filename]
  end

# Determine how many records available for processing
  num_lines = CSV.read(@csv_file).length
  puts "Found #{num_lines - 1} application(s) scheduled for deleting.\n"

# For each record, initialize variables you would need.
  CSV.foreach(@csv_file, headers: true) do |row|
    obsolete_app_name = row[0]
    obsolete_app_id = row[1]

    # ToDo: make a debug and non-debug version of the script.
    # Now delete the obsolete app_id
    puts "... deleting Application: #{obsolete_app_name} with App ID: #{obsolete_app_id}\n"
    begin
      api_call_url = "#{@delete_app_url}#{obsolete_app_id}"
      asset_search_response = RestClient::Request.execute(
        method: :delete,
        url: api_call_url,
        headers: @headers
      )
    rescue RestClient::Exception => e
      puts e.message + ": Application not found"
      # puts e.backtrace.inspect
    end
  end
  puts "\nCompleted the deletion of the application(s) in file"
end

# main script starts now
if @options[:operation].nil?
  puts "No operation specified. So defaulting to 'download' mode"
  download_applications
  exit_msg
end

case @options[:operation]
when "download"
  download_applications
  exit_msg
when "consolidate"
  consolidate_applications
  exit_msg
when "delete"
  delete_applications
  exit_msg
else
  puts "Error: Incorrect operation provided"
  puts "Possible modes options:"
  puts "  download"
  puts "  consolidate"
  exit_msg
end
