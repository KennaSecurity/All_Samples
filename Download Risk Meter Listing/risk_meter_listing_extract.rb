require 'json'
require 'rest-client'
require 'csv'
require 'optparse'

# Initialize parser
my_parser = OptionParser.new do |parser|
  parser.banner = "\nUsage: risk_meter_listing_extract.rb -t your_API_token"
  parser.on '-t', '--token=TOKEN', 'Mandatory argument. API token for the account making API calls'
end

options = {}
my_parser.parse!(into: options)

if options[:token].nil?
  puts "Missing token!\n"
  abort(my_parser.help)
end

# Variables we'll need later. Change base URL base to match your environment
@token = options[:token]
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token }
@base_url = 'https://api.kennasecurity.com'
@risk_meter_endpoint = '/asset_groups/'
@csv_file = "risk_meter_listing.csv"

# work out the number of application pages of applications for the instance
begin
  api_call_url = "#{@base_url}#{@risk_meter_endpoint}"
  risk_meter_listing_response = RestClient::Request.execute(
    method: :get,
    url: api_call_url,
    headers: @headers
  )
rescue RestClient::Exception => e
  puts e.message
  puts e.backtrace.inspect
end

# Get meta information on the download
no_of_pages, no_of_risk_meters  = [JSON.parse(risk_meter_listing_response)['meta']['pages'], JSON.parse(risk_meter_listing_response)['meta']['total_count']]

puts "The details of #{no_of_risk_meters} risk meters over #{no_of_pages} pages will now be downloaded"

# Now iterate through all the pages of the risk meter listing and extract relevant info
csv_headers = ["Risk Meter", "Risk Meter ID", "Parent ID?", "Score", "True Risk Score", "# of Vulns", "Unique CVE count", "Child RM IDs", "Created Time", "Query String"]

csv = CSV.open(@csv_file, 'w')
csv << csv_headers

1.upto(no_of_pages) do |page_num|
  puts "Querying page #{page_num} of #{no_of_pages}"
  begin
    api_call_url = "#{@base_url}#{@risk_meter_endpoint}/?page=#{page_num}.to_s"
    risk_meter_listing_response = RestClient::Request.execute(
      method: :get,
      url: api_call_url,
      headers: @headers
    )
  rescue RestClient::Exception => e
    puts e.message
    puts e.backtrace.inspect
  end

  page_risk_meters = JSON.parse(risk_meter_listing_response.body)['asset_groups']

  page_risk_meters.each_index do |array_index|
    csv << ["#{page_risk_meters[array_index]["name"]}",
      "#{page_risk_meters[array_index]["id"]}",
      page_risk_meters[array_index]["parent"] ? "#{page_risk_meters[array_index]["parent"]["id"]}" : "No Parent",
      "#{page_risk_meters[array_index]["risk_meter_score"]}",
      "#{page_risk_meters[array_index]["true_risk_meter_score"]}",
      "#{page_risk_meters[array_index]["vulnerability_count"]}",
      "#{page_risk_meters[array_index]["unique_open_cve_count"]}",
      "#{page_risk_meters[array_index]["child_ids"]}",
      "#{page_risk_meters[array_index]["created_at"]}",
      "#{page_risk_meters[array_index]["querystring"]}"]
  end
end

puts "Script completed successfully! Check file '#{@csv_file}' for your report\n"
