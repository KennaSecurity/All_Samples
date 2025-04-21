require 'json'
require 'rest-client'
require 'optparse'
require 'date'

# Initialize parser for API token, asset group ID, custom base URL, and date range
options = {}
parser = OptionParser.new do |parser|
  parser.banner = "\nUsage: risk_meter_average.rb -t YOUR_API_TOKEN -i ASSET_GROUP_ID [options]"
  parser.on('-t', '--token=TOKEN', 'Mandatory argument. API token for the account making API calls') do |t|
    options[:token] = t
  end
  parser.on('-i', '--id=ID', 'Mandatory argument. Asset group ID for querying risk meter scores') do |i|
    options[:id] = i
  end
  parser.on('-b', '--base_url=URL', 'Optional argument. Custom base URL (defaults to api.kennasecurity.com)') do |b|
    options[:base_url] = b
  end
  parser.on('-s', '--start_date=DATE', 'Optional argument. Custom start date (YYYY-MM-DD)') do |s|
    options[:start_date] = Date.parse(s) rescue nil
  end
  parser.on('-e', '--end_date=DATE', 'Optional argument. Custom end date (YYYY-MM-DD)') do |e|
    options[:end_date] = Date.parse(e) rescue nil
  end
end

begin
  parser.parse!
rescue OptionParser::ParseError => e
  puts e.message
  abort(parser.help)
end

if options[:token].nil? || options[:id].nil?
  puts "Missing token or asset group ID!"
  abort(parser.help)
end

# Default to last 7 days if no date is provided
end_date = options[:end_date] || Date.today
start_date = options[:start_date] || (end_date - 7)

# Construct full API endpoint from base URL
base_url = options[:base_url] || "api.kennasecurity.com"
api_endpoint = "https://#{base_url}/asset_groups/#{options[:id]}/report_query/historical_risk_meter_scores?start_date=#{start_date}&end_date=#{end_date}"
headers = { 'content-type' => 'application/json', 'X-Risk-Token' => options[:token] }

begin
  # Make the API request
  response = RestClient::Request.execute(
    method: :get,
    url: api_endpoint,
    headers: headers
  )
  data = JSON.parse(response.body)

  # Check if risk_meter_scores is empty
  risk_scores = data['risk_meter_scores'].values
  if risk_scores.empty?
    puts "Risk meter does not have any results for the specified date range #{start_date} to #{end_date}."
  else
    # Calculate average risk meter score for the specified date range
    average_score = risk_scores.sum.to_f / risk_scores.size
    puts "Average risk meter score for the period #{start_date} to #{end_date}: #{average_score.round(2)}"
  end
rescue RestClient::Exception => e
  puts "An error occurred: #{e.message}"
end