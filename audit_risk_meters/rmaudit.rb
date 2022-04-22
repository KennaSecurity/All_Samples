require 'rest-client'
require 'optparse'
require 'json'
require 'csv'
require 'cgi'

# parse user arguments
my_parser = OptionParser.new do |parser|
  parser.banner = "\nRisk Meter Audit Script. Usage: rmaudit.rb [options]"
  parser.on '-r', '--risk_meters=RMFILE', 'Optional argument. A csv file with a listing of risk meter IDs and names',
                  'If this is not specified, then you must provide a token using the (-t) parameter. This takes precedence'
  parser.on '-t', '--token=TOKEN', 'Optional argument. API token for the account making API calls.',
                  'If this is not specified, then you must provide a source csv file using the (-r) parameter with your risk meters'
  parser.on '-f', '--filename=FILENAME', 'Mandatory argument. Filename of the audit log file should be provided'
  parser.on '-d', '--document_header=YES|NO', 'Optional argument (yes | no)- confirms if the risk meter file (-r option) has a header or not.',
                  'If none is specified, the default is "yes"'

end
@options = {}
my_parser.parse!(into: @options)

# Some script initialization, checks and house keeping
if @options.empty?
  abort(my_parser.help)
end

if @options[:filename].nil?
  puts "Filename (-f) for the audit file is a mandatory argument"
  abort(my_parser.help)
elsif @options[:token].nil? && @options[:risk_meters].nil?
  puts "You must specify either the source file for your risk meters, or an API token so your risk meters can be obtained"
  abort(my_parser.help)
end

abort("\n**The file doesn't exist. Please check the file and try again\n") unless File.exists?(@options[:filename])

# Variables we'll need later. Change the base URL base to match your environment
@token = @options[:token]
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token }
@base_url = 'https://api.kennasecurity.com'
@risk_meter_endpoint = '/asset_groups/'

## Methods used in the program
def exit_msg
  puts "\n[*] Exiting program ..."
  puts "[*] Good bye\n"
  exit(0)
end

def save_file()
  puts "\n[*] Saving file ..."
  @csv_file = "risk_meter_audit_#{(Time.now).to_s.gsub(/\s+/,"").gsub(/:/, "")}.csv"
  csv_headers = ["RiskMeter ID", "RiskMeter Name", "Last Access method", "Last Accessed Date"]
  csv = CSV.open(@csv_file, 'w')
  csv << csv_headers
  @collated_results.each_value do |nested_array|
    csv << nested_array
  end
  puts "\n[*] Results saved in #{@csv_file}\n"
  exit_msg
end

def risk_meter_search()
  puts "\n[*] Now auditing risk meter usage from the audit logs\n"
  # web visits regex
  reg_rmvisited = '{"audit_log_event":{"details":{"source".*explore\?search_id=(.*)&(parent.*)??name=(.*)&status'
  reg_rmvisited = Regexp.new((reg_rmvisited), "i")

  # API hits regex
  reg_apihits = '{"audit_log_event":{"details":{"source".*/asset_groups/([0-9]+)"'
  reg_apihits = Regexp.new((reg_apihits), "i")

  header_array = ["Risk Meter ID", "RiskMeter Name", "Last Access method", "Last Accessed Date"]
  @risk_meter_hash = {}
  # puts "\n%-15s %-40s %-25s %-40s" % header_array # Uncomment this line if you would like to see intermediate results on the Terminal
  File.foreach(@options[:filename]) do |line|
    matches = reg_rmvisited.match(line)
    if matches
      logmatch = JSON.parse(line)
      risk_meter_id = matches[1].split("&")[0]
      risk_meter_name = CGI.unescapeHTML(CGI.unescape matches[3])
      risk_meter_access = "Web"
      last_date_of_access = logmatch["audit_log_event"]["occurred_at"]

      @risk_meter_hash[risk_meter_id] = [risk_meter_name, risk_meter_access, last_date_of_access]
      # puts "%-15s %-40s %-25s %-40s" % [risk_meter_id, risk_meter_name, risk_meter_access, last_date_of_access] # Uncomment this line if you would like to see intermediate results on the Terminal
    else
      matches = reg_apihits.match(line)
      if matches
        logmatch = JSON.parse(line)
        risk_meter_id = matches[1]
        if @risk_meter_hash[risk_meter_id]
          risk_meter_name = @risk_meter_hash[risk_meter_id][0]
        else
          risk_meter_name = "API call only. Name not available"
        end
        risk_meter_access = "API"
        last_date_of_access = logmatch["audit_log_event"]["occurred_at"]
        @risk_meter_hash[risk_meter_id] = [risk_meter_name, risk_meter_access, last_date_of_access]
        # puts "%-15s %-40s %-25s %-40s" % [risk_meter_id, risk_meter_name, risk_meter_access, last_date_of_access]   # Uncomment this line if you would like to see intermediate results on the Terminal
      end
    end
  end
end

def collate_and_compare(val, val2)
  @collated_results = {}
  val.each do |org_risk_id|
    val2.each_key do |audit_rm_id|
      if org_risk_id[0].to_i == audit_rm_id.to_i
        compare_rm_id = audit_rm_id.to_i
        compare_rm_name = org_risk_id[1]
        compare_rm_type = @risk_meter_hash[audit_rm_id][1]
        compare_rm_date = @risk_meter_hash[audit_rm_id][2]
        @collated_results[org_risk_id] = compare_rm_id, compare_rm_name, compare_rm_type, compare_rm_date
      end
    end
    @collated_results[org_risk_id] = org_risk_id[0], org_risk_id[1], "Not Applicable", "Not visited during time range" unless @collated_results[org_risk_id]
  end
  save_file
end

# Method to load risk meters from a file
def get_risk_meters_file()
  abort("\n**The risk meter source file doesn't exist. Please check the file and try again\n") unless File.exists?(@options[:risk_meters])
  puts "\n[*] Pulling risk meters from your source file"
  @org_risk_meters = CSV.read(@options[:risk_meters])
  unless @options[:document_header] == ("no" || "n")
    @org_risk_meters.shift()
  end
end

# Method to download risk meters using user's API token
def download_org_risk_meters()
  begin
    api_call_url = "#{@base_url}#{@risk_meter_endpoint}?page=1&per_page=100"
    risk_meter_listing_response = RestClient::Request.execute(
      method: :get,
      url: api_call_url,
      headers: @headers
    )
  rescue RestClient::Exception => e
    puts e.message
    puts e.backtrace.inspect
  end

  no_of_pages, no_of_risk_meters  = [JSON.parse(risk_meter_listing_response)['meta']['pages'], JSON.parse(risk_meter_listing_response)['meta']['total_count']]

  puts "\n[*] Pulling information on #{no_of_risk_meters} risk meters over #{no_of_pages} page(s) ...\n"

  @org_risk_meters = []
  rm_num = 0
  1.upto(no_of_pages) do |page_num|
    puts "[*] Querying page #{page_num} of #{no_of_pages}"
    begin
      api_call_url = "#{@base_url}#{@risk_meter_endpoint}/?page=#{page_num}&per_page=100" # Using max page size
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
      @org_risk_meters[rm_num] = page_risk_meters[array_index]["id"], page_risk_meters[array_index]["name"]
      rm_num += 1
    end
  end
end

def get_risk_meters()
  if @options[:risk_meters]
    get_risk_meters_file()
  else
    download_org_risk_meters()
  end
  puts "[*] Organizational risk meters obtained successfully. \n"
end

# Function to search logs for risk meter usage
risk_meter_search()

# Get risk meters through file or API call
get_risk_meters()

# Compare output from logs against organization's total risk meters
collate_and_compare(@org_risk_meters, @risk_meter_hash)
