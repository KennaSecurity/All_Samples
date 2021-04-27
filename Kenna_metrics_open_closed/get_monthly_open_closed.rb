# frozen_string_literal: true

require 'rubygems'
require 'rest-client'
require 'json'
require 'csv'

# These are the arguments we are expecting to get - header file can be send as third parameter if not included as row 1 in csv
@token = ARGV[0]
@csv_file = ARGV[1] # list of risk meters for which reports are to be produced
@start_date = ARGV[2] # format yyyy-mm-dd
@end_date = ARGV[3] # format yyyy-mm-dd

@max_retries = 5
@start_time = Time.now
@output_filename = "kenna_ltm_report_log-#{@start_time.strftime('%Y%m%dT%H%M')}.txt"

@debug = false

# Variables we'll need later
@asset_group_url = 'https://api.kennasecurity.com/asset_groups'
@vuln_url = 'https://api.kennasecurity.com/vulnerabilities/search?'
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token }
high_risk_filter = 'vulnerability_score:>66'
med_risk_filter = 'vulnerability_score:>33+AND+vulnerability_score:<67'
low_risk_filter = 'vulnerability_score:<34'
open_query_date_limiter = "asset_last_seen:>=#{@start_date}+AND+vulnerability_found:>=#{@start_date}+AND+vulnerability_found:<=#{@end_date}+AND+asset_created:<=#{@end_date}"
closed_query_date_limiter = "asset_last_seen:>=#{@start_date}+AND+closed_at:>=#{@start_date}+AND+closed_at:<=#{@end_date}+AND+asset_created:<=#{@end_date}"
filename = "Kenna_Monthly_Report_#{@start_date}_#{@end_date}.csv"

# Encoding characters
enc_colon = '%3A'
enc_dblquote = '%22'
enc_space = '%20'

def processURL(urlstring)
  query_response = ''
  puts "url string #{urlstring}" if @debug
  begin
    query_response = RestClient::Request.execute(
      method: :get,
      url: urlstring,
      headers: @headers
    )
  rescue RestClient::UnprocessableEntity => e
    log_output = File.open(@output_filename, 'a+')
    log_output << "UnprocessableEntity: #{urlstring}... (time: #{Time.now}, start time: #{@start_time})\n"
    log_output.close
    puts "UnprocessableEntity: #{e.message} #{urlstring}"
  rescue RestClient::BadRequest => e
    log_output = File.open(@output_filename, 'a+')
    log_output << "BadRequest: #{urlstring}... (time: #{Time.now}, start time: #{@start_time})\n"
    log_output.close
    puts "BadRequest: #{e.message} #{urlstring}"
  rescue RestClient::Exception => e
    @retries ||= 0
    if @retries < @max_retries
      @retries += 1
      sleep(15)
      retry
    else
      log_output = File.open(@output_filename, 'a+')
      log_output << "General RestClient error #{urlstring}... (time: #{Time.now}, start time: #{@start_time})\n"
      log_output.close
      puts "Unable to get vulns:#{e.message} #{urlstring}"

    end
  end
  query_response
end

CSV.open(filename, 'w') do |csv|
  csv << ["Reporting Data starting #{@start_date} and ending #{@end_date}"]

  csv <<
    [
      'Risk Meter Name',
      'Staring Score',
      'Ending Score',
      'Total Opened Vulns',
      'Total Closed Vulns',
      'High Opened Vulns',
      'High Closed Vulns',
      'Med Opened Vulns',
      'Med Closed Vulns',
      'Low Opened Vulns',
      'Low Closed Vulns'
    ]

  CSV.foreach(@csv_file, headers: true) do |row|
    rm_name = ''
    rm_tag = ''
    rm_id = ''
    current_risk_score = ''
    row_data = []

    rm_id = row[0]
    rm_name = row[1]
    rm_tag = row[2]

    row_data << rm_name

    query_response = processURL("#{@asset_group_url}/#{rm_id}/report_query/historical_risk_meter_scores?start_date=#{@start_date}&#{@end_date}")
    query_response_json = JSON.parse(query_response)['risk_meter_scores']
    current_risk_score = query_response_json.fetch(@start_date)
    row_data << current_risk_score
    current_risk_score = query_response_json.fetch(@end_date)
    row_data << current_risk_score

    query_url = "#{@vuln_url}status%5B%5D=all&asset%5Bstatus%5D%5B%5D=active&asset%5Bstatus%5D%5B%5D=inactive&q="
    query_url = "#{query_url}tag:%22#{rm_tag}%22+AND+" if !rm_tag.nil? && !rm_tag.empty?

    # total open vuln count
    vuln_response = processURL("#{query_url}#{open_query_date_limiter}")
    vuln_response_meta = JSON.parse(vuln_response)['meta']
    row_data << vuln_response_meta.fetch('total_count') || 0

    # total closed vuln count
    vuln_response = processURL("#{query_url}#{closed_query_date_limiter}")
    vuln_response_meta = JSON.parse(vuln_response)['meta']
    row_data << vuln_response_meta.fetch('total_count') || 0

    # high_risk open vuln count
    vuln_response = processURL("#{query_url}#{high_risk_filter}+AND+#{open_query_date_limiter}")
    vuln_response_meta = JSON.parse(vuln_response)['meta']
    row_data << vuln_response_meta.fetch('total_count') || 0

    # high_risk closed vuln count
    vuln_response = processURL("#{query_url}#{high_risk_filter}+AND+#{closed_query_date_limiter}")
    vuln_response_meta = JSON.parse(vuln_response)['meta']
    row_data << vuln_response_meta.fetch('total_count') || 0

    # med_risk open vuln count
    vuln_response = processURL("#{query_url}#{med_risk_filter}+AND+#{open_query_date_limiter}")
    vuln_response_meta = JSON.parse(vuln_response)['meta']
    row_data << vuln_response_meta.fetch('total_count') || 0

    # med_risk closed vuln count
    vuln_response = processURL("#{query_url}#{med_risk_filter}+AND+#{closed_query_date_limiter}")
    vuln_response_meta = JSON.parse(vuln_response)['meta']
    row_data << vuln_response_meta.fetch('total_count') || 0

    # low_risk open vuln count
    vuln_response = processURL("#{query_url}#{low_risk_filter}+AND+#{open_query_date_limiter}")
    vuln_response_meta = JSON.parse(vuln_response)['meta']
    row_data << vuln_response_meta.fetch('total_count') || 0

    # low_risk closed vuln count
    vuln_response = processURL("#{query_url}#{low_risk_filter}+AND+#{closed_query_date_limiter}")
    vuln_response_meta = JSON.parse(vuln_response)['meta']
    row_data << vuln_response_meta.fetch('total_count') || 0

    csv << row_data
  end
end
