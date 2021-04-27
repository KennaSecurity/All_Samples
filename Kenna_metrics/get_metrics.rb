# frozen_string_literal: true

# kenna-bulk-custom-field-update
require 'rest-client'
require 'json'
require 'csv'

# These are the arguments we are expecting to get - header file can be send as third parameter if not included as row 1 in csv
@token = ARGV[0]
@csv_file = ARGV[1] # name of the output csv file
@meter_list = ARGV[2]
@date_range = ARGV[3]

risk_meter_list = []
url_list = []

# optional keywords for date_range
# previous_month
unless @meter_list.nil?
  CSV.parse(File.open(@meter_list, 'r:iso-8859-1:utf-8', &:read), headers: true) do |row|
    risk_meter_list << row[0]
  end
end

case @date_range
when 'previous_month'
  holderDate = Date.today.prev_month
  year = holderDate.year
  month = holderDate.strftime('%m')

  @date_range = "start_date=#{year}-#{month}-01&end_date=#{year}-#{month}-" << Date.new(year, holderDate.mon,
                                                                                        -1).strftime('%d')
else
  # use the date_range as-is or build in more options
end

@max_retries = 5
start_time = Time.now
output_filename = "kenna_bulk_status_update_log-#{start_time.strftime('%Y%m%dT%H%M')}.txt"

@debug = false

# Variables we'll need later
@asset_group_url = 'https://api.kennasecurity.com/asset_groups'
@mttr_url = 'report_query/historical_mean_time_to_remediate_by_risk_level'
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token }

# Encoding characters
enc_colon = '%3A'
enc_dblquote = '%22'
enc_space = '%20'

if !risk_meter_list.nil?
  risk_meter_list.each do |meter_item|
    url_list << "#{@asset_group_url}/#{meter_item}"
  end
else
  url_list << @asset_group_url
end
url_list.each do |group_url|
  begin
    query_response = RestClient::Request.execute(
      method: :get,
      url: group_url,
      headers: @headers
    )
  rescue RestClient::UnprocessableEntity
    log_output = File.open(output_filename, 'a+')
    log_output << "UnprocessableEntity: #{group_url}... (time: #{Time.now}, start time: #{start_time})\n"
    log_output.close
    puts "BadRequest: #{asset_group_url}"
  rescue RestClient::BadRequest
    log_output = File.open(output_filename, 'a+')
    log_output << "BadRequest: #{group_url}... (time: #{Time.now}, start time: #{start_time})\n"
    log_output.close
    puts "BadRequest: #{group_url}"
  rescue RestClient::Exception
    @retries ||= 0
    if @retries < @max_retries
      @retries += 1
      sleep(15)
      retry
    else
      log_output = File.open(output_filename, 'a+')
      log_output << "General RestClient error #{group_url}... (time: #{Time.now}, start time: #{start_time})\n"
      log_output.close
      puts "Unable to get vulns: #{group_url}"

    end
  end

  header_needed = true
  header_needed = false if File.exist?(@csv_file)
  CSV.open(@csv_file, 'a+') do |writer|
    if header_needed
      writer << ['Risk Meter ID', 'Risk Meter Name', 'Risk Meter Score', 'Score Last Week', 'Score Week Delta',
                 'Score Last Month', 'Score Month Delta', 'Score 90 Days Ago', 'Score 90 Delta', 'Last Update', 'MTTR High', 'MTTR Med', 'MTTR Low', 'Date Range']
    end
    query_response_json = []
    if url_list.size > 1
      query_response_json << JSON.parse(query_response.body)['asset_group']
    else
      query_response_json = JSON.parse(query_response.body)['asset_groups']
    end
    p query_response_json.size if @debug
    query_response_json.each do |item|
      rm_id = item['id']
      rm_name = item['name']
      rm_score = item['risk_meter_score']
      rm_last_update = item['updated_at']
      score_last_week = item['score_last_week'].fetch('score') unless item['score_last_week'].nil?
      score_week_delta = item['score_last_week'].fetch('delta') unless item['score_last_week'].nil?
      score_last_month = item['score_last_month'].fetch('score') unless item['score_last_month'].nil?
      score_month_delta = item['score_last_month'].fetch('delta') unless item['score_last_month'].nil?
      score_90_days_ago = item['score_90_days_ago'].fetch('score') unless item['score_90_days_ago'].nil?
      score_90_delta = item['score_90_days_ago'].fetch('delta') unless item['score_90_days_ago'].nil?
      metric_url = "#{@asset_group_url}/#{rm_id}/#{@mttr_url}"
      puts "metric url = #{metric_url}" if @debug
      metric_url += "?#{@date_range}" unless @date_range.nil?
      begin
        metric_response = RestClient::Request.execute(
          method: :get,
          url: metric_url,
          headers: @headers
        )
      rescue RestClient::UnprocessableEntity
        log_output = File.open(output_filename, 'a+')
        log_output << "UnprocessableEntity: #{metric_url}... (time: #{Time.now}, start time: #{start_time})\n"
        log_output.close
        puts "BadRequest: #{metric_url}"
      rescue RestClient::BadRequest
        log_output = File.open(output_filename, 'a+')
        log_output << "BadRequest: #{metric_url}... (time: #{Time.now}, start time: #{start_time})\n"
        log_output.close
        puts "BadRequest: #{metric_url}"
      rescue RestClient::Exception
        @retries ||= 0
        if @retries < @max_retries
          @retries += 1
          sleep(15)
          retry
        else
          log_output = File.open(output_filename, 'a+')
          log_output << "General RestClient error #{metric_url}... (time: #{Time.now}, start time: #{start_time})\n"
          log_output.close
          puts "Unable to get vulns: #{metric_url}"

        end
      end
      metric_response_json = JSON.parse(metric_response.body)['mttr']
      puts metric_response_json.size if @debug
      high_risk = metric_response_json.fetch('High Risk Vulns')
      med_risk = metric_response_json.fetch('Medium Risk Vulns')
      low_risk = metric_response_json.fetch('Low Risk Vulns')

      writer << [rm_id.to_s, rm_name.to_s, rm_score.to_s, score_last_week.to_s, score_week_delta.to_s,
                 score_last_month.to_s, score_month_delta.to_s, score_90_days_ago.to_s, score_90_delta.to_s, rm_last_update.to_s, high_risk.to_s, med_risk.to_s, low_risk.to_s, @date_range.to_s]
    end
  end
end
