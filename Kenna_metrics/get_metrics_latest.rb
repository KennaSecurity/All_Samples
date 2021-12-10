# kenna-bulk-custom-field-update
require 'rest-client'
require 'json'
require 'csv'
# require 'pry'

#These are the arguments we are expecting to get - header file can be send as third parameter if not included as row 1 in csv
@token = ARGV[0]
@csv_file = ARGV[1] #name of the output csv file

@max_retries =5
start_time = Time.now
@output_filename = "kenna_bulk_status_update_log-#{start_time.strftime("%Y%m%dT%H%M")}.txt"

@debug = true

#Variables we'll need later
#for GCP use the below url
#@asset_group_url = 'https://api.us.kennasecurity.com/asset_groups'
@asset_group_url = 'https://api.kennasecurity.com/asset_groups'
@mttr_url = "report_query/historical_mean_time_to_remediate_by_risk_level"
@category_url = "/report_query/historical_open_vulnerability_count_by_risk_level"
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token }

tag_columns = []

# Encoding characters
enc_colon = "%3A"
enc_dblquote = "%22"
enc_space = "%20"

###################################################
# Helpers
###################################################
def get_historic_scores(riskmeter_id)
  #Get List of Scores in a hash
  #     using .... https://api.us.kennasecurity.com/asset_groups/94571/report_query/historical_risk_meter_scores

  rm_history_query = "#{@asset_group_url}/#{riskmeter_id}/report_query/historical_mean_time_to_remediate_by_risk_level"

  begin
    query_response = RestClient::Request.execute(
      method: :get,
      url: rm_history_query,
      headers: @headers
    )
  rescue RestClient::UnprocessableEntity
    log_output = File.open(@output_filename,'a+')
    log_output << "UnprocessableEntity: #{rm_history_query}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
    log_output.close
    puts "BadRequest: #{asset_group_url}"
  rescue RestClient::BadRequest
    log_output = File.open(@output_filename,'a+')
    log_output << "BadRequest: #{rm_history_query}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
    log_output.close
    puts "BadRequest: #{rm_history_query}"
  rescue RestClient::Exception
    @retries ||= 0
    if @retries < @max_retries
      @retries += 1
      sleep(15)
      retry
    else
      log_output = File.open(@output_filename,'a+')
      log_output << "General RestClient error #{rm_history_query}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
      log_output.close
      puts "Unable to get vulns: #{rm_history_query}"

    end
  end

end

def get_mttr_counts(riskmeter_id)
  rm_mttr_query = "#{@asset_group_url}/#{riskmeter_id}/report_query/historical_mean_time_to_remediate_by_risk_level"
  begin
    query_response = RestClient::Request.execute(
      method: :get,
      url: rm_mttr_query,
      headers: @headers
    )
  rescue RestClient::UnprocessableEntity
    log_output = File.open(@output_filename,'a+')
    log_output << "UnprocessableEntity: #{rm_mttr_query}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
    log_output.close
    puts "BadRequest: #{rm_mttr_query}"
  rescue RestClient::BadRequest
    log_output = File.open(@output_filename,'a+')
    log_output << "BadRequest: #{rm_mttr_query}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
    log_output.close
    puts "BadRequest: #{rm_mttr_query}"
  rescue RestClient::Exception
    @retries ||= 0
    if @retries < @max_retries
      @retries += 1
      sleep(15)
      retry
    else
      log_output = File.open(@output_filename,'a+')
      log_output << "General RestClient error #{rm_mttr_query}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
      log_output.close
      puts "Unable to get vulns: #{rm_mttr_query}"

    end
  end

  query_response_mttr_json = JSON.parse(query_response.body)
  response = query_response_mttr_json["mttr"]

end

def get_category_counts(riskmeter_id)
  rm_category_query = "#{@asset_group_url}/#{riskmeter_id}/#{@category_url}"
  begin
    query_response = RestClient::Request.execute(
      method: :get,
      url: rm_category_query,
      headers: @headers
    )
  rescue RestClient::UnprocessableEntity
    log_output = File.open(@output_filename,'a+')
    log_output << "UnprocessableEntity: #{rm_mttr_query}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
    log_output.close
    puts "BadRequest: #{rm_mttr_query}"
  rescue RestClient::BadRequest
    log_output = File.open(@output_filename,'a+')
    log_output << "BadRequest: #{rm_mttr_query}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
    log_output.close
    puts "BadRequest: #{rm_mttr_query}"
  rescue RestClient::Exception
    @retries ||= 0
    if @retries < @max_retries
      @retries += 1
      sleep(15)
      retry
    else
      log_output = File.open(@output_filename,'a+')
      log_output << "General RestClient error #{rm_mttr_query}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
      log_output.close
      puts "Unable to get vulns: #{rm_mttr_query}"

    end
  end

  query_response_mttr_json = JSON.parse(query_response.body)
  response = query_response_mttr_json["historical_vulnerability_count_by_risk"]

end


# binding.pry
###################################################
# Main Loop
###################################################
begin
  query_response = RestClient::Request.execute(
    method: :get,
    url: @asset_group_url,
    headers: @headers
  )
rescue RestClient::UnprocessableEntity
  log_output = File.open(@output_filename,'a+')
  log_output << "UnprocessableEntity: #{@asset_group_url}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
  log_output.close
  puts "BadRequest: #{asset_group_url}"
rescue RestClient::BadRequest
  log_output = File.open(@output_filename,'a+')
  log_output << "BadRequest: #{@asset_group_url}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
  log_output.close
  puts "BadRequest: #{@asset_group_url}"
rescue RestClient::Exception
  @retries ||= 0
  if @retries < @max_retries
    @retries += 1
    sleep(15)
    retry
  else
    log_output = File.open(@output_filename,'a+')
    log_output << "General RestClient error #{@asset_group_url}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
    log_output.close
    puts "Unable to get vulns: #{@asset_group_url}"

  end
end
header_needed = true
header_needed = false if File.exist?(@csv_file)
CSV.open( @csv_file, 'a+' ) do |writer|
  if header_needed then
    writer << ["Risk Meter ID", "Risk Meter Name", "Risk Meter Score", "Asset Count", "Vuln Count", "Fix Count", "Unique Open CVEs","Top Priority","Active Breach", "Easily Exploitable", "Predicted Exploitable", "Malware Exploitable", "Popular Targets","Highest Score","Highest Score Date", "Lowest Score", "Lowest Score Date","Vuln Density","Last Week","Last Month","90 Days Ago","MTTR-All","MTTR-High","MTTR-Med","MTTR-Low","OPEN-High","OPEN-Med","OPEN-Low"]
  end
  query_response_json = JSON.parse(query_response.body)["asset_groups"]
  if @debug then p query_response_json.size end
  query_response_json.each do |item|

    # binding.pry
    puts "#{item["name"]}"

    rm_id = item["id"]
    # DBB - New Stuff
    rm_name = item["name"]
    rm_risk_meter_score = item["risk_meter_score"]
    rm_asset_count = item["asset_count"]
    rm_vulnerability_count = item["vulnerability_count"]
    rm_fix_count = item["fix_count"]
    rm_unique_open_cve_count = item["unique_open_cve_count"]
    rm_top_priority_count = item["top_priority_count"]
    rm_active_internet_breaches_count = item["active_internet_breaches_count"]
    rm_easily_exploitable_count = item["easily_exploitable_count"]
    rm_predicted_exploitable_count = item["predicted_exploitable_count"]
    rm_malware_exploitable_count = item["malware_exploitable_count"]
    rm_popular_targets_count = item["popular_targets_count"]
    #"Highest Score",
    rm_highest_score = item["highest_score"]["score"]
    # "Highest Score Date",
    rm_highest_score_date = item["highest_score"]["date"]
    # "Lowest Score",
    rm_lowest_score = item["lowest_score"]["score"]
    # "Lowest Score Date",
    rm_lowest_score_date = item["highest_score"]["date"]
    # "Vuln Density",
    rm_vuln_density = item["vulnerability_density"]
    # "Last Week"
    if !item["score_last_week"].nil?
      rm_last_week_score = item["score_last_week"]["score"]
    else
      rm_last_week_score = ""
    end
    # "Last Month"
    if !item["score_last_month"].nil?
      rm_last_month_score = item["score_last_month"]["score"]
    else
      rm_last_month_score = ""
    end

    # "90 Days Ago"
    if !item["score_90_days_ago"].nil?
      rm_90_days_ago_score = item["score_90_days_ago"]["score"]
    else
      rm_90_days_ago_score = ""
    end

    sleep(0.05)
    # "MTTR Counts"
    mttr_counts = get_mttr_counts(rm_id)
    rm_mttr_all = mttr_counts["All vulnerabilities"]
    rm_mttr_high = mttr_counts["High risk"]
    rm_mttr_med = mttr_counts["Medium risk"]
    rm_mttr_low = mttr_counts["Low risk"]

    sleep(0.05)
    # "Category Counts"
    category_counts = get_category_counts(rm_id).values.last
    rm_category_high = category_counts["high"].to_i
    rm_category_med = category_counts["medium"].to_i
    rm_category_low = category_counts["low"].to_i

    writer << ["#{rm_id}", "#{rm_name}", "#{rm_risk_meter_score}", "#{rm_asset_count}", "#{rm_vulnerability_count}", "#{rm_fix_count}", "#{rm_unique_open_cve_count}", "#{rm_top_priority_count}", "#{rm_active_internet_breaches_count}", "#{rm_easily_exploitable_count}", "#{rm_predicted_exploitable_count}", "#{rm_malware_exploitable_count}", "#{rm_popular_targets_count}","#{rm_highest_score}", "#{rm_highest_score_date}", "#{rm_lowest_score}", "#{rm_lowest_score_date}", "#{rm_vuln_density}", "#{rm_last_week_score}", "#{rm_last_month_score}", "#{rm_90_days_ago_score}", "#{rm_mttr_all}", "#{rm_mttr_high}", "#{rm_mttr_med}", "#{rm_mttr_low}", "#{rm_category_high}", "#{rm_category_med}", "#{rm_category_low}"]

    sleep(0.10)

  end
end
