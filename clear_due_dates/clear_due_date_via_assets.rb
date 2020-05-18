# kenna-bulk-custom-field-update
require 'rest-client'
require 'json'

#These are the arguments we are expecting to get 
@token = ARGV[0]
@assets_per_update = ARGV[1] #number of assets to update at one time to keep the vuln pull under 20 pages


#Variables we'll need later
@post_url = 'https://api.kennasecurity.com/vulnerabilities/bulk'
@vuln_url = 'https://api.kennasecurity.com/vulnerabilities/search'
@asset_url = 'https://api.kennasecurity.com/assets/search'
@headers = {'Content-type' => 'application/json', 'X-Risk-Token' => @token }

@max_retries = 5

start_time = Time.now
@output_filename = Logger.new("clear_due_date-#{start_time.strftime("%Y%m%dT%H%M")}.txt")
@debug = false
@vuln_update_count = 0
@vuln_total_count = 0
@asset_count = 0


# Encoding characters
enc_colon = "%3A"
enc_dblquote = "%22"
enc_space = "%20"

def bulkUpdate(vulnids)
  puts "starting bulk update" if @debug
  json_string = nil
  json_string = "{\"vulnerability_ids\": #{vulnids}, "
  json_string = "#{json_string}\"vulnerability\": {"
  json_string = "#{json_string}\"due_date\": \" \"}}"

  puts json_string if @debug

  begin
    query_post_return = RestClient::Request.execute(
      method: :put,
      url: @post_url,
      payload: json_string,
      headers: @headers
    )
  rescue RestClient::TooManyRequests =>e
    retry
  rescue RestClient::UnprocessableEntity => e
    puts "UnprocessableEntity"
    puts e.backtrace.inspect
  rescue RestClient::BadRequest => e
    @output_filename.error("Async BadRequest: #{post_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{start_time.to_s})")
    puts "Async BadRequest: #{e.message}"
  rescue RestClient::Exception => e
    @retries ||= 0
    if @retries < @max_retries
      @retries += 1
      sleep(15)
      retry
    else
      @output_filename.error("Async General RestClient error #{post_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{start_time.to_s})")
      puts "Async Unable to get vulns: #{e.message}"
    end
  rescue Exception => e
    @output_filename.error("Unable to get vulns - general exception: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})")
    puts "Unable to get vulns: #{e.message} #{e.backtrace.inspect}"
  end
end

def get_data(get_url)
  puts "starting query" if @debug
  puts "get data url = #{get_url}" if @debug
  query_return = ""
   begin
      query_return = RestClient::Request.execute(
        method: :get,
        url: get_url,
        headers: @headers
      )
      rescue RestClient::TooManyRequests =>e
        retry
      rescue RestClient::UnprocessableEntity => e
        puts "unprocessible entity: #{e.message}"
      rescue RestClient::BadRequest => e
        @output_filename.error("BadRequest: #{post_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{@start_time.to_s})")
        log_output.close
        puts "BadRequest: #{e.backtrace.inspect}"
      rescue RestClient::Exception => e
        @retries ||= 0
        if @retries < @max_retries
          @retries += 1
          sleep(15)
          retry
        else
          @output_filename.error("General RestClient error #{post_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{@start_time.to_s})")
          puts "Unable to get vulns: #{e.backtrace.inspect}"
        end
      rescue Exception => e
        @output_filename.error("BadRequest: #{post_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{@start_time.to_s})")
        puts "BadRequest: #{e.backtrace.inspect}"
    end
  return query_return
end

pages = 0
page = 1
page_json = ''
assetQuery = "#{@asset_url}?status%5B%5D=active&vulnerability%5Bq%5D=_exists_%3Adue_date"
asset_json = JSON.parse(get_data(assetQuery))
if !asset_json.nil? then
  pages = asset_json["meta"].fetch("pages")
  puts asset_json["meta"].fetch("total_count")
  @asset_count = @asset_count + asset_json["meta"].fetch("total_count")
  puts asset_json["meta"].fetch("total_count")
  while page < pages+1 do 
    asset_array = []
    puts "pages = #{pages} and page = #{page}" if @debug
    if page ==1 then
      page_json = asset_json["assets"]
    else 
      asset_json = JSON.parse(get_data("#{assetQuery}&page=#{page}"))
      page_json = asset_json["assets"]
    end
    page_json.each do |asset| 
      asset_array << asset.fetch("id")
    end
    asset_array.each_slice(@assets_per_update.to_i) do |a|
      asset_string = a.join('&asset%5Bid%5D%5B%5D=')
      vuln_query = "#{@vuln_url}?asset%5Bid%5D%5B%5D=#{asset_string}&q=_exists_%3Adue_date"
      vuln_pages = 0
      vuln_page = 1
      vuln_json = JSON.parse(get_data(vuln_query))
      if !vuln_json.nil? then
        vuln_pages = vuln_json["meta"].fetch("pages")
        @vuln_total_count = @vuln_total_count + vuln_json["meta"].fetch("total_count").to_i
        if vuln_pages > 20 then
          puts "TOO MANY VULNS RERUN WITH A LOWER ASSET COUNT PER BLOCK"
          abort
        end
        vuln_array = []
        while vuln_page < vuln_pages+1 do 
          puts "vuln pages = #{vuln_pages} and vuln page = #{vuln_page}" if @debug
          if vuln_page ==1 then
            vuln_page_json = vuln_json["vulnerabilities"]
          else 
            vuln_json = JSON.parse(get_data("#{vuln_query}&page=#{vuln_page}"))
            vuln_page_json = vuln_json["vulnerabilities"]
          end
          vuln_page_json.each do |vuln| 
            vuln_array << vuln.fetch("id")
          end

          vuln_page += 1
        end
        @vuln_update_count = @vuln_update_count + vuln_array.size
        vuln_array.each_slice(7000) do |b|
          bulkUpdate(b)
        end 
      end
    end
    page += 1 
  end
  puts "total vuln count = #{@vuln_total_count}"
  puts "total asset count = #{@asset_count}"
  puts "vuln update count = #{@vuln_update_count}"
end


