# kenna-bulk-custom-field-update
require 'rest-client'
require 'json'
require 'csv'


#These are the arguments we are expecting to get - header file can be send as third parameter if not included as row 1 in csv
@token = ARGV[0]
@csv_file = ARGV[1] #name of the output csv file
ARGV.length == 3 ? @base_url = ARGV[2] : @base_url = "https://api.kennasecurity.com/"


@max_retries =5
start_time = Time.now
output_filename = Logger.new("kenna_bulk_status_update_log-#{start_time.strftime("%Y%m%dT%H%M")}.txt")

@debug = false

#Variables we'll need later
@asset_group_url = "#{@base_url}asset_groups?"

@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token }

def get_data(get_url)
  puts "starting query" if @debug
  puts "get data url = #{get_url}" if @debug
  query_return = ""
   begin
      query_return = RestClient::Request.execute(
        :method => :get,
        :url => get_url,
        :headers => @headers
      )
      rescue RestClient::TooManyRequests =>e
        retry
      rescue RestClient::UnprocessableEntity => e
        puts "unprocessible entity: #{e.message}"
      rescue RestClient::BadRequest => e
        @output_filename.error("Rest client BadRequest: #{get_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{@start_time.to_s})")
        puts "BadRequest: #{e.backtrace.inspect}"
      rescue RestClient::Exception => e
        @retries ||= 0
        if @retries < @max_retries
          @retries += 1
          sleep(15)
          retry
        else
          @output_filename.error("General RestClient error #{get_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{@start_time.to_s})")
          puts "Unable to get vulns: #{e.backtrace.inspect}"
        end
      rescue Exception => e
        @output_filename.error("General Exception: #{get_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{@start_time.to_s})")
        puts "BadRequest: #{e.backtrace.inspect}"
    end
  return query_return
end

# Encoding characters
enc_colon = "%3A"
enc_dblquote = "%22"
enc_space = "%20"

page = 1

morerows = true
CSV.open( @csv_file, 'w' ) do |writer|

  writer << ["Risk Meter ID", "Risk Meter Name", "Query String", "Asset Count","Vuln Count", "Created", "Updated"]

  while morerows

  query_response = get_data("#{@asset_group_url}page=#{page}")
  meta = JSON.parse(query_response.body)["meta"]
  max_pages = meta.fetch("pages")
  #puts "The number of max pages is #{max_pages}"

  asset_groups = JSON.parse(query_response.body)["asset_groups"]
    asset_groups.each do |item|
      rm_id = item["id"]
      rm_name = item["name"]
      rm_query = URI.decode(item["querystring"])
      rm_assets = item["asset_count"]
      rm_vulns = item["vulnerability_count"]
      rm_created = item["created_at"]
      rm_updated = item["updated_at"]
      writer << ["#{rm_id}", "#{rm_name}", "#{rm_query}","#{rm_assets}", "#{rm_vulns}","#{rm_created}", "#{rm_updated}"]

    end 

    if max_pages > page then
      page = page + 1
      #puts "Processing page number #{page}"
    else
      morerows = false
    
    end
  end
end

puts "Processing complete!"
