# kenna-bulk-custom-field-update
require 'rest-client'
require 'json'

#These are the arguments we are expecting to get 
@token = ARGV[0]
@assets_per_update = ARGV[1] #number of assets to update at one time to keep the vuln pull under 20 pages
ARGV.length == 3 ? @add_query = ARGV[2] : @add_query = nil #unencoded query string to add to search
ARGV.length == 4 ? @base_url = ARGV[3] : @base_url = "https://api.kennasecurity.com/" #set only for KPD or EU

#Variables we'll need later
@post_url = "#{@base_url}vulnerabilities/bulk"
@vuln_url = "#{@base_url}vulnerabilities/search"
@data_export_url = "#{@base_url}data_exports"

@headers = {'Content-type' => 'application/json', 'X-Risk-Token' => @token }

@max_retries = 5

start_time = Time.now
@output_filename = Logger.new("clear_due_date-#{start_time.strftime("%Y%m%dT%H%M")}.txt")
@debug = false

def bulkUpdate(vulnids)
  puts "starting bulk update" if @debug
  json_string = nil
  json_string = "{\"vulnerability_ids\": #{vulnids}, "
  json_string = "#{json_string}\"vulnerability\": {"
  json_string = "#{json_string}\"due_date\": \" \"}}"

  puts json_string if @debug

  begin
    query_post_return = RestClient::Request.execute(
      :method => :put,
      :url => @post_url,
      :payload => json_string,
      :headers => @headers
    )
  rescue RestClient::TooManyRequests =>e
    retry
  rescue RestClient::UnprocessableEntity => e
    puts "UnprocessableEntity"
    puts e.backtrace.inspect
  rescue RestClient::BadRequest => e
    @output_filename.error("Async BadRequest: #{@post_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{start_time.to_s})")
    puts "Async BadRequest: #{e.message}"
  rescue RestClient::Exception => e
    @retries ||= 0
    if @retries < @max_retries
      @retries += 1
      sleep(15)
      retry
    else
      @output_filename.error("Async General RestClient error #{@post_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{start_time.to_s})")
      puts "Async Unable to get vulns: #{e.message}"
    end
  rescue Exception => e
    @output_filename.error("Unable to get vulns - general exception: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})")
    puts "Unable to get vulns: #{e.message} #{e.backtrace.inspect}"
  end

  @output_filename.error("bulk vuln update status: #{JSON.parse(query_post_return.body)}... time: #{Time.now.to_s}\n")
end

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
      @output_filename.error("BadRequest: #{@post_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{@start_time.to_s})")
      puts "BadRequest: #{e.backtrace.inspect}"
    rescue RestClient::Exception => e
      @retries ||= 0
      if @retries < @max_retries
        @retries += 1
        sleep(15)
        retry
      else
        @output_filename.error("General RestClient error #{@post_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{@start_time.to_s})")
        puts "Unable to get vulns: #{e.backtrace.inspect}"
      end
    rescue Exception => e
      @output_filename.error("BadRequest: #{@post_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{@start_time.to_s})")
      puts "BadRequest: #{e.backtrace.inspect}"
    end
  return query_return
end

def get_bulk_assets()
  puts "starting bulk query" if @debug
  q = "_exists_:due_date"
  q = "#{q} AND #{@add_query}" unless @add_query.nil? || @add_query.empty?
  bulk_query_json_string = "{\"status\": [\"active\"],"
  bulk_query_json_string = bulk_query_json_string + " \"vulnerability\":{ \"q\": \"#{q}\"},"
  bulk_query_json_string = bulk_query_json_string + " \"export_settings\": { \"format\": \"json\", "
  bulk_query_json_string = bulk_query_json_string + "\"compression\": \"gzip\", \"model\": \"asset\" }}"

  bulk_query_json = JSON.parse(bulk_query_json_string)

  puts bulk_query_json.to_s
  begin
    query_response = RestClient::Request.execute(
      :method => :post,
      :url => @data_export_url,
      :headers => @headers,
      :payload => bulk_query_json
    ) 
    puts query_response if @debug
    query_response_json = JSON.parse(query_response.body)
    searchID = query_response_json.fetch("search_id")
    #searchID = 1079331
    puts "searchID = #{searchID}" if @debug
    output_results = "myoutputfile_#{searchID}.gz"
    searchComplete = false

    while searchComplete == false
      
      status_code = RestClient.get("#{@data_export_url}/status?search_id=#{searchID}", @headers).code

      puts "status code =#{status_code}" if @debug
      if status_code != 200 then 
        puts "sleeping for async query (data export)" if @debug
        sleep(60)
        next
      else
        puts "ansyc query complete (data export)" if @debug
        searchComplete = true

        # Download the gzip file.
        File.open(output_results, 'w') {|f|
          block = proc { |response|
            response.read_body do |chunk| 
              f.write chunk
            end
          }
          RestClient::Request.new(:method => :get, :url => "#{@data_export_url}?search_id=#{searchID}", :headers => @headers, :block_response => block).execute
        }
        
        # Open the gzip file and process.
        gzfile = open(output_results)
        gz = Zlib::GzipReader.new(gzfile)
        json_data = JSON.parse(gz.read)["assets"]
      end
    end
  rescue RestClient::TooManyRequests => e
    retry
  rescue RestClient::UnprocessableEntity => e
    puts "unprocessible entity: #{e.message}"
  rescue RestClient::BadRequest => e
    @output_filename.error("Rest client BadRequest:...#{e.message} (time: #{Time.now.to_s}, start time: #{@start_time.to_s})")
    puts "BadRequest: #{e.backtrace.inspect}"
  rescue RestClient::Exception => e
    @retries ||= 0
    if @retries < @max_retries
      @retries += 1
      sleep(15)
      retry
    else
      @output_filename.error("General RestClient error... #{e.message}(time: #{Time.now.to_s}, start time: #{@start_time.to_s})")
      puts "Unable to process bulk request: #{e.backtrace.inspect}"
    end
  rescue Exception => e
    @output_filename.error("General Exception:...#{e.message} (time: #{Time.now.to_s}, start time: #{@start_time.to_s})")
    puts "BadRequest: #{e.backtrace.inspect}"
  end
  File.delete output_results
  return json_data
end
asset_array = []
asset_json = get_bulk_assets
if !asset_json.nil? then
  asset_json.each do |asset| 
    asset_array << asset.fetch("id")
  end
  asset_array.each_slice(@assets_per_update.to_i) do |a|
    asset_string = a.join('&asset%5Bid%5D%5B%5D=')
    vuln_query = "#{@vuln_url}?asset%5Bid%5D%5B%5D=#{asset_string}&q=_exists_%3Adue_date"
    vuln_query = "#{vuln_query}+AND+#{URI.escape(@add_query)}" unless @add_query.nil? || @add_query.empty?
    vuln_pages = 0
    vuln_page = 1
    vuln_json = JSON.parse(get_data(vuln_query))
    if !vuln_json.nil? then
      vuln_pages = vuln_json["meta"].fetch("pages")
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
      vuln_array.each_slice(7000) do |b|
        bulkUpdate(b)
      end 
    end
  end
end


