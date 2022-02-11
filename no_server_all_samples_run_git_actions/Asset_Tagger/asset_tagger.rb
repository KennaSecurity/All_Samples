# kenna-asset-tagger
require 'rest-client'
require 'json'
require 'csv'
require 'ipaddr'
require 'thread'
require 'monitor'

@token = ARGV[0]
@csv_file = ARGV[1] # source data
@tag_column_file = ARGV[2] # tag meta data - column from source file and tag prefix
@hostname = ARGV[3] # column name in source file which holds the search field data or empty string

# @asset_api_url = 'https://api.kennasecurity.com/assets'
@asset_api_url = 'https://api.kennasecurity.com/assets' # US AWS
# @asset_api_url = 'https://api.us.kennasecurity.com/assets' # US GCP
# @asset_api_url = 'https://api.ca.kennasecurity.com/assets' # Canada
# @asset_api_url = 'https://api.eu.kennasecurity.com/assets' # Europe

@search_url = @asset_api_url + '/search?q='
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json' }
@debug = false
@max_retries = 5
@start_time = Time.now
@output_filename = Logger.new("kenna-asset-tagger_log-#{@start_time.strftime('%Y%m%dT%H%M')}.txt")

# Encoding characters
@enc_colon = '%3A'
@enc_dblquote = '%22'
@enc_space = '%20'

def build_hostname_url(hostname)
  puts 'building hostname url' if @debug
  substring_host = hostname[/[^.]+/]
  return "hostname#{@enc_colon}#{@enc_dblquote}#{substring_host}#{@enc_dblquote}"

  # In case you want to look for all the hostnames starting with a string, use the following command
  # return "hostname#{@enc_colon}#{@enc_dblquote}#{substring_host}*#{@enc_dblquote}"
end

# Set a finite number of simultaneous worker threads that can run
thread_count = 20

# Create an array to keep track of threads
threads = Array.new(thread_count)

# Create a work queue for the producer to give work to the consumer
work_queue = SizedQueue.new(thread_count)

# Add a monitor so we can notify when a thread finishes and we can schedule a new one
threads.extend(MonitorMixin)

# Add a condition variable on the monitored array to tell the consumer to check the thread array
threads_available = threads.new_cond

# Add a variable to tell the consumer that we are done producing work
sysexit = false

## Set columns to use for tagging, if a @tag_column_file is provided

tag_columns = []
tag_list = []

## Set columns to use for tagging, if a @tag_column_file is provided

if !@tag_column_file.empty? then

  CSV.foreach(@tag_column_file, :headers => true, :encoding => 'UTF-8') {|row|
    tag_columns << Array[row[0], row[1]]
  }

  puts "tag_columns = #{tag_columns.to_s}" if @debug
end

num_lines = CSV.read(@csv_file).length

@output_filename.info("Processing CSV total lines #{num_lines}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")

producer_thread = Thread.new do
  puts 'starting producer loop' if @debug

  ## Iterate through CSV
  CSV.foreach(@csv_file, :headers => true, :encoding => 'UTF-8', :col_sep => ',') {|row|

    current_line = $.

    asset_identifier = nil
    asset_id = nil

    @output_filename.info("Reading line #{$.}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")

    @search_field = 'hostname'

    if @search_field == 'hostname' then
      if !row["#{@hostname}"].nil? && !row["#{@hostname}"].empty? then
        api_query = build_hostname_url(row["#{@hostname}"])
        puts api_query if @debug
      else
        next
      end
    end

    api_query = api_query.gsub(' ', @enc_space)

    query_url = "#{@search_url}#{api_query}"

    @output_filename.info("Query URL...#{query_url}\n")

    tag_list = []
    pull_string = ""
    if tag_columns.count > 0 then
      tag_columns.each{|item|
        pull_column = []
        pull_string = ""
        pull_column = CSV.parse_line("#{item[0]}")
        puts "=== pull_column: " + pull_column.to_s if @debug
        pull_column.each{|col|
          pull_string << "#{row[col]} "
          puts "=== pull_string: " + pull_string.to_s if @debug
        }
        puts "=== pull_string: " + pull_string.to_s if @debug
        if !pull_string.nil? && !pull_string.empty? then
          if !item[1].nil? then
            tag_list << "#{item[1]}#{pull_string}"
          else
            tag_list << "#{pull_string}"
          end
        end
      }
    end

    asset_update_string = ""

    tag_string = pull_string

    puts "tag string = #{tag_string}" if @debug

    work_queue << Array[query_url,tag_string,asset_update_string]

    threads.synchronize do
      threads_available.signal
    end

  }
  # Tell the consumer that we are finished loading the rows
  sysexit = true
end

consumer_thread = Thread.new do
  loop do
    @retries = 0
    puts "at start of consumer loop" if @debug

    # Stop looping when the producer is finished producing work
    work_to_do = []
    work_to_do = work_queue.pop
    break if sysexit && work_queue.nil?
    found_index = nil

    # The MonitorMixin requires us to obtain a lock on the threads array in case
    # a different thread may try to make changes to it.
    threads.synchronize do
      # First, wait on an available spot in the threads array.  This fires every
      # time a signal is sent to the "threads_available" variable
      threads_available.wait_while do
        sleep(1.0/5.0)
        threads.select { |thread| thread.nil? || thread.status == false  ||
                                  thread["finished"].nil? == false}.length == 0
      end
      # Once an available spot is found, get the index of that spot so we may
      # use it for the new thread
      found_index = threads.rindex { |thread| thread.nil? || thread.status == false ||
                                              thread["finished"].nil? == false }
      puts "i just found index = #{found_index}" if @debug
    end
    # Get a new unit of work from the work queue

    threads[found_index] = Thread.new(work_to_do) do
      puts "starting the thread loop" if @debug

      query_url = work_to_do[0]
      tag_string = work_to_do[1]
      asset_string = work_to_do[2]

      begin
        query_response = RestClient::Request.execute(
          method: :get,
          proxy: @proxy_string,
          url: query_url,
          headers: @headers
        )
        rescue RestClient::TooManyRequests =>e
          retry
        rescue RestClient::UnprocessableEntity => e
          @output_filename.error("Unable to get Asset - #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
          puts "Unable to get Asset: #{e.message}"
          Thread.exit
        rescue URI::InvalidURIError => e
          @output_filename.error("Unable to get Assets - InvalidURI: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
          puts "Unable to get assets: #{e.backtrace.inspect}"
          Thread.exit
        rescue RestClient::Exception => e
          @retries ||= 0
          if @retries < @max_retries
            @retries += 1
            sleep(15)
            retry
          else
            @output_filename.error("General RestClient error #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
            puts "Unable to get assets: #{e.message}"
            Thread.exit
          end
        rescue Exception => e
          @output_filename.error("Unable to get vulns - general exception: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
          puts "Unable to get vulns: #{e.backtrace.inspect}"
          Thread.exit
      end
      query_meta_json = JSON.parse(query_response)["meta"]
      total_found = query_meta_json.fetch("total_count")
      if total_found == 0 then
        @output_filename.error("Asset not found - #{query_url}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
        puts "No matching assets found for #{query_url}" if @debug
        Thread.current["finished"] = true
        threads.synchronize do
          threads_available.signal
        end
      else
        pages = query_meta_json.fetch("pages")
        query_response_json = JSON.parse(query_response)["assets"]

        query_response_json.each do |item|
          asset_id = item["id"]
          #puts asset_id

          begin

            if !tag_string.empty? then
              tag_update_json = {
                'asset' => {
                  'tags' => "#{tag_string}"
                }
              } ## Push tags to assets

              tag_api_url = "#{@asset_api_url}/#{asset_id}/tags"

              @output_filename.info("Post tag URL...#{tag_api_url}\n")
              @output_filename.info("tag json...#{tag_update_json.to_s}\n")

                tag_update_response = RestClient::Request.execute(
                  method: :put,
                  url: tag_api_url,
                  headers: @headers,
                  proxy: @proxy_string,
                  payload: tag_update_json,
                  timeout: 10
                )
              end
              if !asset_string.empty? then
                asset_update_json = JSON.parse(asset_string)

                update_api_url = "#{@asset_api_url}/#{asset_id}"
                @output_filename.info("Post asset URL...#{update_api_url}\n")
                @output_filename.info("asset update json...#{asset_update_json.to_s}\n")
                  update_response = RestClient::Request.execute(
                    method: :put,
                    url: update_api_url,
                    headers: @headers,
                    proxy: @proxy_string,
                    payload: asset_update_json
                  )
              end
          rescue RestClient::TooManyRequests =>e
            retry
          rescue RestClient::UnprocessableEntity => e
            @output_filename.error("Unable to update - UnprocessableEntity: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
            puts "Unable to update: #{e.message}"
            Thread.exit
          rescue RestClient::BadRequest => e
            @output_filename.error("Unable to update - BadRequest: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
            puts "Unable to update: #{e.message}"
            Thread.exit
          rescue RestClient::Exception => e
            @retries ||= 0
            if @retries < @max_retries then
              @retries += 1
              sleep(15)
              retry
            else
              @output_filename.error("General RestClient in tag update error #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n)")
              puts "Unable to update: #{e.message}"
              Thread.exit
            end
          rescue Exception => e
            @output_filename.error("Unable to get vulns - general exception: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
            puts "Unable to get vulns: #{e.backtrace.inspect}"
            Thread.exit
          end
        end
      end
      threads.synchronize do
        threads_available.signal
      end
    end
    threads.synchronize do
      threads_available.signal
    end
  end
  threads.synchronize do
    threads_available.signal
  end
end

# Join on both the producer and consumer threads so the main thread doesn't exit while
# they are doing work.
producer_thread.join
consumer_thread.join 1

# Join on the child processes to allow them to finish (if any are left)
threads.each do |thread|
  thread.join unless thread.nil?
end

puts "DONE!"
