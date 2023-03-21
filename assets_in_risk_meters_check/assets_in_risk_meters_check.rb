# kenna-bulk-custom-field-update
require 'rest-client'
require 'json'
require 'csv'
require 'thread'
require 'monitor'
require 'ipaddr'

#These are the arguments we are expecting to get - header file can be send as third parameter if not included as row 1 in csv
@token = ARGV[0]
@meta_file = ARGV[1] #source data
@rm_id_column = ARGV[2] #name of rm id column in csv file
@tag_column = ARGV[3] #name of the tag for the column

#Variables we'll need later
@asset_api_url = 'https://api.kennasecurity.com/assets'
@asset_bulk_url = '/bulk'
@search_url = "/search?" 
@headers = {'Content-Type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json'}

@start_time = Time.now

@output_filename = "kenna_asset_meter_check-#{@start_time.strftime("%Y%m%dT%H%M")}.txt"

@max_retries = 5
@debug = false

# Set a finite number of simultaneous worker threads that can run
thread_count = 5

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

def find_json_status?(json)
  begin
    return json.fetch("status") == "incomplete"
  rescue Exception => e
    puts("json.fetch(): #{e.message}")
    return false
  end
end

def bulkUpdate(assets, tag_value)
  query_post_return = nil 
  puts "made it to bulk update"
  puts "tag value in bulk update = #{tag_value}"
  post_url = "#{@asset_api_url}#{@asset_bulk_url}"
  puts post_url
  holder = "{\"asset_ids\": #{assets.to_s}, \"asset\": {\"tags\": [\"#{tag_value}\"]},\"realtime\": true}"
  puts holder if @debug

  begin
    query_post_return = RestClient::Request.execute(
      :method => :put,
      :url => post_url,
      :payload => holder,
      :headers => @headers
    )
  rescue RestClient::UnprocessableEntity => e
    log_output = File.open(@output_filename,'a+')
    log_output << "UnprocessableEntity: #{post_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n"
    log_output.close
    puts "UnprocessableEntity: #{e.message}"

  rescue RestClient::BadRequest => e
    log_output = File.open(@output_filename,'a+')
    log_output << "BadRequest: #{post_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n"
    log_output.close
    puts "BadRequest: #{e.message}"
  rescue RestClient::Exception => e
    @retries ||= 0
    if @retries < @max_retries
      @retries += 1
      sleep(15)
      retry
    else
      log_output = File.open(@output_filename,'a+')
      log_output << "General RestClient error #{post_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n"
      log_output.close
      puts "Unable to get vulns: #{e.message}"
    end
  rescue Exception => e
    puts "Exception: #{e.message}"
  end
  puts JSON.parse(query_post_return.body)
end

producer_thread = Thread.new do
  puts "starting producer loop" if @debug
  # For each item in the loop ...
  CSV.foreach(@meta_file, :headers => true) do |row|
    rm_id = row["#{@rm_id_column}"]
    tag_value = row["#{@tag_column}"]
    puts "got tag value #{tag_value}"

    # Search for assets in a risk meter by ID (rm_id).
    query_url = "#{@asset_api_url}#{@search_url}search_id=#{rm_id}"

    begin
      query_response = RestClient::Request.execute(
        :method => :get,
        :url => query_url,
        :headers => @headers
      )
    rescue RestClient::TooManyRequests
      log_output = File.open(@output_filename,'a+')
      log_output << "TooManyRequests: #{query_url}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n"
      log_output.close
      retry
    rescue RestClient::UnprocessableEntity 
      log_output = File.open(@output_filename,'a+')
      log_output << "UnprocessableEntity: #{query_url}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n"
      log_output.close
      puts "BadRequest: #{query_url}"
    rescue RestClient::BadRequest
      log_output = File.open(@output_filename,'a+')
      log_output << "BadRequest: #{query_url}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n"
      log_output.close
      puts "BadRequest: #{query_url}"
    rescue RestClient::Exception
      @retries ||= 0
      if @retries < @max_retries
        @retries += 1
        sleep(15)
        retry
      else
        log_output = File.open(@output_filename,'a+')
        log_output << "General RestClient error #{query_url}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n"
        log_output.close
        puts "Unable to get assets: #{query_url}"
        next
      end
    end
    puts query_response

    meta_response_json = JSON.parse(query_response.body)["meta"]
    tot_assets = meta_response_json.fetch("total_count")
    next if tot_assets == 0
    pages = meta_response_json.fetch("pages")
    log_output = File.open(@output_filename,'a+')
    log_output << "Checking #{query_url}. Total assets = #{tot_assets}\n"
    log_output.close

    asset_page_size = 500
    if pages > 20 then
      # Calculate new page size and round up to the nearest 100.
      asset_page_size = tot_assets / 20
      page_size_in_hundreds = (asset_page_size / 100) + 1
      asset_page_size = page_size_in_hundreds * 100
      puts("Page size modified to #{asset_page_size}\n")
    end

    log_output = File.open(@output_filename,'a+')
    log_output << "Starting Thread for #{query_url} Total assets = #{tot_assets}\n"
    log_output.close

    # Put the row on the work queue
    work_queue << Array[asset_page_size, query_url, tag_value]
    
    # Tell the consumer to check the thread array so it can attempt to schedule the
    # next job if a free spot exists.
    threads.synchronize do
      threads_available.signal
    end
  end
  # Tell the consumer that we are finished downloading currencies
  sysexit = true
end

## Iterate through CSV
consumer_thread = Thread.new do
  loop do
    if @debug then puts "at start of consumer loop" end 
    # Stop looping when the producer is finished producing work
    work_to_do = []
    # Get a new unit of work from the work queue
    work_to_do = work_queue.pop
    break if sysexit & work_queue.nil?
    found_index = nil

    # The MonitorMixin requires us to obtain a lock on the threads array in case
    # a different thread may try to make changes to it.
    threads.synchronize do
      sleep(1.0/5.0)
      if @debug then puts "looking for a thread" end
      # First, wait on an available spot in the threads array.  This fires every
      # time a signal is sent to the "threads_available" variable
      threads_available.wait_while do
        threads.select { |thread| thread.nil? || thread.status == false  ||
                                  thread["finished"].nil? == false}.empty?
        if @debug then puts "in threads_available loop" end
      end
      # Once an available spot is found, get the index of that spot so we may
      # use it for the new thread
      found_index = threads.rindex { |thread| thread.nil? || thread.status == false ||
                                              thread["finished"].nil? == false }

      if @debug then puts "i just found index = #{found_index}" end
    end

    asset_page_size = work_to_do[0]
    query_url = work_to_do[1]
    tag_value = work_to_do[2]

    puts "got tag value out of array #{tag_value}"
    
    #json_data = JSON.parse(custom_field_string)
    #puts "json_data = #{json_data}" if @debug

    threads[found_index] = Thread.new(work_to_do) do
      assets_array = []

      puts "starting regular query" if @debug
      query_url = "#{query_url}&per_page=#{asset_page_size}"

      begin
        query_response = RestClient::Request.execute(
          :method => :get,
          :url => query_url,
          :headers => @headers
        )
      
        meta_response_json = JSON.parse(query_response.body)["meta"]
        tot_assets = meta_response_json.fetch("total_count")
        log_output = File.open(@output_filename,'a+')
        log_output << "Processing = #{query_url}. Total assets = #{tot_assets}\n"
        log_output.close
        if @debug then puts "Processing #{query_url} Total assets = #{tot_assets}" end
        pages = meta_response_json.fetch("pages")
 
        endloop = pages + 1
        (1...endloop).step(1) do |i|
          puts "Currently processing page #{i} of #{pages}"
          #query_url = "#{query_url}&page=#{i}"
          puts "paging url = #{query_url}&page=#{i}" if @debug
 
          query_response = RestClient::Request.execute(
            :method => :get,
            :url => "#{query_url}&page=#{i}",
            :headers => @headers
          )
          # Build URL to set the custom field value for each vulnerability
          #counter = 0
          query_response_json = JSON.parse(query_response.body)["assets"]
          query_response_json.each do |item|
            asset_id = item["id"]
            assets_array << asset_id
            if assets_array.length == 30000 then
              bulkUpdate(assets_array,tag_value)
              assets_array = []
            end
          end
          bulkUpdate(assets_array,tag_value)
          Thread.current["finished"] = true
          threads.synchronize do
            threads_available.signal
          end
        end
      rescue RestClient::TooManyRequests =>e
        retry
      rescue RestClient::UnprocessableEntity => e
        log_output = File.open(@output_filename,'a+')
        log_output << "UnprocessableEntity: #{query_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n"
        log_output.close
        puts "BadRequest: #{e.message}"
      rescue RestClient::BadRequest => e
        log_output = File.open(@output_filename,'a+')
        log_output << "BadRequest: #{query_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n"
        log_output.close
        puts "BadRequest: #{e.message}"
      rescue RestClient::Exception => e
        @retries ||= 0
        puts "one #{@retries}"
        if @retries < @max_retries
          @retries += 1
          sleep(15)
          retry
        else
          log_output = File.open(@output_filename,'a+')
          log_output << "General RestClient error #{query_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n"
          log_output.close
          puts "Unable to get vulns: #{e.message}"
          next
        end
      end

      Thread.current["finished"] = true
      threads.synchronize do
        threads_available.signal
      end
    end  
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
