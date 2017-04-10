# kenna-asset-tagger
require 'rest-client'
require 'json'
require 'csv'
require 'ipaddr'
require 'thread'
require 'monitor'

#These are the arguments we are expecting to get - header file can be send as third parameter if not included as row 1 in csv
@token = ARGV[0]
@csv_file = ARGV[1] #source data
@tag_column_file = ARGV[2] #custom field id's and columns with data
@host_search_field = ARGV[3] #field to use first for asset match ip_address or hostname or empty string
@ip_address = ARGV[4] #column name in source file which holds the search field data or empty string
@hostname = ARGV[5] #column name in source file which holds the hostname data or empty string
ARGV.length == 7 ? @priority_column = ARGV[6] : @priority_column = nil #column that holds priority setting


@asset_api_url = 'https://api.kennasecurity.com/assets'
@async_api_url = 'https://api.kennasecurity.com/assets/create_async_search'
@search_url = @asset_api_url + '/search?q='
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json'}
@debug = false
@max_retries = 5

# Encoding characters
@enc_colon = "%3A"
@enc_dblquote = "%22"
@enc_space = "%20"
@custom_field_columns = [] 

start_time = Time.now
output_filename = "kenna_bulk_status_update_log-#{start_time.strftime("%Y%m%dT%H%M")}.txt"

@max_retries = 5
@debug = true

def build_ip_url(ipstring)
  puts "building ip url" if @debug
  url = ""
  if ipstring.index('/').nil? then
    subnet = IPAddr.new(ipstring)
    url = "ip:#{@enc_dblquote}#{subnet}#{@enc_dblquote}"
  else 
    subnet = IPAddr.new(ipstring)
    iprange = subnet.to_range()
    beginip = iprange.begin
    endip = iprange.end
    url = "ip:" + "[" + "#{beginip}" + " TO " + "#{endip}" + "]"
  end
  return url
end

def build_hostname_url(hostname)
  puts "building hostname url" if @debug
  return "hostname:#{@enc_dblquote}#{hostname}*#{@enc_dblquote}"
end

def is_ip?(str)
  !!IPAddr.new(str) rescue false
end

def Boolean(value)
  case value
  when true, 'true', 1, '1', 't' then true
  when false, 'false', nil, '', 0, '0', 'f' then false
  end
end

def find_json_status?(json)
  begin
    json.fetch("status") == "incomplete"
    return true
  rescue Exception => e
    return false
  end
end

def is_nil_and_empty(data)
     data.blank? || data.nil?
end  

# Set a finite number of simultaneous worker threads that can run
thread_count = 8

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

tag_columns = []
tag_list = [] 

## Set columns to use for tagging, if a @tag_column_file is provided
begin

CSV.foreach(@tag_column_file, :headers => true, :encoding => "UTF-8"){|row|

  tag_columns << Array[row[0],row[1]]

}

num_lines = CSV.read(@csv_file).length

log_output = File.open(output_filename,'a+')
log_output << "Processing CSV total lines #{num_lines}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
log_output.close

producer_thread = Thread.new do
  puts "starting producer loop" if @debug
  

  ## Iterate through CSV
  CSV.foreach(@csv_file, :headers => true, :encoding => "UTF-8"){|row|

    current_line = $.

    asset_identifier = nil
    asset_id = nil
    priority = nil

    log_output = File.open(output_filename,'a+')
    log_output << "Reading line #{$.}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
    log_output.close

    query_url = nil
    hostname_query = nil
    ip_address_query = nil
    if @host_search_field == "ip_address" || @host_search_field == "hostname" then
      if !row["#{@ip_address}"].nil? && is_ip?(row["#{@ip_address}"]) then
        ip_address_query = build_ip_url(row["#{@ip_address}"])
      end
      if !row["#{@hostname}"].nil? then
        hostname_query = build_hostname_url(row["#{@hostname}"])
      end
    end

    tag_list = [] 
    if tag_columns.count > 0 then
      tag_columns.each{|item|
        pull_column = []
        pull_string = ""
        pull_column = CSV.parse_line("#{item[0]}")
        pull_column.each{|col|
          pull_string << "#{row[col]} "
        } 
        pull_string = pull_string.strip
        pull_string = pull_string.gsub(/['<','>','\n','\t',':','(',')']/,'').chomp
        if !pull_string.nil? && !pull_string.empty? then
          if !item[1].nil? then
            tag_list << "#{item[1]}#{pull_string}"
          else
            tag_list << "#{pull_string}"
          end
        end
      }
    end

    if !@priority_column.nil? then 
      priority = row["#{@priority_column}"]
    end 

    tag_string = ""
    tag_list.each{|t| tag_string << "#{t},"}
    tag_string = tag_string[0...-1]
    #puts "tag string = #{tag_string}" if @debug


    work_queue << Array[hostname_query,ip_address_query,tag_string,priority]
    
    # Tell the consumer to check the thread array so it can attempt to schedule the
    # next job if a free spot exists.
    threads.synchronize do
      threads_available.signal
    end
  }
  # Tell the consumer that we are finished downloading currencies
  sysexit = true
end

consumer_thread = Thread.new do
  loop do
    @retries = 0
    puts "at start of consumer loop" if @debug

    # Stop looping when the producer is finished producing work
    work_to_do = []
    work_to_do = work_queue.pop
    break if sysexit & work_queue.nil?
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

      hostname_query = work_to_do[0]
      ip_address_query = work_to_do[1]
      tag_string = work_to_do[2]
      priority = work_to_do[3]

      tag_update_json = {
            'asset' => {
              'tags' => "#{tag_string}"
            }
          }## Push tags to assets
      #puts "tag json = #{tag_update_json}" if @debug
      if !priority.nil? then
        asset_update_json = {
            'asset' =>{
              'priority' => row["#{@priority_column}"]
            }
          }
      end

      async_query = false
      query_url = nil
      asset_found = false
      attempted = false
      pages = 0
      tot_assets = 0
      query_response_json = nil
      query_response = nil
      api_query = nil

      while asset_found == false

        if @host_search_field == "ip_address" && ip_address_query.nil? == false && attempted == false then
          api_query = ip_address_query
        elsif @host_search_field == "ip_address" && hostname_query.nil? == false && attempted == true then
          api_query = hostname_query
        elsif @host_search_field == "hostname" && hostname_query.nil? == false && attempted == false then
          api_query = hostname_query
        elsif @host_search_field == "hostname" && ip_address_query.nil? == false && attempted == true then
          api_query = ip_address_query
        else
          break
        end 

        

        if api_query.nil? == false then
          query_url = "#{@search_url}"
          query_url = "#{query_url}#{api_query}"
        else
          break
        end

        query_url = query_url.gsub(/\&$/, '')

        puts "query url = #{query_url}" if @debug

        begin
          query_response = RestClient::Request.execute(
            method: :get,
            url: query_url,
            headers: @headers
          ) 
          rescue RestClient::TooManyRequests =>e
              puts "need to retry" if @debug
              retry
          rescue RestClient::UnprocessableEntity => e
            log_output = File.open(output_filename,'a+')
            log_output << "Unable to get Asset - #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
            log_output.close
            puts "Unable to get Asset: #{e.message}"
            Thread.exit
          rescue URI::InvalidURIError => e
            log_output = File.open(output_filename,'a+')
            log_output << "Unable to get Assets - InvalidURI: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
            log_output.close
            puts "Unable to get assets: #{e.backtrace.inspect}"
            Thread.exit
          rescue RestClient::Exception => e
            @retries ||= 0
            if @retries < @max_retries
              @retries += 1
              sleep(15)
              retry
            else
              log_output = File.open(output_filename,'a+')
              log_output << "General RestClient error #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
              log_output.close
              puts "Unable to get assets: #{e.message}"
              Thread.exit
            end
            Thread.exit
          rescue Exception => e
            log_output = File.open(output_filename,'a+')
            log_output << "Unable to get Assets - general exception: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
            log_output.close
            puts "Unable to get assets: #{e.backtrace.inspect}"
            Thread.exit
        end

        query_meta_json = JSON.parse(query_response)["meta"]
        tot_assets = query_meta_json.fetch("total_count")
        pages = query_meta_json.fetch("pages")
        if tot_assets == 0 then
          puts "tot assets equal 0"
          if attempted == false then
            puts "changed attempted to true"
            attempted = true
          else
            break
          end
        else
          puts "tot assets greater than 0"
          asset_found = true
        end
      end

      # Put the row on the work queue
      if pages > 20 then
        async_query = true
      elsif pages == 0 then
        next
      end

      if async_query then
        query_url = "#{@async_api_url}?"
      else
        query_url = "#{@search_url}"
      end

      if !api_query.nil? then
        query_url = "#{query_url}#{api_query}"
      end

      query_url = query_url.gsub(/\&$/, '')

      if !async_query then 
        puts "starting regular query" if @debug
        begin
          query_response = RestClient::Request.execute(
            method: :get,
            url: query_url,
            headers: @headers
          )

        
          meta_response_json = JSON.parse(query_response.body)["meta"]
          tot_assets = meta_response_json.fetch("total_count")
          log_output = File.open(output_filename,'a+')
          log_output << "Processing = #{query_url}. Total assets = #{tot_assets}\n"
          log_output.close
          puts "Processing #{query_url} Total assets = #{tot_assets}" if @debug
          pages = meta_response_json.fetch("pages")

          endloop = pages + 1
          (1...endloop).step(1) do |i|
            puts "paging url = #{query_url}&page=#{i}" if @debug

            query_response = RestClient::Request.execute(
              method: :get,
              url: "#{query_url}&page=#{i}",
              headers: @headers
            )
            # Build URL to set the custom field value for each asset

            query_response_json = JSON.parse(query_response.body)["assets"]
            query_response_json.each do |item|
              asset_id = item["id"]
              post_url = "#{@asset_api_url}/#{asset_id}"
              tag_post_url = "#{@asset_api_url}/#{asset_id}/tags"
              puts "post_url = #{post_url}" if @debug
              begin
                query_post_return = RestClient::Request.execute(
                  method: :put,
                  url: tag_post_url,
                  payload: tag_update_json,
                  headers: @headers
                )
                if !priority.nil? then
                  query_post_return = RestClient::Request.execute(
                    method: :put,
                    url: post_url,
                    payload: asset_update_json,
                    headers: @headers
                  )
                end
                rescue RestClient::TooManyRequests =>e
                  retry
                rescue RestClient::UnprocessableEntity => e
                  #if we got here it worked
                rescue RestClient::BadRequest => e
                  log_output = File.open(output_filename,'a+')
                  log_output << "BadRequest: #{post_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
                  log_output.close
                  puts "BadRequest: #{e.message}"
                  Thread.exit
                rescue RestClient::Exception => e
                  @retries ||= 0
                  puts "one #{@retries}"
                  if @retries < @max_retries
                    @retries += 1
                    sleep(15)
                    retry
                  else
                    log_output = File.open(output_filename,'a+')
                    log_output << "General RestClient error #{post_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
                    log_output.close
                    puts "Unable to get asset: #{e.message}"
                    Thread.exit
                  end
              end
            end
          end
        rescue RestClient::TooManyRequests =>e
          retry
        rescue RestClient::UnprocessableEntity 
          log_output = File.open(output_filename,'a+')
          log_output << "UnprocessableEntity: #{query_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
          log_output.close
          puts "UnprocessableEntity: #{e.message}"
          Thread.exit
        rescue RestClient::BadRequest => e
          log_output = File.open(output_filename,'a+')
          log_output << "BadRequest: #{post_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
          log_output.close
          puts "BadRequest: #{e.message}"
          Thread.exit
        rescue RestClient::Exception => e
          @retries ||= 0
          if @retries < @max_retries
            @retries += 1
            sleep(15)
            retry
          else
            log_output = File.open(output_filename,'a+')
            log_output << "General RestClient error #{post_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
            log_output.close
            puts "Unable to get asset: #{e.message}"
            Thread.exit
          end
        end
        threads.synchronize do
          threads_available.signal
        end
      else
        puts "starting async query" if @debug
        begin
          query_response = RestClient::Request.execute(
            method: :post,
            url: query_url,
            headers: @headers
          ) 
          query_response_json = JSON.parse(query_response.body)
          searchID = query_response_json.fetch("search_id")
          output_results = "myoutputfile_#{searchID}.json"
          searchComplete = false

          while searchComplete == false
            File.open(output_results, 'w') {|f|
                block = proc { |response|
                  response.read_body do |chunk| 
                    f.write chunk
                  end
                }
                RestClient::Request.new(method: :get, url: "https://api.kennasecurity.com/assets/async_search?search_id=#{searchID}", headers: @headers, block_response: block).execute
            }

            results_json = JSON.parse(File.read(output_results))

            if find_json_status?(results_json) then 
              #results_json.fetch("status") == "incomplete" then
              puts "sleeping for async query" if @debug
              sleep(60)
              next
            #end
            else
              puts "ansyc query complete" if @debug
              searchComplete = true
              results_json = JSON.parse(File.read(output_results))["assets"]
              results_json.each do |item|
                asset_id = item["id"]
                post_url = "#{@asset_api_url}/#{asset_id}"
                tag_post_url = "#{@asset_api_url}/#{asset_id}/tags"
                puts "tag_post_url = #{tag_post_url}" if @debug
                begin
                query_post_return = RestClient::Request.execute(
                  method: :put,
                  url: tag_post_url,
                  payload: tag_update_json,
                  headers: @headers
                )
                if priority.nil? == false then
                  query_post_return = RestClient::Request.execute(
                    method: :put,
                    url: post_url,
                    payload: asset_update_json,
                    headers: @headers
                  )
                end
                rescue RestClient::TooManyRequests =>e
                  retry
                rescue RestClient::UnprocessableEntity => e

                rescue RestClient::BadRequest => e
                  log_output = File.open(output_filename,'a+')
                  log_output << "Async BadRequest: #{post_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
                  log_output.close
                  puts "Async BadRequest: #{e.message}"
                rescue RestClient::Exception => e
                  @retries ||= 0
                  if @retries < @max_retries
                    @retries += 1
                    sleep(15)
                    retry
                  else
                    log_output = File.open(output_filename,'a+')
                    log_output << "Async General RestClient error #{post_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
                    log_output.close
                    puts "Async Unable to get asset: #{e.message}"
                    next
                  end
                end
              end
              File.delete(output_results)
            end
          end
        rescue RestClient::TooManyRequests =>e
          retry
        rescue RestClient::UnprocessableEntity => e
          log_output = File.open(output_filename,'a+')
          log_output << "UnprocessableEntity: #{query_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
          log_output.close
          puts "UnprocessableEntity: #{e.message}"
          Thread.exit
        rescue RestClient::BadRequest => e
          log_output = File.open(output_filename,'a+')
          log_output << "BadRequest: #{query_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
          log_output.close
          puts "BadRequest: #{e.message}"
          Thread.exit
        rescue RestClient::Exception => e
          @retries ||= 0
          if @retries < @max_retries
            @retries += 1
            sleep(15)
            retry
          else
            log_output = File.open(output_filename,'a+')
            log_output << "General RestClient error #{query_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
            log_output.close
            puts "Unable to get asset: #{e.message}"
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
consumer_thread.join

# Join on the child processes to allow them to finish (if any are left)
threads.each do |thread|
    thread.join unless thread.nil?
end
puts "DONE!"

rescue Exception => e
  log_output = File.open(output_filename,'a+')
  log_output << "Unable to get Assets - general exception: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
  log_output.close
  puts "Unable to get assets: #{e.backtrace.inspect}"
end
