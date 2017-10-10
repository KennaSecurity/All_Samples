# custom field update multi-threaded
require 'rest-client'
require 'json'
require 'csv'
require 'ipaddr'
require 'thread'
require 'monitor'

#These are the arguments we are expecting to get - header file can be send as third parameter if not included as row 1 in csv
@token = ARGV[0]
@csv_file = ARGV[1] #source data
@data_column_file = ARGV[2] #custom field id's and columns with data
@vuln_type = ARGV[3] # cve or cwe or wasc or scanner_id or vuln_id or empty string
@vuln_column = ARGV[4] # column that holds the vuln key or empty string
@host_search_field = ARGV[5] #field to use first for asset match ip_address or hostname or empty string
@ip_address = ARGV[6] #column name in source file which holds the search field data or empty string
@hostname = ARGV[7] #column name in source file which holds the hostname data or empty string
@notes_type = ARGV[8] #where notes value will come from - static, column or empty string
@notes_value = ARGV[9] #set notes based on previous param - value, column name or empty string 
@due_date = ARGV[10] #column with due date or empty string
@status_type = ARGV[11] #where status value will come from - static, column or empty string for setting new data
@status_value = ARGV[12] #set status based on previous param - value, column name or empty string for setting new data
@vuln_status = ARGV[13] #vuln status all, open or other for retrieval 

@enc_colon = "%3A"
@enc_dblquote = "%22"
@enc_space = "%20"

#Variables we'll need later
@vuln_api_url = 'https://api.kennasecurity.com/vulnerabilities'
@search_url = "/search?status%5B%5D=#{@vuln_status}&" 
@urlquerybit = 'q='
@async_api_url = 'https://api.kennasecurity.com/vulnerabilities/create_async_search'
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json'}
@custom_field_columns = [] 

start_time = Time.now
output_filename = "kenna_bulk_status_update_log-#{start_time.strftime("%Y%m%dT%H%M")}.txt"

@max_retries = 5
@debug = false

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

## Set columns to use for tagging, if a @tag_column_file is provided

CSV.foreach(@data_column_file, :headers => true, :encoding => "UTF-8"){|row|

  @custom_field_columns << Array[row[0],row[1]]

}

num_lines = CSV.read(@csv_file).length

log_output = File.open(output_filename,'a+')
log_output << "Processing CSV total lines #{num_lines}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
log_output.close

if @vuln_status.empty? then 
  log_output = File.open(output_filename,'a+')
  log_output << "Vuln Status Null - Setting Vuln Status to Open\n"
  log_output.close
  @vuln_status = "open"
end if

producer_thread = Thread.new do
  puts "starting producer loop" if @debug
  
  ## Iterate through CSV
  CSV.foreach(@csv_file, :headers => true, :encoding => "UTF-8"){|row|

    current_line = $.

    asset_identifier = nil
    asset_id = nil

    log_output = File.open(output_filename,'a+')
    log_output << "Reading line #{$.}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
    log_output.close

    query_url = nil
    vuln_query = nil
    hostname_query = nil
    ip_address_query = nil
    if @host_search_field == "ip_address" || @host_search_field == "hostname" then
      if !row["#{@ip_address}"].nil? then
        ip_address_query = build_ip_url(row["#{@ip_address}"])
      end
      if !row["#{@hostname}"].nil? then
        hostname_query = build_hostname_url(row["#{@hostname}"])
      end
    end

    if !@vuln_type.nil? then
      if @vuln_type == "vuln_id" then
        vuln_query = "id%5B%5D=#{row[@vuln_column]}"
      else
        rowdata = row[@vuln_column]
        if @vuln_type == "cve" then
          if rowdata.start_with?("CVE-") then
            rowdata = rowdata[4..-1]
          end
        end
        vuln_query = "#{@vuln_type}:#{rowdata}"
      end
    end

    custom_field_string = ""
    @custom_field_columns.each{|item| 
      row_value = CGI.escape(row[item[0]])
      if !row_value.empty? then 
          custom_field_string << "\"#{item[1]}\":\"#{row[item[0]]}\","
      end
    }

    custom_field_string = custom_field_string[0...-1]
    
    json_string = nil

    json_string = "{\"vulnerability\": {"
    if !@notes_type.empty? then
      if @notes_type == "static" then
        json_string = "#{json_string}\"notes\": \"#{@notes_value}\", "
      else
        json_string = "#{json_string}\"notes\": \"#{row[@notes_value]}\", "
      end
    end
    if !@status_type.empty? then
      if @status_type == "static" then
        json_string = "#{json_string}\"status\": \"#{@status_value}\", "
      else
        json_string = "#{json_string}\"status\": \"#{row[@status_value]}\", "
      end
    end
    if !@due_date.empty? then
      new_date = row[@due_date]
      if new_date.nil? then
        new_date = " "
      else
        new_date = DateTime.parse(new_date)
        new_date = new_date.strftime('%FT%TZ')
      end
      json_string = "#{json_string}\"due_date\": \"#{new_date}\", "
    end

    json_string = "#{json_string}\"custom_fields\": {#{custom_field_string}}}}"

    puts json_string if @debug


    work_queue << Array[hostname_query,ip_address_query,vuln_query,JSON.parse(json_string)]
    
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
        sleep(1.0/2.0)
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
      vuln_query = work_to_do[2]
      json_data = work_to_do[3]

      async_query = false
      query_url = nil
      asset_found = false
      attempted = false
      pages = 0
      tot_vulns = 0
      query_response_json = nil
      query_response = nil
      api_query = nil

      while asset_found == false

        if @host_search_field == "ip_address" && ip_address_query.nil? == false && attempted == false then
          api_query = ip_address_query
        elsif @host_search_field == "ip_address" && !ip_address_query.nil? && !hostname_query.nil? && attempted == true then
          api_query = hostname_query
        elsif @host_search_field == "hostname" && !hostname_query.nil? && attempted == false then
          api_query = hostname_query
        elsif @host_search_field == "hostname" && !hostname_query.nil? && !ip_address_query.nil? && attempted == true then
          api_query = ip_address_query
        elsif hostname_query.nil? && ip_address_query.nil? then
          attempted = true
          asset_found = true
        end 

        #query_url = "#{@vuln_api_url}#{@search_url}#{@urlquerybit}"

        if !vuln_query.nil? then
          if @vuln_type == "vuln_id" then
            query_url = "#{@vuln_api_url}#{@search_url}#{query_url}#{vuln_query}"
          else
            query_url = "#{@vuln_api_url}#{@search_url}#{@urlquerybit}#{vuln_query}"
          end
        else
          query_url = "#{@vuln_api_url}#{@search_url}#{@urlquerybit}"
        end

        if !api_query.nil? then
          if !vuln_query.nil? then
            query_url = "#{query_url}+AND+#{api_query}"
          else
            query_url = "#{query_url}#{api_query}"
          end
        end

        query_url = query_url.gsub(/\&$/, '')

        puts "query url = #{query_url}" if @debug
        puts "json data = #{json_data}" if @debug


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
            log_output << "Unable to get vulns - #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
            log_output.close
            puts "Unable to get vulns: #{e.message}"
            Thread.exit
          rescue URI::InvalidURIError => e
            log_output = File.open(output_filename,'a+')
            log_output << "Unable to get vulns - InvalidURI: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
            log_output.close
            puts "Unable to get vulns: #{e.backtrace.inspect}"
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
              puts "Unable to get vulns: #{e.message}"
              Thread.exit
            end
            Thread.exit
          rescue Exception => e
            log_output = File.open(output_filename,'a+')
            log_output << "Unable to get vulns - general exception: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
            log_output.close
            puts "Unable to get vulns: #{e.backtrace.inspect}"
            Thread.exit
        end

        query_meta_json = JSON.parse(query_response)["meta"]
        tot_vulns = query_meta_json.fetch("total_count")
        pages = query_meta_json.fetch("pages")
        puts "tot vulns = #{tot_vulns}   and  pages = #{pages}"
        if tot_vulns == 0 then
          if attempted == false then
            attempted = true
          else
            break
          end
        else
          asset_found = true
        end
      end

      # Put the row on the work queue
      if pages > 20 then
        async_query = true
      end

      puts "async query #{async_query}"

      if async_query then
        query_url = "#{@async_api_url}?"
      else
        query_url = "#{@vuln_api_url}#{@search_url}"
      end

        if !vuln_query.nil? then
          if @vuln_type == "vuln_id" then
            query_url = "#{query_url}#{vuln_query}"
          else
            query_url = "#{query_url}#{@urlquerybit}#{vuln_query}"
          end
        else
          query_url = "#{query_url}#{@urlquerybit}"
        end

        if !api_query.nil? then
          if !vuln_query.nil? then
            query_url = "#{query_url}+AND+#{api_query}"
          else
            query_url = "#{query_url}#{api_query}"
          end
        end

      
      query_url = query_url.gsub(/\&$/, '')

      puts "before submit #{query_url}" if @debug

      if !async_query then 
        puts "starting regular query" if @debug

        begin
          query_response = RestClient::Request.execute(
            method: :get,
            url: query_url,
            headers: @headers
          )

          #puts query_response
          meta_response_json = JSON.parse(query_response.body)["meta"]
          tot_vulns = meta_response_json.fetch("total_count")
          log_output = File.open(output_filename,'a+')
          log_output << "Processing = #{query_url}. Total vulnerabilities = #{tot_vulns}\n"
          log_output.close
          puts "Processing #{query_url} Total vulnerabilities = #{tot_vulns}" if @debug
          pages = meta_response_json.fetch("pages")

          endloop = pages + 1
          (1...endloop).step(1) do |i|
            puts "paging url = #{query_url}&page=#{i}" if @debug

            query_response = RestClient::Request.execute(
              method: :get,
              url: "#{query_url}&page=#{i}",
              headers: @headers
            )
            # Build URL to set the custom field value for each vulnerability
            #counter = 0
            query_response_json = JSON.parse(query_response.body)["vulnerabilities"]
            query_response_json.each do |item|
              vuln_id = item["id"]
              post_url = "#{@vuln_api_url}/#{vuln_id}"
              puts "post_url = #{post_url}" if @debug
              puts "json = #{json_data}" if @debug
              begin
                query_post_return = RestClient::Request.execute(
                  method: :put,
                  url: post_url,
                  payload: json_data,
                  headers: @headers
                )
                rescue RestClient::TooManyRequests =>e
                  retry
                rescue RestClient::UnprocessableEntity => e
                  #it worked
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
                    puts "Unable to get vulns: #{e.message}"
                    Thread.exit
                  end
                rescue Exception => e
                  log_output = File.open(output_filename,'a+')
                  log_output << "BadRequest: #{post_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
                  log_output.close
                  puts "BadRequest: #{e.message}"
                  Thread.exit
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
            puts "Unable to get vulns: #{e.message}"
            Thread.exit
          end
        rescue Exception => e
            log_output = File.open(output_filename,'a+')
            log_output << "Unable to get vulns - general exception: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
            log_output.close
            puts "Unable to get vulns: #{e.backtrace.inspect}"
            Thread.exit
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
                RestClient::Request.new(method: :get, url: "https://api.kennasecurity.com/vulnerabilities/async_search?search_id=#{searchID}", headers: @headers, block_response: block).execute
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
              results_json = JSON.parse(File.read(output_results))["vulnerabilities"]
              results_json.each do |item|
                vuln_id = item["id"]
                post_url = "#{@vuln_api_url}/#{vuln_id}"
                puts "post_url = #{post_url}" if @debug
                begin
                query_post_return = RestClient::Request.execute(
                  method: :put,
                  url: post_url,
                  payload: json_data,
                  headers: @headers
                )
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
                    puts "Async Unable to get vulns: #{e.message}"
                    next
                  end
                rescue Exception => e
                  log_output = File.open(output_filename,'a+')
                  log_output << "Unable to get vulns - general exception: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
                  log_output.close
                  puts "Unable to get vulns: #{e.backtrace.inspect}"
                  Thread.exit
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
            puts "Unable to get vulns: #{e.message}"
            Thread.exit
          end
        rescue Exception => e
          log_output = File.open(output_filename,'a+')
          log_output << "Unable to get vulns - general exception: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
          log_output.close
          puts "Unable to get vulns: #{e.backtrace.inspect}"
          Thread.exit
        end
      end
      #Thread.current.exit
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

