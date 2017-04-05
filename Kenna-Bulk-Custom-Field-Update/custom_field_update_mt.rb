# kenna-bulk-custom-field-update
require 'rest-client'
require 'json'
require 'csv'
require 'thread'
require 'monitor'
require 'ipaddr'

#These are the arguments we are expecting to get - header file can be send as third parameter if not included as row 1 in csv
@token = ARGV[0]
@csv_file = ARGV[1] #source data
@data_column_file = ARGV[2] #custom field id's and columns with data
@vuln_type = ARGV[3] # cve or cwe or wasc or scanner_id or empty string
@vuln_column = ARGV[4] # column that holds the vuln key or empty string
@host_search_field = ARGV[5] #field to use first for asset match ip_address or hostname or empty string
@ip_address = ARGV[6] #column name in source file which holds the search field data or empty string
@hostname = ARGV[7] #column name in source file which holds the hostname data or empty string


#Variables we'll need later
@vuln_api_url = 'https://api.kennasecurity.com/vulnerabilities'
@search_url = "/search?" 
@urlquerybit = 'q='
@async_api_url = 'https://api.kennasecurity.com/vulnerabilities/create_async_search'
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json'}
@custom_field_columns = [] 


# Encoding characters
@enc_colon = "%3A"
@enc_dblquote = "%22"
@enc_space = "%20"

start_time = Time.now

def build_ip_url(ipstring)
  url = ""
  if ipstring.index('/').nil? then
    subnet = IPAddr.new(ipstring)
    url = "ip:#{@enc_dblquote}#{subnet}#{@enc_dblquote}"
  else 
    subnet = IPAddr.new(ipstring)
    iprange = subnet.to_range()
    beginip = iprange.begin
    endip = iprange.end
    url = "ip:" + "%7B" + "#{beginip}" + "+TO+" + "#{endip}" + "%7D"
  end
  return url
end

def find_json_status?(json)
  begin
    json.fetch("status") == "incomplete"
    return true
  rescue Exception => e
    return false
  end
end

def build_hostname_url(hostname)
  return "hostname:#{@enc_dblquote}#{hostname}*#{@enc_dblquote}"
end

def Boolean(value)
  case value
  when true, 'true', 1, '1', 't' then true
  when false, 'false', nil, '', 0, '0', 'f' then false
  else
    raise ArgumentError, "invalid value for Boolean(): \"#{value.inspect}\""
  end
end

#Helper method for checking if we have an IP address from the csv files
def is_ip?(str)
  !!IPAddr.new(str) rescue false
end

output_filename = "kenna_bulk_status_update_log-#{start_time.strftime("%Y%m%dT%H%M")}.txt"

@max_retries = 5
@debug = true



# Set a finite number of simultaneous worker threads that can run
thread_count = 10

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

producer_thread = Thread.new do
  puts "starting producer loop" if @debug
  # For each item in the loop ...
  CSV.foreach(@csv_file, :headers => true) do |row|
    query_url = ""
    vuln_query = nil
    if @host_search_field == "ip_address" then
      if !row["#{@ip_address}"].nil? then
        api_query = build_ip_url(row["#{@ip_address}"])
      elsif !@hostname == '' && !row["#{@hostname}"].nil? then
          api_query = build_hostname_url(row["#{@hostname}"])
      else
        next
      end
    elsif @host_search_field == "hostname" then
      if !row["#{@hostname}"].nil? then 
        api_query = build_hostname_url(row["#{@hostname}"])
      elsif !row["#{@ip_address}"].nil? then
        api_query = build_ip_url(row["#{@ip_address}"])
      else
        next
      end
    end

    #if !@vuln_type.nil? && !@vuln_type=="" then
    if !@vuln_type.nil? then
      vuln_query = "#{@vuln_type}:#{row[@vuln_column]}&"
      puts "vuln query = #{vuln_query}" if @debug
    end

    query_url = "#{@vuln_api_url}#{@search_url}#{@urlquerybit}"

    if !vuln_query.nil? then
      query_url = "#{query_url}#{vuln_query}"
    end

    if !api_query.nil? then
      query_url = "#{query_url}#{api_query}"
    end

    query_url = query_url.gsub(/\&$/, '')

    puts "query url = #{query_url}" if @debug

    async_query = false
    begin
      query_response = RestClient::Request.execute(
        method: :get,
        url: query_url,
        headers: @headers
      )
      rescue RestClient::TooManyRequests =>e
                retry
      rescue RestClient::UnprocessableEntity 
        log_output = File.open(output_filename,'a+')
        log_output << "UnprocessableEntity: #{query_url}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
        log_output.close
        puts "BadRequest: #{query_url}"
      rescue RestClient::BadRequest
        log_output = File.open(output_filename,'a+')
        log_output << "BadRequest: #{query_url}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
        log_output.close
        puts "BadRequest: #{query_url}"
      rescue RestClient::Exception
        @retries ||= 0
        if @retries < @max_retries
          @retries += 1
          sleep(15)
          retry
        else
          log_output = File.open(output_filename,'a+')
          log_output << "General RestClient error #{query_url}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
          log_output.close
          puts "Unable to get vulns: #{query_url}"
          next
        end
    end
    meta_response_json = JSON.parse(query_response.body)["meta"]
    tot_vulns = meta_response_json.fetch("total_count")
    next if tot_vulns == 0
    pages = meta_response_json.fetch("pages")
    log_output = File.open(output_filename,'a+')
    log_output << "Checking #{query_url}. Total vulnerabilities = #{tot_vulns}\n"
    log_output.close
    # Put the row on the work queue
    if pages > 20 then
      async_query = true
    end
    puts "#{tot_vulns} #{pages}"
    log_output = File.open(output_filename,'a+')
    log_output << "Starting Thread for #{query_url} Total vulnerabilities = #{tot_vulns}\n"
    log_output.close

    if async_query then
      query_url = "#{@async_api_url}?"
    else
      query_url = "#{@vuln_api_url}#{@search_url}"
    end

    if vuln_query.nil? then
      query_url = "#{query_url}#{@urlquerybit}#{api_query}"
    else
      query_url = "#{query_url}#{@urlquerybit}#{vuln_query}#{api_query}"
    end

    query_url = query_url.gsub(/\&$/, '')

    #puts "query url = #{query_url}" if @debug
    custom_field_string = ""
    @custom_field_columns.each{|item| 
      row_value = row[item[0]]
      if !row_value.nil? then
        custom_field_string << "\"#{item[1]}\":\"#{row[item[0]]}\","
      end
    }

    custom_field_string = custom_field_string[0...-1]

    work_queue << Array["#{async_query}","#{query_url}","#{custom_field_string}"]
    
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
                                  thread["finished"].nil? == false}.length == 0
        if @debug then puts "in threads_available loop" end
      end
      # Once an available spot is found, get the index of that spot so we may
      # use it for the new thread
      found_index = threads.rindex { |thread| thread.nil? || thread.status == false ||
                                              thread["finished"].nil? == false }

      if @debug then puts "i just found index = #{found_index}" end
    end

    

    threads[found_index] = Thread.new(work_to_do) do
      async_query = Boolean(work_to_do[0])
      query_url = work_to_do[1]
      custom_field_string = work_to_do[2]
      custom_field_string = "{\"vulnerability\": {\"custom_fields\": {#{custom_field_string}}}}"
      json_data = JSON.parse(custom_field_string)
      puts "in thread #{async_query} #{query_url} #{custom_field_string}"
      if !async_query then 
        puts "starting regular query" if @debug
        begin
          query_response = RestClient::Request.execute(
            method: :get,
            url: query_url,
            headers: @headers
          )
        rescue RestClient::TooManyRequests =>e
          retry
        rescue RestClient::UnprocessableEntity => e
          log_output = File.open(output_filename,'a+')
          log_output << "UnprocessableEntity: #{query_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
          log_output.close
          puts "BadRequest: #{e.message}"
        rescue RestClient::BadRequest => e
          log_output = File.open(output_filename,'a+')
          log_output << "BadRequest: #{query_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
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
            log_output = File.open(output_filename,'a+')
            log_output << "General RestClient error #{query_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
            log_output.close
            puts "Unable to get vulns: #{e.message}"
            next
          end
        end
        
        meta_response_json = JSON.parse(query_response.body)["meta"]
        tot_vulns = meta_response_json.fetch("total_count")
        log_output = File.open(output_filename,'a+')
        log_output << "Processing = #{query_url}. Total vulnerabilities = #{tot_vulns}\n"
        log_output.close
        if @debug then puts "Processing #{query_url} Total vulnerabilities = #{tot_vulns}" end
        pages = meta_response_json.fetch("pages")

        endloop = pages + 1
        (1...endloop).step(1) do |i|
          puts "Currently processing page #{i} of #{pages}"
          #query_url = "#{query_url}&page=#{i}"
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
            begin
              query_post_return = RestClient::Request.execute(
                method: :put,
                url: post_url,
                payload: json_data,
                headers: @headers
              )
              rescue RestClient::TooManyRequests =>e
                retry
              rescue RestClient::UnprocessableEntity 
                #if we got here it worked

              rescue RestClient::BadRequest => e
                log_output = File.open(output_filename,'a+')
                log_output << "BadRequest: #{post_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
                log_output.close
                puts "BadRequest: #{e.message}"
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
                  next
                end
            end
          end
          Thread.current["finished"] = true
          threads.synchronize do
            threads_available.signal
          end
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
            puts "building the search"
            File.open(output_results, 'w') {|f|
              puts "file opened"
                block = proc { |response|
                  puts "in the block"
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
                end
              end
              Thread.current["finished"] = true
              threads.synchronize do
                threads_available.signal
              end
            end
          end
        rescue RestClient::TooManyRequests =>e
          retry
        rescue RestClient::UnprocessableEntity => e
          log_output = File.open(output_filename,'a+')
          log_output << "UnprocessableEntity: #{query_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
          log_output.close
          puts "BadRequest: #{e.message}"
        rescue RestClient::BadRequest => e
          log_output = File.open(output_filename,'a+')
          log_output << "BadRequest: #{query_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
          log_output.close
          puts "BadRequest: #{e.message}"
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
            next
          end
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
consumer_thread.join

# Join on the child processes to allow them to finish (if any are left)
threads.each do |thread|
    thread.join unless thread.nil?
end
puts "DONE!"



