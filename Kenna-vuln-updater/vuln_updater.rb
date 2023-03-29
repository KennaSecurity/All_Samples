# vuln updater multi-threaded
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
ARGV.length == 15 ? @base_url = ARGV[14] : @base_url = "https://api.kennasecurity.com/"

@enc_dblquote = "%22"

@start_time = Time.now
@output_filename = Logger.new("kenna_vuln_updater_log-#{@start_time.strftime("%Y%m%dT%H%M")}.txt")

if @vuln_status.empty? then 
  @output_filename.error("Vuln Status Null - Setting Vuln Status to Open\n")
  @vuln_status = "open"
end

#Variables we'll need later
@vuln_api_url = "#{@base_url}vulnerabilities"
@vuln_api_bulk = 'bulk'
@search_url = "/search?status%5B%5D=#{@vuln_status}&" 
@urlquerybit = 'q='
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json'}
@custom_field_columns = [] 

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

def is_nil_and_empty(data)
     data.blank? || data.nil?
end  

def post_data(post_url,json_data)
  begin
    puts "posting url #{post_url}"
    puts "posting json #{json_data}"
      RestClient::Request.execute(
        :method => :put,
        :url => post_url,
        :payload => json_data,
        :headers => @headers
      )
  rescue RestClient::TooManyRequests =>e
    retry
  rescue RestClient::UnprocessableEntity => e
    puts "unprocessible entity: #{e.message}"
  rescue RestClient::BadRequest => e
    @output_filename.error("BadRequest: #{post_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
    puts "BadRequest: #{e.backtrace.inspect}"
    Thread.exit
  rescue RestClient::Exception => e
    @retries ||= 0
    if @retries < @max_retries
      @retries += 1
      sleep(15)
      retry
    else
      @output_filename.error("General RestClient error #{post_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
      puts "Unable to get vulns: #{e.backtrace.inspect}"
      Thread.exit
    end
  rescue Exception => e
    @output_filename.error("BadRequest: #{post_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
    puts "BadRequest: #{e.backtrace.inspect}"
    Thread.exit
  end
end

# Set a finite number of simultaneous worker threads that can run
thread_count = 1

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

if !@data_column_file.empty? then

  CSV.foreach(@data_column_file, :headers => true, :encoding => "UTF-8"){|row|

    @custom_field_columns << Array[row[0],row[1]]

  }
end

num_lines = CSV.read(@csv_file).length

@output_filename.error("reading CSV total lines #{num_lines}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")

producer_thread = Thread.new do
  puts "starting producer loop" if @debug
  
  ## Iterate through CSV
  CSV.foreach(@csv_file, :headers => true, :encoding => "UTF-8"){|row|

    @output_filename.error("Reading line #{$.}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")

    vuln_query = ""
    hostname_query = ""
    ip_address_query = ""
    if @host_search_field == "ip_address" || @host_search_field == "hostname" then
      if !row["#{@ip_address}"].nil? then
        ip_address_query = build_ip_url(row["#{@ip_address}"])
      end
      if !row["#{@hostname}"].nil? then
        hostname_query = build_hostname_url(row["#{@hostname}"])
      end
    end

    if !@vuln_type.empty? then
      if @vuln_type == "vuln_id" then
        vuln_query = "id%5B%5D=#{row[@vuln_column]}"
        #puts "here #{@vuln_column} = #{row[@vuln_column]}" if @debug
      else
        rowdata = row[@vuln_column]
        if @vuln_type == "cve" then
          if rowdata.start_with?("CVE-") then
            rowdata = rowdata[4..-1]
          end
        end
        vuln_query = "#{@vuln_type}:\"#{rowdata}\""
      end
    end

    custom_field_string = ""
    if !@custom_field_columns.empty? then
      @custom_field_columns.each{|item|
        row_value = row[item[0]] 
        if row_value.nil? then
          row_value = " "
        end
        custom_field_string << "\"#{item[1]}\":\"#{row_value}\","
      }
    end

    custom_field_string = custom_field_string[0...-1]
    
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
        new_date = Date.strptime(new_date, '%m/%d/%Y')
        new_date = new_date.strftime('%FT%TZ')
      end
      json_string = "#{json_string}\"due_date\": \"#{new_date}\", "
    end

    #puts "***** #{custom_field_string}"
    if !custom_field_string.empty? then
      json_string = "#{json_string}\"custom_fields\": {#{custom_field_string}}"
    end

    json_string = json_string[0..-3] if json_string.end_with?(', ')

    json_string = "#{json_string}}}"

    #puts json_string if @debug
    #puts "#{vuln_query} = vuln_query" if @debug

    # Put the row on the work queue
    work_queue << Array[hostname_query,ip_address_query,vuln_query,json_string]
    
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
      api_query = ""

      while asset_found == false

        if @host_search_field == "ip_address" && ip_address_query.empty? == false && attempted == false then
          api_query = ip_address_query
        elsif @host_search_field == "ip_address" && !ip_address_query.empty? && !hostname_query.empty? && attempted == true then
          api_query = hostname_query
        elsif @host_search_field == "ip_address" && attempted == true && hostname_query.empty? then
          break
        elsif @host_search_field == "hostname" && !hostname_query.empty? && attempted == false then
          api_query = hostname_query
        elsif @host_search_field == "hostname" && !hostname_query.empty? && !ip_address_query.empty? && attempted == true then
          api_query = ip_address_query
        elsif @host_search_field == "hostname" && attempted == true && ip_address_query.empty? then
          break
        elsif hostname_query.empty? && ip_address_query.empty? then
          attempted = true
          asset_found = true
        end 

        puts "api_query = #{api_query}" if @debug

        if !vuln_query.empty? then
          if @vuln_type == "vuln_id" then
            query_url = "#{@vuln_api_url}#{@search_url}#{query_url}#{vuln_query}"
          else
            query_url = "#{@vuln_api_url}#{@search_url}#{@urlquerybit}#{vuln_query}"
          end
        else
          query_url = "#{@vuln_api_url}#{@search_url}#{@urlquerybit}"
        end

        if !api_query.empty? then
          if !vuln_query.empty? then
            query_url = "#{query_url}+AND+#{api_query}"
          else
            query_url = "#{query_url}#{api_query}"
          end
        end

        query_url = query_url.gsub(/\&$/, '')

        #puts "query url = #{query_url}" if @debug
        #puts "json data = #{json_data}" if @debug


        begin
          query_response = RestClient::Request.execute(
            :method => :get,
            :url => query_url,
            :headers => @headers
          ) 
          
          query_meta_json = JSON.parse(query_response)["meta"]
          tot_vulns = query_meta_json.fetch("total_count")
          pages = query_meta_json.fetch("pages")
          puts "first query #{query_url} tot vulns = #{tot_vulns} and pages = #{pages}"
          if tot_vulns == 0 then
            break if @host_search_field.empty?
            if attempted == false then
              attempted = true
              next
            else
              break
            end
          else
            asset_found = true
          end
        rescue RestClient::TooManyRequests => e
          retry
        rescue RestClient::UnprocessableEntity => e
          @output_filename.error("UnprocessableEntity: #{query_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
          puts "UnprocessableEntity: #{e.message}"
          Thread.exit
        rescue RestClient::BadRequest => e
          @output_filename.error("BadRequest: #{query_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
          puts "BadRequest: #{e.message} for #{query_url}"
          Thread.exit
        rescue RestClient::Exception => e
          @retries ||= 0
          if @retries < @max_retries
            @retries += 1
            sleep(15)
            retry
          else
            @output_filename.error("General RestClient error #{query_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
            puts "Unable to get vulns: #{e.message}"
            Thread.exit
          end
        rescue Exception => e
          @output_filename.error("Unable to get vulns - general exception: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
          puts "Unable to get vulns: #{e.message} #{e.backtrace.inspect}"
          Thread.exit
        end

        # Determine if we're going to use "Search Vulnerabilities" API or
        # an async query via data export APIs.
        if pages > 20 then
          async_query = true
        end

        puts "async query needed: #{async_query}" if @debug

        begin

          query_url = "#{@vuln_api_url}#{@search_url}"

          if !vuln_query.empty? then
            if @vuln_type == "vuln_id" then
              query_url = "#{query_url}#{vuln_query}"
            else
              query_url = "#{query_url}#{@urlquerybit}#{vuln_query}"
            end
          else
            query_url = "#{query_url}#{@urlquerybit}"
          end

          if !api_query.empty? then
            if !vuln_query.empty? then
              query_url = "#{query_url}+AND+#{api_query}"
            else
              query_url = "#{query_url}#{api_query}"
            end
          end

          query_url = query_url.gsub(/\&$/, '')

          if !async_query then
            puts "starting regular query" if @debug
            puts "before submit #{query_url}" if @debug

            morepages = true
            i=1
            vuln_ids = []
            #endloop = pages + 1
            while morepages
              puts "paging url = #{query_url}&page=#{i}" if @debug

              query_response = RestClient::Request.execute(
                :method => :get,
                :url => "#{query_url}&page=#{i}",
                :headers => @headers
              )
              # Build URL to set the custom field value for each vulnerability
              query_response_json = JSON.parse(query_response.body)["vulnerabilities"]
              meta_response_json = JSON.parse(query_response.body)["meta"]
              pages = meta_response_json.fetch("pages")
              if pages == i then
                morepages = false
              else
                i+=1
              end

              query_response_json.each do |item|
                vuln_ids << item["id"]
              end
            end

            post_url = "#{@vuln_api_url}/#{@vuln_api_bulk}"
            puts vuln_ids.size

            vuln_ids.each_slice(5000) do |a|

              json_data = json_data.insert(json_data.index('vulnerability')-1, "\"vulnerability_ids\": #{a},")
            end
            puts "*************************"
            #puts "post_url for nonasync = #{post_url}" if @debug
            #puts "json for nonasync post = #{json_data}" if @debug

            post_data(post_url,json_data)

          else
            puts "starting async query using data exports" if @debug

            bulk_query_json_string = "{\"asset\": {\"status\": [\"active\"]}, \"status\": [\"#{@vuln_status}\"], "

            if !api_query.empty? then
              if !vuln_query.empty? then
                puts "here1"
                q = "\"#{vuln_query.gsub(/"/,'\"')}+AND+#{api_query}\""
              else
                puts "here2"
                q = "\"#{api_query}\""
              end
            elsif !vuln_query.empty?
              q = "\"#{vuln_query.gsub(/"/,'\"')}\""
            end

            #q = q.gsub(':', "\:")
            bulk_query_json_string = bulk_query_json_string + " \"q\": #{q}, \"export_settings\": { \"format\": \"json\", "
            bulk_query_json_string = bulk_query_json_string + "\"compression\": \"gzip\", \"model\": \"vulnerability\" }}"

            #bulk_query_json = JSON.parse(bulk_query_json_string)

            puts bulk_query_json_string
            # Request a data export.
            query_response = RestClient::Request.execute(
              :method => :post,
              :url => "#{@base_url}data_exports",
              :headers => @headers,
              :payload => bulk_query_json_string
            ) 
            query_response_json = JSON.parse(query_response.body)
            searchID = query_response_json.fetch("search_id")
            puts "searchID = #{searchID}" if @debug
            #searchID = "33444"
            output_results = "myoutputfile_#{searchID}.json"
            searchComplete = false

            # Wait for data export to be complete.
            while searchComplete == false
            
              status_code = RestClient.get("#{@base_url}data_exports/status?search_id=#{searchID}", @headers).code

              puts "status code =#{status_code}" if @debug
              if status_code != 200 then 
                puts "sleeping for async query" if @debug
                sleep(60)
                next
              else
                puts "async query (data export) complete" if @debug
                searchComplete = true
                File.open(output_results, 'w') {|f|
                  block = proc { |response|
                    response.read_body do |chunk| 
                      f.write chunk
                    end
                  }
                  # Retrieve data exports in a gzip file.
                  RestClient::Request.new(:method => :get, :url => "#{@base_url}data_exports?search_id=#{searchID}", :headers => @headers, :block_response => block).execute
                }

                # Open gzip file and process.
                gzfile = open(output_results)
                gz = Zlib::GzipReader.new(gzfile)
                vuln_ids = []
                results_json = JSON.parse(gz.read)["vulnerabilities"]
                results_json.each do |item|
                  vuln_ids << item["id"]
                end
              end 
            end

            post_url = "#{@vuln_api_url}/#{@vuln_api_bulk}"
            puts "post_url = #{post_url}" if @debug
            
            # Update vulnerabilities with "Bulk Vulnerabilities" API 5,000 vulnerabilities at a time.
            vuln_ids.each_slice(5000) do |a|

              json_data = json_data.insert(json_data.index('vulnerability')-1, "\"vulnerability_ids\": #{a},") 

              puts "*************************"    
              puts "async post_url = #{post_url}" if @debug
              puts "async json = #{json_data}" if @debug

              post_data(post_url,json_data)

            end

            # Delete gzip file.
            File.delete(output_results)
          end

        rescue RestClient::TooManyRequests => e
          retry
        rescue RestClient::UnprocessableEntity => e
          @output_filename.error("UnprocessableEntity: #{query_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
          puts "UnprocessableEntity: #{e.message}"
          Thread.exit
        rescue RestClient::BadRequest => e
          @output_filename.error("BadRequest: #{query_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
          puts "BadRequest: #{e.message} for #{query_url}"
          Thread.exit
        rescue RestClient::Exception => e
          @retries ||= 0
          if @retries < @max_retries
            @retries += 1
            sleep(15)
            retry
          else
            @output_filename.error("General RestClient error #{query_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
            puts "Unable to get vulns: #{e.message}"
            Thread.exit
          end
        rescue Exception => e
          @output_filename.error("Unable to get vulns - general exception: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{@start_time.to_s})\n")
          puts "Unable to get vulns: #{e.message} #{e.backtrace.inspect}"
          Thread.exit
        end
      end
      #Thread.current.exit
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

