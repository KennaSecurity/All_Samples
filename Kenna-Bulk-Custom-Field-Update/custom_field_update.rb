# kenna-bulk-custom-field-update
require 'rest-client'
require 'json'
require 'csv'
require 'thread'
require 'monitor'
require 'ipaddr'

#These are the arguments we are expecting to get - header file can be send as third parameter if not included as row 1 in csv
@token = ARGV[0]
@csv_file = ARGV[1]
ARGV.length == 3 ? @tag_column_file = ARGV[2] : @tag_column_file = nil
@max_retries = 5

#Variables we'll need later
@vuln_api_url = 'https://api.kennasecurity.com/vulnerabilities'
@search_url = "/search?" 
@urlquerybit = 'q='
@async_api_url = 'https://api.kennasecurity.com/vulnerabilities/create_async_search'
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json'}
# Encoding characters
enc_colon = "%3A"
enc_dblquote = "%22"
enc_space = "%20"

#Helper method for checking if we have an IP address from the csv files
def is_ip?(str)
  !!IPAddr.new(str) rescue false
end

tag_columns = []
tag_columns = File.readlines(@tag_column_file).map{|line| line.strip}.uniq.reject(&:empty?) if !@tag_column_file.nil?
start_time = Time.now
output_filename = "kenna_bulk_status_update_log-#{start_time.strftime("%Y%m%dT%H%M")}.txt"


@debug = true



# Set a finite number of simultaneous worker threads that can run
thread_count = 100

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


num_lines = CSV.read(@csv_file).length
start_time = Time.now
if @debug then puts "Found #{num_lines} lines." end


producer_thread = Thread.new do
  if @debug then "starting producer loop" end
  # For each item in the loop ...
  CSV.foreach(@csv_file, :headers => true) do |row|
    subnet = IPAddr.new(row['Subnet'].downcase)
    iprange = subnet.to_range()
    beginip = iprange.begin
    endip = iprange.end
    api_query = "ip#{enc_colon}" + "[" + "#{beginip}" + " TO " + "#{endip}" + "]"
    api_query = api_query.gsub(' ',enc_space)

    # Build URL to find the vulnerabilities associated with each IP address
    query_url = "#{@vuln_api_url}#{@search_url}#{@urlquerybit}#{api_query}"
    async_query = false
    begin
      query_response = RestClient::Request.execute(
        method: :get,
        url: query_url,
        headers: @headers
      )
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

        end
    end
      meta_response_json = JSON.parse(query_response.body)["meta"]
      tot_vulns = meta_response_json.fetch("total_count")
      pages = meta_response_json.fetch("pages")
      log_output = File.open(output_filename,'a+')
      log_output << "Checking iprange = #{beginip} to #{endip}. Total vulnerabilities = #{tot_vulns}\n"
      log_output.close
    # Put the row on the work queue
    if tot_vulns > 0 then 
        inncode = row['InnCode']
        rdit = row['ITFS RDIT / HGV Lead']
        itm = row['Local ITM']
        region = row['Region']
      if pages > 20 then
        str_subnet = row['Subnet'].downcase
        cidr_str = str_subnet[-2,2]
        diff = 28 - cidr_str.to_i
        str_subnet = str_subnet.chop.chop.chop
        1.upto(2 ** diff) { |k|
          str_subnet = "#{str_subnet}/28"
          subnet = IPAddr.new(str_subnet)
          iprange = subnet.to_range()
          work_queue << Array[inncode,rdit,itm,region,iprange.begin,iprange.end]
          puts "loop #{k} = #{iprange.begin} to #{iprange.end}"
          str_subnet = IPAddr.new(iprange.end.to_s).succ.to_s

        }
      else
        subnet = IPAddr.new(row['Subnet'].downcase)
        iprange = subnet.to_range()
        work_queue << Array[inncode,rdit,itm,region,iprange.begin,iprange.end]
      end

      log_output = File.open(output_filename,'a+')
      log_output << "Starting Thread for iprange = #{beginip} to #{endip}. Total vulnerabilities = #{tot_vulns}\n"
      log_output.close
    else
      log_output = File.open(output_filename,'a+')
      log_output << "No Thread Started for iprange = #{beginip} to #{endip}. Total vulnerabilities = #{tot_vulns}\n"
      log_output.close
    end
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

    break if sysexit & work_queue.nil?
    found_index = nil

    # The MonitorMixin requires us to obtain a lock on the threads array in case
    # a different thread may try to make changes to it.
    threads.synchronize do
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
    work_to_do = []
    # Get a new unit of work from the work queue
    work_to_do = work_queue.pop


    threads[found_index] = Thread.new(work_to_do) do

    inncode = work_to_do[0]
    rdit = work_to_do[1]
    itm = work_to_do[2]
    region = work_to_do[3]
    beginip = work_to_do[4]
    endip = work_to_do[5]


    api_query = "ip#{enc_colon}" + "[" + "#{beginip}" + " TO " + "#{endip}" + "]"
    api_query = api_query.gsub(' ',enc_space)

    # Build URL to find the vulnerabilities associated with each IP address
    query_url = "#{@vuln_api_url}#{@search_url}#{@urlquerybit}#{api_query}"

    begin
      query_response = RestClient::Request.execute(
        method: :get,
        url: query_url,
        headers: @headers
      )
      meta_response_json = JSON.parse(query_response.body)["meta"]
      tot_vulns = meta_response_json.fetch("total_count")
      log_output = File.open(output_filename,'a+')
      log_output << "Processing for iprange = #{beginip} to #{endip}. Total vulnerabilities = #{tot_vulns}\n"
      log_output.close
      if @debug then puts "Processing for iprange = #{beginip} to #{endip}. Total vulnerabilities = #{tot_vulns}" end
      pages = meta_response_json.fetch("pages")

      endloop = pages + 1
      (1...endloop).step(1) do |i|
        puts "Currently processing page #{i} of #{pages}"
        query_url = "#{@vuln_api_url}#{@search_url}page=#{i}&#{@urlquerybit}#{api_query}"
        #puts query_url
        query_response = RestClient::Request.execute(
          method: :get,
          url: query_url,
          headers: @headers
        )
        # Build URL to set the custom field value for each vulnerability
        counter = 0
        query_response_json = JSON.parse(query_response.body)["vulnerabilities"]
        query_response_json.each do |item|
          vuln_id = item["id"]
          post_url = "#{@vuln_api_url }/#{vuln_id}"
          json_data = {
            'vulnerability' => {
              'custom_fields' => {
                4061 => inncode,
                4062 => rdit, 
                4108 => itm,
                4109 => region
              }
            }
          }

          begin
            query_post_return = RestClient::Request.execute(
              method: :put,
              url: post_url,
              payload: json_data,
              headers: @headers
            )
            rescue RestClient::UnprocessableEntity 
              #if we got here it worked

            rescue RestClient::BadRequest
              log_output = File.open(output_filename,'a+')
              log_output << "BadRequest: #{post_url}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
              log_output.close
              puts "BadRequest: #{post_url}"
            rescue RestClient::Exception
              @retries ||= 0
              if @retries < @max_retries
                @retries += 1
                sleep(15)
                retry
              else
                log_output = File.open(output_filename,'a+')
                log_output << "General RestClient error #{post_url}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
                log_output.close
                puts "Unable to get vulns: #{post_url}"

              end
          end
        end
      end
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
      puts "one #{@retries}"
      if @retries < @max_retries
        @retries += 1
        sleep(15)
        retry
      else
        log_output = File.open(output_filename,'a+')
        log_output << "General RestClient error #{query_url}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
        log_output.close
        puts "Unable to get vulns: #{query_url}"

      end
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



