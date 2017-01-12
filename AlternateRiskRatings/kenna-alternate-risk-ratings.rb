# alternate risk ratings
require 'rest-client'
require 'json'
require 'csv'
require 'thread'
require 'monitor'

@token = ARGV[0]
@file_name = ARGV[1]

@vuln_api_url = 'https://api.kennasecurity.com/vulnerabilities'
@search_url = @vuln_api_url + '/search?q='
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json'}
@max_retries = 5
@debug = true

# Encoding characters
enc_colon = "%3A"
enc_dblquote = "%22"
enc_space = "%20"

start_time = Time.now
output_filename = "kenna-archer-sync_log-#{start_time.strftime("%Y%m%dT%H%M")}.txt"

# Set a finite number of simultaneous worker threads that can run
thread_count = 3

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

producer_thread = Thread.new do
  puts "starting producer loop" if @debug

  ## Iterate through CSV
  CSV.foreach(@file_name, :headers => true) do |row|
    log_output = File.open(output_filename,'a+')
    log_output << "Reading line #{$.}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
    log_output.close
    ## Pull from CSV
    vuln_search = row['Vulnerability']
    vuln_type = row['Type']
    determination = row['Determination']
    work_queue << Array[vuln_search,vuln_type,determination]
    # Tell the consumer to check the thread array so it can attempt to schedule the
    # next job if a free spot exists.
    threads.synchronize do
      threads_available.signal
    end
  end
  # Tell the consumer that we are finished downloading currencies
  sysexit = true
end


consumer_thread = Thread.new do
  loop do
    @retries = 0
    puts "at start of consumer loop" if @debug

    # Stop looping when the producer is finished producing work
    break if sysexit & work_queue.nil?
    found_index = nil

    # The MonitorMixin requires us to obtain a lock on the threads array in case
    # a different thread may try to make changes to it.
    threads.synchronize do
      # First, wait on an available spot in the threads array.  This fires every
      # time a signal is sent to the "threads_available" variable
      threads_available.wait_while do
        sleep(2)
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
    work_to_do = []
    work_to_do = work_queue.pop


    threads[found_index] = Thread.new(work_to_do) do
      puts "starting the thread loop" if @debug

      ## Pull from CSV
      vuln_search = work_to_do[0]
      vuln_type = work_to_do[1]
      determination = work_to_do[2]



      query_url =  "#{@search_url}vulnerability_score:0+AND+vulnerability_definition.name:%22#{vuln_search.gsub(/ /,'+')}%22"

      puts "query url = #{query_url}" if @debug

      ## Query API with query_url
      vuln_id = nil
      begin
        query_response = RestClient::Request.execute(
          method: :get,
          url: query_url,
          headers: @headers
        )
 
        query_response_json = JSON.parse(query_response)["vulnerabilities"]

        query_response_json.each do |item|
          vuln_id = item["id"]
          if !vuln_id.nil? then
            puts "Found Kenna vuln_id: #{vuln_id}, updating..." if @debug
            log_output = File.open(output_filename,'a+')
            log_output << "Found Kenna vuln_id: #{vuln_id}, updating...\n"
            log_output.close
            vuln_url = "#{@vuln_api_url}/#{vuln_id}"

            ## update vuln ID with data
            vuln_update_json = {
              'vulnerability' => {
                'custom_fields' => {
                4170 => vuln_type,
                4171 => determination
                }
              }
            }
            begin
              update_response = RestClient::Request.execute(
                method: :put,
                url: vuln_url,
                headers: @headers,
                payload: vuln_update_json
              ) 
          
              rescue RestClient::TooManyRequests =>e
                retry

              rescue RestClient::UnprocessableEntity => e
                #this means it worked

              rescue RestClient::BadRequest => e
                log_output = File.open(output_filename,'a+')
                log_output << "BadRequest: #{e.message}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
                log_output.close
                puts "BadRequest: #{e.message}"
              rescue RestClient::Exception => e
                puts "i hit an exception #{e.message}"

                @retries ||= 0
                if @retries < @max_retries
                  @retries += 1
                  sleep(15)
                  retry
                else
                  log_output = File.open(output_filename,'a+')
                  log_output << "General RestClient error #{e.message}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
                  log_output.close
                  puts "Exception: #{e.code} #{e.message}"
                end
              rescue Exception => e
                puts "general exception #{e.code} #{e.message}"
            end
          end
        end
      end
      Thread.current["finished"] = true

      # Tell the consumer to check the thread array
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
