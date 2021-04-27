# frozen_string_literal: true

# kenna-asset-tagger
require 'rest-client'
require 'json'
require 'csv'
require 'ipaddr'
require 'monitor'

@token = ARGV[0]
@csv_file = ARGV[1] # source data
@tag_column_file = ARGV[2] # tag meta data - column from source file and tag prefix
@search_field = ARGV[3] # field to use first for asset match ip_address or hostname or application or netbios or url
@ip_address = ARGV[4] # column name in source file which holds the search field data or empty string
@hostname = ARGV[5] # column name in source file which holds the hostname data or empty string
@notes_type = ARGV[6] # where notes value will come from - static, column or empty string
@notes_value = ARGV[7] # set notes based on previous param - value, column name or empty string
@owner_type = ARGV[8] # where owner value will come from - static, column or empty string for setting new data
@owner_value = ARGV[9] # set owner based on previous param - value, column name or empty string for setting new data
@alt_locator = ARGV[10] # column that holds data for either application or netbios or url
@priority_column = ARGV.length == 12 ? ARGV[11] : '' # column that holds priority setting
@proxy_string = ARGV.length == 13 ? ARVG[12] : '' # proxy string for REST connection if needed

@asset_api_url = 'https://api.kennasecurity.com/assets'
@search_url = "#{@asset_api_url}/search?q="
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json' }
@debug = false
@max_retries = 5

# Encoding characters
@enc_colon = '%3A'
@enc_dblquote = '%22'
@enc_space = '%20'

def build_ip_url(ipstring)
  puts 'building ip url' if @debug
  url = ''
  if ipstring.index('/').nil?
    subnet = IPAddr.new(ipstring)
    url = "ip:#{@enc_dblquote}#{subnet}#{@enc_dblquote}"
  else
    subnet = IPAddr.new(ipstring)
    iprange = subnet.to_range
    beginip = iprange.begin
    endip = iprange.end
    url = "ip#{@enc_colon}" + '[' + beginip.to_s + ' TO ' + endip.to_s + ']'
  end
  url
end

def build_hostname_url(hostname)
  puts 'building hostname url' if @debug
  "hostname#{@enc_colon}#{@enc_dblquote}#{hostname}*#{@enc_dblquote}"
end

def is_ip?(str)
  !IPAddr.new(str).nil?
rescue StandardError
  false
end

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

tag_columns = []
tag_list = []

## Set columns to use for tagging, if a @tag_column_file is provided

unless @tag_column_file.empty?

  CSV.foreach(@tag_column_file, headers: true, encoding: 'UTF-8') do |row|
    tag_columns << Array[row[0], row[1]]
  end

  puts "tag_columns = #{tag_columns}" if @debug
end

start_time = Time.now
output_filename = "kenna-asset-tagger_log-#{start_time.strftime('%Y%m%dT%H%M')}.txt"

num_lines = CSV.read(@csv_file).length

log_output = File.open(output_filename, 'a+')
log_output << "Processing CSV total lines #{num_lines}... (time: #{Time.now}, start time: #{start_time})\n"
log_output.close

producer_thread = Thread.new do
  puts 'starting producer loop' if @debug

  ## Iterate through CSV
  CSV.foreach(@csv_file, headers: true, encoding: 'UTF-8') do |row|
    current_line = $INPUT_LINE_NUMBER

    asset_identifier = nil
    asset_id = nil

    log_output = File.open(output_filename, 'a+')
    log_output << "Reading line #{$INPUT_LINE_NUMBER}... (time: #{Time.now}, start time: #{start_time})\n"
    log_output.close

    # Get 'asset' identifier and figure out if ip/hostname
    # locator = row["#{@search_field}"]
    case @search_field
    when 'ip_address'
      if !row[@ip_address.to_s].nil? && is_ip?(row[@ip_address.to_s])
        api_query = build_ip_url(row[@ip_address.to_s])
      elsif !@hostname == '' && !row[@hostname.to_s].nil?
        api_query = build_hostname_url(row[@hostname.to_s])
      else
        next
      end
    when 'hostname'
      if !row[@hostname.to_s].nil? && !row[@hostname.to_s].empty?
        api_query = build_hostname_url(row[@hostname.to_s])
      elsif !row[@ip_address.to_s].nil? && is_ip?(row[@ip_address.to_s])
        api_query = build_ip_url(row[@ip_address.to_s])
      else
        next
      end
    when 'application'
      unless row[@alt_locator.to_s].nil?
        api_query = "application#{@enc_colon}#{@enc_dblquote}#{row[@alt_locator.to_s]}*#{@enc_dblquote}"
      end
    when 'netbios'
      api_query = "netbios#{@enc_colon}#{row[@alt_locator.to_s]}" unless row[@alt_locator.to_s].nil?
    when 'url'
      unless row[@alt_locator.to_s].nil?
        api_query = "url#{@enc_colon}#{@enc_dblquote}#{row[@alt_locator.to_s]}#{@enc_dblquote}"
      end
    end
    api_query = api_query.gsub(' ', @enc_space)

    query_url = "#{@search_url}#{api_query}"

    log_output = File.open(output_filename, 'a+')
    log_output << "Query URL...#{query_url}\n"
    log_output.close

    tag_list = []
    if tag_columns.count.positive?
      tag_columns.each do |item|
        pull_column = []
        pull_string = ''
        pull_column = CSV.parse_line((item[0]).to_s)
        pull_column.each do |col|
          pull_string << "#{row[col]} "
        end
        pull_string = pull_string.strip
        next unless !pull_string.nil? && !pull_string.empty?

        tag_list << if !item[1].nil?
                      "#{item[1]}#{pull_string}"
                    else
                      pull_string.to_s
                    end
      end
    end

    asset_update_string = ''

    if !@notes_type.empty? || !@owner_type.empty? || !@priority_column.empty?

      asset_update_string = '{"asset": {'
      unless @notes_type.empty?
        asset_update_string = if @notes_type == 'static'
                                "#{asset_update_string}\"notes\": \"#{@notes_value}\""
                              else
                                "#{asset_update_string}\"notes\": \"#{row[@notes_value]}\""
                              end
        asset_update_string = "#{asset_update_string}, " unless @owner_type.empty?
      end
      unless @owner_type.empty?
        asset_update_string = if @owner_type == 'static'
                                "#{asset_update_string}\"owner\": \"#{@owner_value}\""
                              else
                                "#{asset_update_string}\"owner\": \"#{row[@owner_value]}\""
                              end
        asset_update_string = "#{asset_update_string}, " if !@priority_column.nil? && !@priority_column.empty?
      end
      if !@priority_column.nil? && !@priority_column.empty?
        asset_update_string = "#{asset_update_string}\"priority\": \"#{row[@priority_column]}\""
      end

      asset_update_string = "#{asset_update_string}}}"
    end

    tag_string = ''
    tag_list.each do |t|
      t = t.gsub(/[\s,]/, ' ')
      tag_string << "#{t},"
    end
    tag_string = tag_string[0...-1]
    puts "tag string = #{tag_string}" if @debug

    work_queue << Array[query_url, tag_string, asset_update_string]

    threads.synchronize do
      threads_available.signal
    end
  end
  # Tell the consumer that we are finished loading the rows
  sysexit = true
end

consumer_thread = Thread.new do
  loop do
    @retries = 0
    puts 'at start of consumer loop' if @debug

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
        sleep(1.0 / 5.0)
        threads.select do |thread|
          thread.nil? || thread.status == false ||
            thread['finished'].nil? == false
        end.length.zero?
      end
      # Once an available spot is found, get the index of that spot so we may
      # use it for the new thread
      found_index = threads.rindex do |thread|
        thread.nil? || thread.status == false ||
          thread['finished'].nil? == false
      end
      puts "i just found index = #{found_index}" if @debug
    end
    # Get a new unit of work from the work queue

    threads[found_index] = Thread.new(work_to_do) do
      puts 'starting the thread loop' if @debug

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
      rescue RestClient::TooManyRequests => e
        retry
      rescue RestClient::UnprocessableEntity => e
        log_output = File.open(output_filename, 'a+')
        log_output << "Unable to get Asset - #{e.backtrace.inspect}... (time: #{Time.now}, start time: #{start_time})\n"
        log_output.close
        puts "Unable to get Asset: #{e.message}"
        Thread.exit
      rescue URI::InvalidURIError => e
        log_output = File.open(output_filename, 'a+')
        log_output << "Unable to get Assets - InvalidURI: #{e.backtrace.inspect}... (time: #{Time.now}, start time: #{start_time})\n"
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
          log_output = File.open(output_filename, 'a+')
          log_output << "General RestClient error #{e.backtrace.inspect}... (time: #{Time.now}, start time: #{start_time})\n"
          log_output.close
          puts "Unable to get assets: #{e.message}"
          Thread.exit
        end
      rescue Exception => e
        log_output = File.open(output_filename, 'a+')
        log_output << "Unable to get vulns - general exception: #{e.backtrace.inspect}... (time: #{Time.now}, start time: #{start_time})\n"
        log_output.close
        puts "Unable to get vulns: #{e.backtrace.inspect}"
        Thread.exit
      end
      query_meta_json = JSON.parse(query_response)['meta']
      total_found = query_meta_json.fetch('total_count')
      if total_found.zero?
        log_output = File.open(output_filename, 'a+')
        log_output << "Asset not found - #{query_url}... (time: #{Time.now}, start time: #{start_time})\n"
        log_output.close
        puts "No matching assets found for #{query_url}" if @debug
        Thread.current['finished'] = true
        threads.synchronize do
          threads_available.signal
        end
      else
        pages = query_meta_json.fetch('pages')
        query_response_json = JSON.parse(query_response)['assets']

        query_response_json.each do |item|
          asset_id = item['id']
          # puts asset_id

          begin
            unless tag_string.empty?
              tag_update_json = {
                'asset' => {
                  'tags' => tag_string.to_s
                }
              } ## Push tags to assets

              tag_api_url = "#{@asset_api_url}/#{asset_id}/tags"

              log_output = File.open(output_filename, 'a+')
              log_output << "Post tag URL...#{tag_api_url}\n"
              log_output << "tag json...#{tag_update_json}\n"
              log_output.close

              tag_update_response = RestClient::Request.execute(
                method: :put,
                url: tag_api_url,
                headers: @headers,
                proxy: @proxy_string,
                payload: tag_update_json,
                timeout: 10
              )
            end
            unless asset_string.empty?
              asset_update_json = JSON.parse(asset_string)

              update_api_url = "#{@asset_api_url}/#{asset_id}"

              log_output = File.open(output_filename, 'a+')
              log_output << "Post asset URL...#{update_api_url}\n"
              log_output << "asset update json...#{asset_update_json}\n"
              log_output.close
              update_response = RestClient::Request.execute(
                method: :put,
                url: update_api_url,
                headers: @headers,
                proxy: @proxy_string,
                payload: asset_update_json
              )
            end
          rescue RestClient::TooManyRequests => e
            retry
          rescue RestClient::UnprocessableEntity => e
            log_output = File.open(output_filename, 'a+')
            log_output << "Unable to update - UnprocessableEntity: #{e.backtrace.inspect}... (time: #{Time.now}, start time: #{start_time})\n"
            log_output.close
            puts "Unable to update: #{e.message}"
            Thread.exit
          rescue RestClient::BadRequest => e
            log_output = File.open(output_filename, 'a+')
            log_output << "Unable to update - BadRequest: #{e.backtrace.inspect}... (time: #{Time.now}, start time: #{start_time})\n"
            log_output.close
            puts "Unable to update: #{e.message}"
            Thread.exit
          rescue RestClient::Exception => e
            @retries ||= 0
            if @retries < @max_retries
              @retries += 1
              sleep(15)
              retry
            else
              log_output = File.open(output_filename, 'a+')
              log_output << "General RestClient in tag update error #{e.backtrace.inspect}... (time: #{Time.now}, start time: #{start_time})\n"
              log_output.close
              puts "Unable to update: #{e.message}"
              Thread.exit
            end
          rescue Exception => e
            log_output = File.open(output_filename, 'a+')
            log_output << "Unable to get vulns - general exception: #{e.backtrace.inspect}... (time: #{Time.now}, start time: #{start_time})\n"
            log_output.close
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
  thread&.join
end
puts 'DONE!'
