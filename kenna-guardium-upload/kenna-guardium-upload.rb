# frozen_string_literal: true

# kenna-archer-sync
require 'rest-client'
require 'json'
require 'nokogiri'

@token = ARGV[0]
@dir_name = ARGV[1]
@scanner_field_id = ARGV[2]
@vendor_field_id = ARGV[3]
@hostcase = ARGV[4] # upcase, downcase or nochange

@vuln_api_url = 'https://api.kennasecurity.com/vulnerabilities'
@search_url = "#{@vuln_api_url}/search?q="
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json' }
@max_retries = 5
@debug = false

# Encoding characters
enc_colon = '%3A'
enc_dblquote = '%22'
enc_space = '%20'

## Query API with query_url
asset_id = nil
primary_locator = nil
key = nil
vuln_id = nil
status = nil
notes = nil
serviceName = nil

def directory_exists?(directory)
  Dir.exist?(directory)
end

start_time = Time.now
output_filename = "kenna-guardium_log-#{start_time.strftime('%Y%m%dT%H%M')}.txt"

puts 'Directory not found' unless directory_exists?(@dir_name)

Dir.glob("#{@dir_name}/*.xml") do |fname|
  puts fname.to_s if @debug

  doc = File.open(fname) { |f| Nokogiri::XML(f) }

  ## Iterate through xml nodes

  log_output = File.open(output_filename, 'a+')
  log_output << "Reading file #{fname}... (time: #{Time.now}, start time: #{start_time})\n"
  log_output.close

  doc.xpath('//host').each do |node|
    ip_str = node.xpath('ip/@value').to_s
    dns_hostname = node.xpath('hostName').text
    case @hostcase
    when 'upcase'
      dns_hostname.upcase!
    when 'downcase'
      dns_hostname.downcase!
    end
    puts "ip_str = #{ip_str}" if @debug
    puts "hostname = #{dns_hostname}" if @debug
    if !dns_hostname.nil?
      primary_locator = 'hostname'
      key = dns_hostname.to_s
    else
      primary_locator = 'ip_address'
      key = ip_str.to_s
    end
    vuln_url = nil

    begin
      last_seen = DateTime.parse(node.xpath('lastSeen').text)

      vendor = node.xpath('port/service/@vendor').text.chomp
      port = node.xpath('port/@value').text.chomp

      version = node.xpath('port/service/@version').text.gsub(/['<','>','\n','\t',':','(',')']/, '').chomp
      serviceName = node.xpath('port/service/@name').text.chomp

      notes = "Port=#{port} Name=#{serviceName} Version=#{version}"
      # ## Build query string/URL
      if !dns_hostname.nil?
        vuln_url = "#{@vuln_api_url}/search?status%5B%5D=all&q=hostname:#{enc_dblquote}#{dns_hostname}*#{enc_dblquote}"
      elsif !ip_str.nil?
        vuln_url = "#{@vuln_api_url}/search?status%5B%5D=all&q=ip:#{enc_dblquote}#{ip_str}#{enc_dblquote}"
      else
        next
      end
      puts "vuln url = #{vuln_url}" if @debug

      node.xpath(".//vulnerability[@type='CVE ID']").each do |vuln|
        final_vuln_url = nil
        cve = vuln.xpath('./@id').text
        final_vuln_url = "#{vuln_url}+AND+cve:%22#{cve}%22"
        puts "final vuln url = #{final_vuln_url}" if @debug
        vuln_id = nil

        get_response = RestClient::Request.execute(
          method: :get,
          url: final_vuln_url,
          headers: @headers
        )

        get_response_json = JSON.parse(get_response)['vulnerabilities']
        get_response_json.each do |item|
          vuln_id = item['id']
        end
        puts "vuln_id= #{vuln_id}" if @debug

        query_url = @vuln_api_url.to_s

        vuln_create_json = {
          'vulnerability' => {
            'cve_id' => "CVE-#{cve}",
            'primary_locator' => primary_locator.to_s,
            'last_seen_time' => last_seen,
            primary_locator.to_s => key
          }
        }
        # change me----the custome field identifiers need to be changed for each instance
        vuln_update_json = {
          'vulnerability' => {
            'status' => 'open',
            'notes' => notes.to_s,
            'last_seen_time' => last_seen,
            'custom_fields' => {
              @scanner_field_id.to_s => 'Guardium',
              @vendor_field_id.to_s => vendor.to_s
            }
          }
        }

        if vuln_id.nil?
          log_output = File.open(output_filename, 'a+')
          log_output << "Kenna Creating Vuln for new asset. #{cve} AND #{key}\n"
          log_output.close
          puts 'creating new vuln' if @debug
          update_response = RestClient::Request.execute(
            method: :post,
            url: @vuln_api_url,
            headers: @headers,
            payload: vuln_create_json
          )

          update_response_json = JSON.parse(update_response)['vulnerability']
          new_json = JSON.parse(update_response_json)

          vuln_id = new_json.fetch('id')
        end

        vuln_custom_uri = "#{@vuln_api_url}/#{vuln_id}"
        log_output = File.open(output_filename, 'a+')
        log_output << "Kenna updating vuln: #{vuln_id} for #{cve} and #{key}\n"
        log_output.close
        puts 'updating vuln' if @debug
        update_response = RestClient::Request.execute(
          method: :put,
          url: vuln_custom_uri,
          headers: @headers,
          payload: vuln_update_json
        )
        next if update_response.code == 204
      end
    rescue RestClient::UnprocessableEntity => e
      log_output = File.open(output_filename, 'a+')
      log_output << "UnprocessableEntity: #{e.message}... (time: #{Time.now}, start time: #{start_time})\n"
      log_output.close
      puts "UnprocessableEntity: #{e.message}"
    rescue RestClient::BadRequest => e
      log_output = File.open(output_filename, 'a+')
      log_output << "BadRequest: #{e.message}... (time: #{Time.now}, start time: #{start_time})\n"
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
        log_output = File.open(output_filename, 'a+')
        log_output << "General RestClient error #{e.message}... (time: #{Time.now}, start time: #{start_time})\n"
        log_output.close
        puts "Exception: #{e.message}"
      end
    end
  end
end
