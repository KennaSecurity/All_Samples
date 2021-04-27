# frozen_string_literal: true

# kenna-archer-sync
require 'rest-client'
require 'json'
require 'nokogiri'

@token = ARGV[0]
@dir_name = ARGV[1]
@riskcode_id = ARGV[2] # custom field id for risk code
@confidence_id = ARGV[3] # custom field id for confidence
@riskdesc_id = ARGV[4] # custom field id for risk desc
@scandata_id = ARGV[5] # custom field for the scanner identification field

@vuln_api_url = 'https://api.kennasecurity.com/vulnerabilities'
@search_url = "#{@vuln_api_url}/search?q="
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json' }
@debug = true

@max_retries = 5

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
output_filename = "kenna-zap_log-#{start_time.strftime('%Y%m%dT%H%M')}.txt"

puts 'Directory not found' unless directory_exists?(@dir_name)

Dir.glob("#{@dir_name}/*.xml") do |fname|
  puts fname.to_s if @debug

  doc = File.open(fname) { |f| Nokogiri::XML(f) }

  ## Iterate through xml nodes

  log_output = File.open(output_filename, 'a+')
  log_output << "Reading file #{fname}... (time: #{Time.now}, start time: #{start_time})\n"
  log_output.close

  doc.xpath('//OWASPZAPReport').each do |report|
    tmp = report.xpath('@generated').text
    last_seen = DateTime.parse(tmp).strftime('%FT%TZ')
    puts "last_seen = #{last_seen}"

    report.xpath('site').each do |node|
      # uri = node.xpath("@name").to_s
      ssl = node.xpath('@ssl').to_s
      # puts "orig uri = #{uri}"

      node.xpath('alerts/alertitem').each do |item|
        plugin = item.xpath('pluginid').text
        puts "plugin = #{plugin}"
        riskcode = item.xpath('riskcode').text
        puts "riskcode = #{riskcode}"
        confidence = item.xpath('confidence').text
        puts "confidence = #{confidence}"
        riskdesc = item.xpath('riskdesc').text
        puts "riskdesc = #{riskdesc}"
        cweid = item.xpath('cweid').text
        puts "cweid = #{cweid}"
        wascid = item.xpath('wascid').text
        puts "wascid = #{wascid}"
        next if wascid.empty? && cweid.empty?

        item.xpath('instances/instance').each do |issue|
          param = nil

          param = issue.xpath('param').text

          evidence = issue.xpath('evidence').text
          uri = issue.xpath('uri').text
          attack = item.xpath('attack').text
          puts "attack = #{attack}"
          puts "evidence = #{evidence}"
          puts "param = #{param}"

          if ssl == 'false'
            puts 'ssl is false'
            uri.gsub('https', 'http')
          end

          notes = "Evidence=#{evidence}" unless evidence.empty?

          uri = URI.encode(uri)

          puts "uri = #{uri}"

          unless attack.empty?
            notes = if notes.empty?
                      "Attack=#{attack}"
                    else
                      "#{notes} Attack=#{attack}"
                    end
          end
          unless param.empty?
            notes = if notes.empty?
                      "Param=#{param}"
                    else
                      "#{notes} Param=#{param}"
                    end
          end

          notes = notes.gsub(/['<','>','_','\n','\t',':','(',')',''',"{","}"]/, '').chomp
          # Build query string/URL
          vuln_url = "#{@vuln_api_url}/search?status%5B%5D=all&q=url:#{enc_dblquote}#{uri}#{enc_dblquote}+AND+cwe:#{enc_dblquote}CWE-#{cweid}#{enc_dblquote}"
          puts "vuln url = #{vuln_url}" if @debug

          begin
            vuln_id = nil

            get_response = RestClient::Request.execute(
              method: :get,
              url: vuln_url,
              headers: @headers
            )

            get_response_json = JSON.parse(get_response)['vulnerabilities']
            vuln_id = get_response_json[0]['id'] if get_response_json.count.positive?

            puts "vuln_id= #{vuln_id}" if @debug

            query_url = @vuln_api_url.to_s

            vuln_create_json = {
              'vulnerability' => {
                'cwe_id' => "CWE-#{cweid}",
                'wasc_id' => "WASC-#{wascid}",
                'primary_locator' => 'url',
                'last_seen_time' => last_seen,
                'url' => uri,
                'identifier' => plugin
              }
            }
            # change me----the custome field identifiers need to be changed for each instance
            vuln_update_json = {
              'vulnerability' => {
                'status' => 'open',
                'notes' => notes.to_s,
                'last_seen_time' => last_seen,
                'custom_fields' => {
                  @riskcode_id.to_s => riskcode,
                  @confidence_id.to_s => confidence,
                  @riskdesc_id.to_s => riskdesc.to_s,
                  @scandata_id.to_s => 'OWASPZAP'
                }
              }
            }

            if vuln_id.nil?
              log_output = File.open(output_filename, 'a+')
              log_output << "Kenna Creating Vuln for new asset. #{cweid} AND #{uri}\n"
              log_output.close
              puts 'creating new vuln' if @debug
              update_response = RestClient::Request.execute(
                method: :post,
                url: @vuln_api_url,
                headers: @headers,
                payload: vuln_create_json
              )

              update_response_json = JSON.parse(update_response)['vulnerability']
              vuln_id = update_response_json.fetch('id')

            end

            vuln_custom_uri = "#{@vuln_api_url}/#{vuln_id}"
            log_output = File.open(output_filename, 'a+')
            log_output << "Kenna updating vuln: #{vuln_id} for #{uri} and #{cweid}\n"
            log_output.close
            puts 'updating vuln' if @debug
            update_response = RestClient::Request.execute(
              method: :put,
              url: vuln_custom_uri,
              headers: @headers,
              payload: vuln_update_json
            )
          # if update_response.code == 204 then next end
          # end
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
    end
  end
end
