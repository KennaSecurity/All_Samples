# frozen_string_literal: true

# kenna-docker-upload
require 'rest-client'
require 'json'

@token = ARGV[0]
@dir_name = ARGV[1]

@vuln_api_url = 'https://api.kennasecurity.com/vulnerabilities'
@search_url = "#{@vuln_api_url}/search?q="
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json' }
@debug = false

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
output_filename = "kenna-docker_log-#{start_time.strftime('%Y%m%dT%H%M')}.txt"

puts 'Directory not found' unless directory_exists?(@dir_name)

Dir.glob("#{@dir_name}/*.json") do |fname|
  puts fname.to_s if @debug

  doc = JSON.parse(File.read(fname))

  ## Iterate through xml nodes

  log_output = File.open(output_filename, 'a+')
  log_output << "Reading file #{fname}... (time: #{Time.now}, start time: #{start_time})\n"
  log_output.close

  doc = doc[0]
  # namespace = doc.fetch("namespace")
  last_seen_time = doc.fetch('check_completed_at')
  last_seen = DateTime.parse(last_seen_time).strftime('%FT%TZ')

  layer_details = doc['layer_details']

  layer_details.each do |layer_detail|
    shasum = layer_detail.fetch('sha256sum')

    components = layer_detail['components']
    next if components.nil?

    components.each do |component|
      component_name = component.fetch('component')
      component_version = component.fetch('version')
      vulns = component['vulns']
      fullpath = component.fetch('fullpath')
      next if vulns.nil?

      vulns.each do |vuln|
        cve = vuln['vuln'].fetch('cve')
        search_cve = cve.sub(/\ACVE-/, '')
        identifier = search_cve.gsub(/-/, '')

        application = "Docker-#{component_name}-#{component_version}"
        notes = "Full Path = #{fullpath}"
        # notes = notes.gsub(/['<','>','_','\n','\t',':','(',')',''',"{","}"]/,'').chomp

        vuln_url = "#{@vuln_api_url}/search?status%5B%5D=all&q=file:#{enc_dblquote}#{application}#{enc_dblquote}+AND+cve:#{search_cve}"
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
              'cve_id' => cve.to_s,
              'primary_locator' => 'file',
              'last_seen_time' => last_seen,
              'file' => application,
              'identifier' => identifier
            }
          }
          # puts vuln_create_json if @debug
          vuln_update_json = {
            'vulnerability' => {
              'notes' => notes.to_s,
              'last_seen_time' => last_seen
            }
          }
          # puts vuln_update_json if @debug
          if vuln_id.nil?
            log_output = File.open(output_filename, 'a+')
            log_output << "Kenna Creating Vuln for new asset. #{cve} AND #{application}\n"
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
          log_output << "Kenna updating vuln: #{vuln_id} for #{application} and #{cve}\n"
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
        rescue Exception => e
          log_output = File.open(output_filename, 'a+')
          log_output << "Exception: #{e.message}... (time: #{Time.now}, start time: #{start_time})\n"
          log_output.close
          puts 'general exception'
        end
      end
    end
  end
end
