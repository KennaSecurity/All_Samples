# frozen_string_literal: true

require 'rest-client'
require 'json'
require 'csv'
# require 'URI'

@data_file = ARGV[0]
@has_header = ARGV[1]
@mapping_file = ARGV[2]
@skip_autoclose = ARGV[3] # defaults to false
@output_filename = ARGV[4] # json filename for converted data
# DBro - Added for ASSET ONLY Run
@assets_only = ARGV.length >= 6 ? ARGV[5] : 'false' # Optional TRUE/FALSE param to indicate ASSET ONLY import. Defaults to false
@domain_suffix = ARGV.length == 7 ? ARGV[6] : '' # Optional domain suffix for hostnames.

@token = ARGV[7]
@folder = ARGV[8]
@connector_id = ARGV[9]
@file_extension = ARGV[10]

@LOCATOR_DELIMITER = ':'
@API_ENDPOINT_CONNECTOR = 'https://api.kennasecurity.com/connectors'
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json' }

@debug = true
$map_locator = ''

@output_filename = "#{@output_filename}.json" unless @output_filename.match(/\.json$/)

#### SAUSAGE MAKING METHODS
module Kenna
  module KdiHelpers
    def generate_kdi_file
      { skip_autoclose: (@skip_autoclose.eql?('true') ? true : false), assets: $assets.uniq,
        vuln_defs: $vuln_defs.uniq }
    end

    def create_asset(file, ip_address, mac_address, hostname, ec2, netbios, url, fqdn, external_id, database, application, tags, owner, os, os_version, priority)
      tmpassets = []
      success = true

      # this case statement will check for dup assets based on the main locator as declared in the options input file
      # comment out the entire block if you want all deduplicaton to happen in Kenna

      case $map_locator
      when 'ip_address'
        return success unless $assets.select { |a| a[:ip_address] == ip_address }.empty?
      when 'hostname'
        return success unless $assets.select { |a| a[:hostname] == hostname }.empty?
      when 'file'
        return success unless $assets.select { |a| a[:file] == file }.empty?
      when 'mac_address'
        return success unless $assets.select { |a| a[:mac_address] == mac_address }.empty?
      when 'netbios'
        return success unless $assets.select { |a| a[:netbios] == netbios }.empty?
      when 'ec2'
        return success unless $assets.select { |a| a[:ec2] == ec2 }.empty?
      when 'fqdn'
        return success unless $assets.select { |a| a[:fqdn] == fqdn }.empty?
      when 'external_id'
        return success unless $assets.select { |a| a[:external_id] == external_id }.empty?
      when 'database'
        return success unless $assets.select { |a| a[:database] == database }.empty?
      when 'url'
        return success unless $assets.select { |a| a[:url] == url }.empty?
      else
        puts 'Error: main locator not provided' if @debug
        success = false

      end

      tmpassets << { file: file.to_s } unless file.nil? || file.empty?
      tmpassets << { ip_address: ip_address } unless ip_address.nil? || ip_address.empty?
      tmpassets << { mac_address: mac_address } unless mac_address.nil? || mac_address.empty?
      tmpassets << { hostname: hostname } unless hostname.nil? || hostname.empty?
      tmpassets << { ec2: ec2.to_s } unless ec2.nil? || ec2.empty?
      tmpassets << { netbios: netbios.to_s } unless netbios.nil? || netbios.empty?
      tmpassets << { url: url.to_s } unless url.nil? || url.empty?
      tmpassets << { fqdn: fqdn.to_s } unless fqdn.nil? || fqdn.empty?
      tmpassets << { external_id: external_id.to_s } unless external_id.nil? || external_id.empty?
      tmpassets << { database: database.to_s } unless database.nil? || database.empty?
      tmpassets << { application: application.to_s } unless application.nil? || application.empty?
      tmpassets << { tags: tags } unless tags.nil? || tags.empty?
      tmpassets << { owner: owner.to_s } unless owner.nil? || owner.empty?
      tmpassets << { os: os.to_s } unless os.nil? || os.empty?
      tmpassets << { os_version: os_version.to_s } unless os_version.nil? || os_version.to_s.empty?
      tmpassets << { priority: priority } unless priority.nil? || priority.to_s.empty?
      tmpassets << { vulns: [] }

      if file.to_s.empty? && ip_address.to_s.empty? && mac_address.to_s.empty? && hostname.to_s.empty? && ec2.to_s.empty? && netbios.to_s.empty? && url.to_s.empty? && database.to_s.empty? && external_id.to_s.empty? && fqdn.to_s.empty? && application.to_s.empty?
        success = false
      end

      $assets << tmpassets.reduce(&:merge) if success

      success
    end

    def create_asset_vuln(hostname, ip_address, file, mac_address, netbios, url, ec2, fqdn, external_id, database, scanner_type, scanner_id, details, created, scanner_score, last_fixed,
                          last_seen, status, closed, port)

      # find the asset
      case $map_locator
      when 'ip_address'
        asset = $assets.select { |a| a[:ip_address] == ip_address }.first
      when 'hostname'
        asset = $assets.select { |a| a[:hostname] == hostname }.first
      when 'file'
        asset = $assets.select { |a| a[:file] == file }.first
      when 'mac_address'
        asset = $assets.select { |a| a[:mac_address] == mac_address }.first
      when 'netbios'
        asset = $assets.select { |a| a[:netbios] == netbios }.first
      when 'url'
        asset = $assets.select { |a| a[:url] == url }.first
      when 'ec2'
        asset = $assets.select { |a| a[:ec2] == ec2 }.first
      when 'fqdn'
        asset = $assets.select { |a| a[:fqdn] == fqdn }.first
      when 'external_id'
        asset = $assets.select { |a| a[:external_id] == external_id }.first
      when 'database'
        asset = $assets.select { |a| a[:database] == database }.first
      else
        'Error: main locator not provided' if @debug
      end

      puts "Unknown asset, can't associate a vuln!" unless asset
      return unless asset

      # associate the asset
      assetvulns = []
      assetvulns << { scanner_type: scanner_type.to_s, scanner_identifier: scanner_id.to_s }
      assetvulns << { details: details.to_s } unless details.nil?
      assetvulns << { created_at: created.to_s } unless created.nil?
      assetvulns << { scanner_score: scanner_score } unless scanner_score.nil? || scanner_score.zero?
      assetvulns << { last_fixed_on: last_fixed.to_s } unless last_fixed.nil?
      assetvulns << { last_seen_at: last_seen.to_s } unless last_seen.nil?
      assetvulns << { closed_at: closed.to_s } unless closed.nil?
      assetvulns << { port: port } unless port.nil?
      assetvulns << { status: status.to_s }

      asset[:vulns] << assetvulns.reduce(&:merge)
    end

    def create_vuln_def(scanner_type, scanner_id, cve_id, wasc_id, cwe_id, name, description, solution)
      vuln_def = []
      vuln_def << { scanner_type: scanner_type.to_s, scanner_identifier: scanner_id.to_s }
      vuln_def << { cve_identifiers: cve_id.to_s } unless cve_id.nil? || cve_id.empty?
      vuln_def << { wasc_identifiers: wasc_id.to_s } unless wasc_id.nil? || wasc_id.empty?
      vuln_def << { cwe_identifiers: cwe_id.to_s } unless cwe_id.nil? || cwe_id.empty?
      vuln_def << { name: name.to_s } unless name.nil? || name.empty?
      vuln_def << { description: description.to_s } unless description.nil? || description.empty?
      vuln_def << { solution: solution.to_s } unless solution.nil? || solution.empty?

      $vuln_defs << vuln_def.reduce(&:merge)
    end
  end
end
#### END OF SAUSAGE MAKING

# Gotta have these two globals because I am lazy and it is easier
$assets = []
$vuln_defs = []
$mapping_array = []
$date_format_in = ''

CSV.parse(File.open(@mapping_file, 'r:iso-8859-1:utf-8', &:read), headers: true) do |row|
  $mapping_array << Array[row[0], row[1]]
  $mapping_array.compact
end
# headers =
$date_format_in = $mapping_array.assoc('date_format').last.to_s
$map_locator = $mapping_array.assoc('locator').last.to_s
map_file = $mapping_array.assoc('file').last.to_s
map_ip_address = $mapping_array.assoc('ip_address').last.to_s
map_mac_address = $mapping_array.assoc('mac_address').last.to_s
map_hostname = $mapping_array.assoc('hostname').last.to_s
map_ec2 = $mapping_array.assoc('ec2').last.to_s
map_netbios = $mapping_array.assoc('netbios').last.to_s
map_url = $mapping_array.assoc('url').last.to_s
map_fqdn = $mapping_array.assoc('fqdn').last.to_s
map_external_id = $mapping_array.assoc('external_id').last.to_s
map_database = $mapping_array.assoc('database').last.to_s
map_application = $mapping_array.assoc('application').last.to_s
map_tags = $mapping_array.assoc('tags').last.to_s
map_tag_prefix = $mapping_array.assoc('tag_prefix').last.to_s
map_owner = $mapping_array.assoc('owner').last.to_s
map_os = $mapping_array.assoc('os').last.to_s
map_os_version = $mapping_array.assoc('os_version').last.to_s
map_priority = $mapping_array.assoc('priority').last.to_s

if @assets_only == 'false' # DBro - Added for ASSET ONLY Run
  map_scanner_source = $mapping_array.assoc('scanner_source').last.to_s
  map_scanner_type = $mapping_array.assoc('scanner_type').last.to_s
  map_scanner_id = $mapping_array.assoc('scanner_id').last.to_s
  map_scanner_id.encode!('utf-8')
  map_details = $mapping_array.assoc('details').last.to_s
  map_created = $mapping_array.assoc('created').last.to_s
  map_scanner_score = $mapping_array.assoc('scanner_score').last.to_s
  map_last_fixed = $mapping_array.assoc('last_fixed').last.to_s
  map_last_seen = $mapping_array.assoc('last_seen').last.to_s
  map_status = $mapping_array.assoc('status').last.to_s
  map_closed = $mapping_array.assoc('closed').last.to_s
  map_port = $mapping_array.assoc('port').last.to_s
  map_cve_id = $mapping_array.assoc('cve_id').last.to_s
  map_wasc_id = $mapping_array.assoc('wasc_id').last.to_s
  map_cwe_id = $mapping_array.assoc('cwe_id').last.to_s
  map_name = $mapping_array.assoc('name').last.to_s
  map_description = $mapping_array.assoc('description').last.to_s
  map_solution = $mapping_array.assoc('solution').last.to_s
  score_map_string = $mapping_array.assoc('score_map').last.to_s
  status_map_string = $mapping_array.assoc('status_map').last.to_s
  score_map = JSON.parse(score_map_string) unless score_map_string.nil? || score_map_string.empty?
  status_map = JSON.parse(status_map_string) unless status_map_string.nil? || status_map_string.empty?
end

# Configure Date format
###########################
# CUSTOMIZE Date format
###########################
# date_format_in = "%m/%d/%Y %H:%M"
date_format_KDI = '%Y-%m-%d-%H:%M:%S'

include Kenna::KdiHelpers

CSV.parse(File.open(@data_file, 'r:bom|utf-8', &:read), headers: @has_header.eql?('true') ? true : false) do |row|
  ##################
  #  CSV MAPPINGS  #
  ##################
  # Asset settings #
  ##################
  locator = row[$map_locator.to_s] # field used to compare for dupes
  file = row[map_file.to_s] # (string) path to affected file
  ip_address = row[map_ip_address.to_s] # (string) ip_address of internal facing asset
  mac_address = row[map_mac_address.to_s] # (mac format-regex) MAC address asset
  hostname = row[map_hostname.to_s] # (string) hostname name/domain name of affected asset
  ec2 = row[map_ec2.to_s] # (string) Amazon EC2 instance id or name
  netbios = row[map_netbios.to_s] # (string) netbios name
  url = row[map_url.to_s]
  url = url.strip unless url.nil? # (string) URL pointing to asset
  fqdn = row[map_fqdn.to_s] # (string) fqdn of asset
  external_id = row[map_external_id.to_s] # (string) ExtID of asset-Often used as an int org name for asset
  database = row[map_database.to_s] # (string) Name of database
  application = row[map_application.to_s] # (string) ID/app Name

  # DBro - Added for ASSET ONLY Run
  hostname += ".#{@domain_suffix}" if @domain_suffix != '' && (@assets_only == 'false' || @assets_only == false)

  #########################
  # Asset Metadata fields #
  #########################
  tag_list = map_tags.split(',') # (string) list of strings that correspond to tags on an asset
  prefix_list = map_tag_prefix.split(',')
  # puts tag_list
  tags = []
  count = 0
  tag_list.each do |col|
    col = col.gsub(/\A['"]+|['"]+\Z/, '')
    if !row[col].nil? && !row[col].empty?
      tags << if prefix_list.empty?
                (row[col]).to_s
              else
                prefix_list[count] + (row[col]).to_s
              end
    end
    count += 1
  end
  owner = row[map_owner.to_s] # (string) Some string that identifies an owner of an asset
  os = row[map_os.to_s] # (string) Operating system of asset
  os_version = row[map_os_version.to_s] # (string) OS version
  priority = row[map_priority.to_s].to_i unless row[map_priority.to_s].nil? || row[map_priority.to_s].empty?

  if @assets_only == 'false' # DBro - Added for ASSET ONLY Run
    #########################
    # Vulnerability Section #
    #########################
    scanner_type = if map_scanner_source == 'static'
                     map_scanner_type.to_s # (string) - default is freeform if nil from CSV
                   else
                     row[map_scanner_type.to_s] # (string) - default is freeform if nil from CSV
                   end
    raise 'no scanner type found!' unless !scanner_type.nil? && !scanner_type.empty?

    scanner_id = row[map_scanner_id.to_s]
    raise 'no scanner id found!' unless !scanner_id.nil? && !scanner_id.empty?

    details = row[map_details.to_s] # (string) - Details about vuln
    created = row[map_created.to_s]
    if score_map.nil? || score_map.empty? # (string) - Date vuln created
      unless row[map_scanner_score.to_s].nil? || row[map_scanner_score.to_s].empty?
        scanner_score = row[map_scanner_score.to_s].to_i
      end
    else
      unless row[map_scanner_score.to_s].nil? || row[map_scanner_score.to_s].empty?
        scanner_score = score_map[row[map_scanner_score.to_s]].to_i
      end
    end
    last_fixed = row[map_last_fixed.to_s] # (string) - Last fixed date
    last_seen = row[map_last_seen.to_s]
    status = if status_map.nil? || status_map.empty?
               row[map_status.to_s] # (string) #Rqd Def if nil; open status by default if not in import
             else
               status_map[row[map_status.to_s]]
             end
    closed = row[map_closed.to_s] # (string) Date it was closed
    port = row[map_port.to_s].to_i unless row[map_port.to_s].nil? || row[map_port.to_s].empty?

    ############################
    # Vulnerability Definition #
    ############################

    # in vuln section ##  scanner =
    # in vuln section ##  scanner_id =
    cve_id = row[map_cve_id.to_s] # (string) Any CVE(s)?
    wasc_id = row[map_wasc_id.to_s] # (string) Any WASC?
    cwe_id = row[map_cwe_id.to_s] # (string) Any CWE?
    name = row[map_name.to_s] # (string) Name/title of Vuln
    description = row[map_description.to_s] # (string) Description
    solution = row[map_solution.to_s] # (string) Solution
  end

  # #call the methods that will build the json now##

  status = 'open' if status.nil? || status.empty?
  # Convert the dates
  created = DateTime.strptime(created, $date_format_in).strftime(date_format_KDI) unless created.nil? || created.empty?
  unless last_fixed.nil? || last_fixed.empty?
    last_fixed = DateTime.strptime(last_fixed,
                                   $date_format_in).strftime(date_format_KDI)
  end

  last_seen = if last_seen.nil? || last_seen.empty?
                # last_seen = "2019-03-01-14:00:00"
                DateTime.now.strftime(date_format_KDI)
              else
                DateTime.strptime(last_seen, $date_format_in).strftime(date_format_KDI)
              end

  closed = DateTime.strptime(closed, $date_format_in).strftime(date_format_KDI) unless closed.nil?

  ### CREATE THE ASSET
  done = create_asset(file, ip_address, mac_address, hostname, ec2, netbios, url, fqdn, external_id, database,
                      application, tags, owner, os, os_version, priority)
  # puts "create assset = #{done}"
  next unless done

  ### ASSOCIATE THE ASSET TO THE VULN

  if @assets_only == 'false' # DBro - Added for ASSET ONLY Run
    create_asset_vuln(hostname, ip_address, file, mac_address, netbios, url, ec2, fqdn, external_id, database, scanner_type, scanner_id, details, created, scanner_score, last_fixed,
                      last_seen, status, closed, port)

    # CREATE A VULN DEF THAT HAS THE SAME ID AS OUR VULN
    create_vuln_def(scanner_type, scanner_id, cve_id, wasc_id, cwe_id, name, description, solution)
  end
end

kdi_output = generate_kdi_file

# puts JSON.pretty_generate kdi_output

f = File.new(@output_filename, 'w')
f.write(JSON.pretty_generate(kdi_output))
f.close

def directory_exists?(directory)
  Dir.exist?(directory)
end

start_time = Time.now
output_filename = "kenna-runConnector_log-#{start_time.strftime('%Y%m%dT%H%M')}.txt"
log_output = File.open(output_filename, 'a+')
log_output << "Start time: time: #{Time.now}\n"

puts 'Directory not found' unless directory_exists?(@folder)

Dir.entries(@folder.to_s).each do |abspath|
  puts abspath
  next unless abspath.end_with? @file_extension.to_s

  fname = File.basename(abspath, @file_extension.to_s)

  conn_url = "#{@API_ENDPOINT_CONNECTOR}/#{@connector_id}/data_file?run=true"
  puts conn_url if @debug

  begin
    query_response = RestClient::Request.execute(
      method: :post,
      url: conn_url,
      headers: @headers,
      payload: {
        multipart: true,
        file: File.new("#{@folder}/" + abspath, 'rb')
      }
    )

    query_response_json = JSON.parse(query_response.body)

    puts query_response_json.fetch('success') if @debug

    running = true

    conn_check_url = "#{@API_ENDPOINT_CONNECTOR}/#{@connector_id}"

    while running

      sleep(15)
      conn_check = RestClient::Request.execute(
        method: :get,
        url: conn_check_url,
        headers: @headers
      )

      conn_check_json = JSON.parse(conn_check)['connector']
      puts conn_check_json if @debug
      running = conn_check_json.fetch('running')
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
  log_output = File.open(output_filename, 'a+')
  log_output << "End time: time: #{Time.now}\n"
end
