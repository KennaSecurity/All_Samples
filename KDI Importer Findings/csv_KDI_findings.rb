# frozen_string_literal: true

require 'json'
require 'csv'
# require 'pry'

@data_file = ARGV[0]
@has_header = ARGV[1]
@mapping_file = ARGV[2]
@skip_autoclose = ARGV[3] # defaults to false
@output_filename = ARGV[4] # json filename for converted data

@debug = false
$map_locator = ''

@output_filename = "#{@output_filename}.json" unless @output_filename.match(/\.json$/)

#### SAUSAGE MAKING METHODS
module Kenna
  module KdiHelpers
    def generate_kdi_file
      { skip_autoclose: (@skip_autoclose.eql?('true') ? true : false), assets: $assets.uniq,
        vuln_defs: $vuln_defs.uniq }
    end

    def create_asset(file, url, external_id, application, tags, owner)
      tmpassets = []
      success = true

      # this case statement will check for dup assets based on the main locator as declared in the options input file
      # comment out the entire block if you want all deduplicaton to happen in Kenna

      case $map_locator
      when 'file'
        return success unless $assets.select { |a| a[:file] == file }.empty?
      when 'external_id'
        return success unless $assets.select { |a| a[:external_id] == external_id }.empty?
      when 'url'
        return success unless $assets.select { |a| a[:url] == url }.empty?
      else
        puts 'Error: main locator not provided' if @debug
        success = false

      end

      tmpassets << { file: file.to_s } unless file.nil? || file.empty?
      tmpassets << { url: url.to_s } unless url.nil? || url.empty?
      tmpassets << { external_id: external_id.to_s } unless external_id.nil? || external_id.empty?
      tmpassets << { application: application.to_s } unless application.nil? || application.empty?
      tmpassets << { tags: tags } unless tags.nil? || tags.empty?
      tmpassets << { owner: owner.to_s } unless owner.nil? || owner.empty?
      tmpassets << { vulns: [] }
      tmpassets << { findings: [] }

      success = false if file.to_s.empty? && url.to_s.empty? && application.to_s.empty?

      $assets << tmpassets.reduce(&:merge) if success

      success
    end

    def create_asset_findings(file, url, external_id, scanner_type, scanner_id, additional_fields, created, severity,
                              last_seen, triage_state, due_date)

      # find the asset
      case $map_locator
      when 'file'
        asset = $assets.select { |a| a[:file] == file }.first
      when 'url'
        asset = $assets.select { |a| a[:url] == url }.first
      when 'external_id'
        asset = $assets.select { |a| a[:external_id] == external_id }.first
      else
        'Error: main locator not provided' if @debug
      end

      put "Unknown asset, can't associate a vuln!" unless asset
      returm unless asset

      # associate the asset
      assetfindings = []
      assetfindings << { scanner_type: scanner_type.to_s, scanner_identifier: scanner_id.to_s }
      assetfindings << { additional_fields: additional_fields } unless additional_fields.nil?
      assetfindings << { created_at: created.to_s } unless created.nil?
      assetfindings << { severity: severity } unless severity.nil? || severity.zero?
      assetfindings << { last_seen_at: last_seen.to_s } unless last_seen.nil?
      assetfindings << { due_date: due_date } unless due_date.nil?
      assetfindings << { triage_state: triage_state.to_s }

      asset[:findings] << assetfindings.reduce(&:merge)
    end

    def create_vuln_def(scanner_type, scanner_id, cve_id, wasc_id, cwe_id, name, description, solution)
      vuln_def = []
      vuln_def << { scanner_type: scanner_type.to_s, scanner_identifier: scanner_id.to_s }
      vuln_def << { cve_identifiers: cve_id.to_s } unless cve_id.nil? || cve_id.empty?
      vuln_def << { wasc_identifier: wasc_id.to_s } unless wasc_id.nil? || wasc_id.empty?
      vuln_def << { cwe_identifier: cwe_id.to_s } unless cwe_id.nil? || cwe_id.empty?
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

# binding.pry

CSV.parse(File.open(@mapping_file, 'r:iso-8859-1:utf-8', &:read), headers: true) do |row|
  $mapping_array << Array[row[0], row[1]]
  $mapping_array.compact
end
# headers =
$date_format_in = $mapping_array.assoc('date_format').last.to_s
$map_locator = $mapping_array.assoc('locator').last.to_s
map_file = $mapping_array.assoc('file').last.to_s
map_url = $mapping_array.assoc('url').last.to_s
map_external_id = $mapping_array.assoc('external_id').last.to_s
map_application = $mapping_array.assoc('application').last.to_s
map_tags = $mapping_array.assoc('tags').last.to_s
map_tag_prefix = $mapping_array.assoc('tag_prefix').last.to_s
map_owner = $mapping_array.assoc('owner').last.to_s

# binding.pry

map_scanner_source = $mapping_array.assoc('scanner_source').last.to_s
map_scanner_type = $mapping_array.assoc('scanner_type').last.to_s
map_scanner_id = $mapping_array.assoc('scanner_id').last.to_s
map_scanner_id.encode!('utf-8')
map_additional_fields = $mapping_array.assoc('additional_fields').last.to_s
map_created = $mapping_array.assoc('created').last.to_s
map_severity = $mapping_array.assoc('severity').last.to_s
map_last_seen = $mapping_array.assoc('last_seen').last.to_s
map_triage_state = $mapping_array.assoc('triage_state').last.to_s
map_cve_id = $mapping_array.assoc('cve_id').last.to_s
map_wasc_id = $mapping_array.assoc('wasc_id').last.to_s
map_cwe_id = $mapping_array.assoc('cwe_id').last.to_s
map_name = $mapping_array.assoc('name').last.to_s
map_description = $mapping_array.assoc('description').last.to_s
map_solution = $mapping_array.assoc('solution').last.to_s
severity_map_string = $mapping_array.assoc('severity_map').last.to_s
triage_state_map_string = $mapping_array.assoc('triage_state_map').last.to_s
severity_map = JSON.parse(severity_map_string) unless severity_map_string.nil? || severity_map_string.empty?
unless triage_state_map_string.nil? || triage_state_map_string.empty?
  triage_state_map = JSON.parse(triage_state_map_string)
end
# Configure Date format
###########################
# CUSTOMIZE Date format
###########################
# date_format_in = "%m/%d/%Y %H:%M"
date_format_KDI = '%Y-%m-%d-%H:%M:%S'

include Kenna::KdiHelpers

CSV.parse(File.open(@data_file, 'r:iso-8859-1:utf-8', &:read),
          headers: @has_header.eql?('true') ? true : false) do |row|
  # binding.pry

  ##################
  #  CSV MAPPINGS  #
  ##################
  # Asset settings #
  ##################
  locator = row[$map_locator.to_s] # field used to compare for dupes
  file = row[map_file.to_s]                 # (string) path to affected file
  url = row[map_url.to_s]                   # (string) URL pointing to asset
  external_id = row[map_external_id.to_s] # (string) ExtID of asset-Often used as an int org name for asset
  application = row[map_application.to_s] # (string) ID/app Name

  #########################
  # Asset Metadata fields #
  #########################
  tag_list = map_tags.split(',') # (string) list of strings that correspond to tags on an asset
  prefix_list = map_tag_prefix.split(',')
  additional_fields_list = map_additional_fields.split(',') unless map_additional_fields.nil?

  # binding.pry

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
  tags.compact if !tags.nil? && !tags.empty?

  additional_fields = nil
  if !additional_fields_list.nil? && !additional_fields_list.empty?
    additional_fields_list.each do |col|
      col = col.gsub(/\A['"]+|['"]+\Z/, '')
      if !row[col].nil? && !row[col].empty?
        if additional_fields.nil?
          additional_fields = { col => row[col] }
        else
          additional_fields.merge!({ col => row[col] })
        end
      end
    end
  end

  additional_fields.compact if !additional_fields.nil? && !additional_fields.empty?

  owner = row[map_owner.to_s] # (string) Some string that identifies an owner of an asset

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

  # additional_fields = JSON.pretty_generate(additional_fields) if !additional_fields.nil? && !additional_fields.empty?       #(string) - Details about vuln
  created = row[map_created.to_s]
  if severity_map.nil? || severity_map.empty? # (string) - Date vuln created
    severity = row[map_severity.to_s].to_i unless row[map_severity.to_s].nil? || row[map_severity.to_s].empty?
  else
    unless row[map_severity.to_s].nil? || row[map_severity.to_s].empty?
      severity = severity_map[row[map_severity.to_s]].to_i
    end
  end
  last_seen = row[map_last_seen.to_s]
  triage_state = if triage_state_map.nil? || triage_state_map.empty?
                   row[map_triage_state.to_s] # (string) #Rqd Def if nil; open triage_state by default if not in import
                 else
                   triage_state_map[row[map_triage_state.to_s]]
                 end

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

  # #call the methods that will build the json now##

  triage_state = 'new' if triage_state.nil? || triage_state.empty?
  # Convert the dates
  unless created.nil? || created.empty?
    created = DateTime.strptime(created,
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
  done = create_asset(file, url, external_id, application, tags, owner)
  puts "create assset = #{done}"
  next unless done

  ### ASSOCIATE THE ASSET TO THE VULN
  create_asset_findings(file, url, external_id, scanner_type, scanner_id, additional_fields, created, severity,
                        last_seen, triage_state, closed)

  # CREATE A VULN DEF THAT HAS THE SAME ID AS OUR VULN
  create_vuln_def(scanner_type, scanner_id, cve_id, wasc_id, cwe_id, name, description, solution)
end

kdi_output = generate_kdi_file

# puts JSON.pretty_generate kdi_output

f = File.new(@output_filename, 'w')
f.write(JSON.pretty_generate(kdi_output))
f.close
