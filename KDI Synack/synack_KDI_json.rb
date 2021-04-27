# frozen_string_literal: true

require 'json'
require 'csv'

@data_file = ARGV[0]
@skip_autoclose = ARGV[1] # defaults to false
@output_filename = ARGV[2] # json filename for converted data

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

    def create_asset(url, application)
      tmpassets = []
      success = true

      tmpassets << { url: url.to_s } unless url.nil? || url.empty?
      tmpassets << { application: application.to_s } unless application.nil? || application.empty?
      tmpassets << { vulns: [] }

      success = false if url.to_s.empty?

      $assets << tmpassets.reduce(&:merge) if success

      success
    end

    def create_asset_vuln(url, scanner_type, scanner_id, last_seen, created, scanner_score, details, closed, status)
      # find the asset
      asset = $assets.select { |a| a[:url] == url }.first
      puts "Unknown asset, can't associate a vuln!" unless asset
      return unless asset

      # associate the asset
      assetvulns = []

      assetvulns << { scanner_type: scanner_type.to_s, scanner_identifier: scanner_id.to_s }
      assetvulns << { last_seen_at: last_seen.to_s } unless last_seen.nil?
      assetvulns << { created_at: created.to_s } unless created.nil?
      assetvulns << { scanner_score: scanner_score } unless scanner_score.nil? || scanner_score.zero?
      assetvulns << { details: details.to_s } unless details.nil?
      assetvulns << { closed_at: closed.to_s } unless closed.nil?
      assetvulns << { status: status.to_s }

      asset[:vulns] << assetvulns.reduce(&:merge)
    end

    def create_vuln_def(scanner_type, scanner_id, name, description, solution)
      vuln_def = []
      vuln_def << { scanner_type: scanner_type.to_s, scanner_identifier: scanner_id.to_s }
      vuln_def << { name: name.to_s, description: description.to_s, solution: solution.to_s }

      $vuln_defs << vuln_def.reduce(&:merge)
    end
  end
end
#### END OF SAUSAGE MAKING

# Gotta have these two globals because I am lazy and it is easier
$assets = []
$vuln_defs = []
# $date_format_in = ''

# Configure Date format
###########################
# CUSTOMIZE Date format
###########################
# date_format_in = "%m/%d/%Y %H:%M"
date_format_KDI = '%Y-%m-%d-%H:%M:%S'

include Kenna::KdiHelpers

base_json = JSON.parse(File.read(@data_file))

# result = base_json["result"]

base_json.each do |item|
  ##################
  #  CSV MAPPINGS  #
  ##################
  # Asset settings #
  ##################

  # tags = []

  # tags << "product:#{ptd}" unless ptd.nil? || ptd.empty?
  # tags << "site_name:#{site}" unless site.nil? || site.empty?

  ### CREATE THE ASSET
  url = []

  #########################
  # Vulnerability Section #
  #########################
  last_seen = item.fetch('updated_at')
  scanner_id = item.fetch('id')
  name = item.fetch('title')
  description = item.fetch('description')
  solution = item.fetch('recommended_fix')
  closed = item.fetch('closed_at')
  # scanner_score = item.fetch("cve_score")
  item['exploitable_locations'].each do |el|
    url << el.fetch('value').gsub(/\s+/, '')
  end
  application = item['listing'].fetch('codename')
  scanner_type = 'Synack'
  scanner_score = item.fetch('cvss_final')

  vuln_info = item['vulnerability_status']

  created = vuln_info.fetch('created_at')
  temp_status = vuln_info.fetch('text')
  status = ''

  status = case temp_status
           when 'Risk Accepted'
             'closed'
           when 'Final Review'
             'open'
           else
             'open'
           end

  details = item.fetch('validation_steps').to_s

  ############################
  # Vulnerability Definition #
  ############################
  closed = DateTime.strptime(closed, '%Y-%m-%dT%T%:z').strftime(date_format_KDI) unless closed.nil? || closed.empty?
  unless last_seen.nil? || last_seen.empty?
    last_seen = DateTime.strptime(last_seen,
                                  '%Y-%m-%dT%T%:z').strftime(date_format_KDI)
  end
  unless created.nil? || created.empty?
    created = DateTime.strptime(created,
                                '%Y-%m-%dT%T.%LZ').strftime(date_format_KDI)
  end

  url.each do |url_asset|
    create_asset(url_asset, application)
    create_asset_vuln(url_asset, scanner_type, scanner_id, last_seen, created, scanner_score.to_i, details, closed,
                      status)
    # create_asset_vuln(url,scanner_type,scanner_id,last_seen,created,scanner_score.to_i)
    # CREATE A VULN DEF THAT HAS THE SAME ID AS OUR VULN
    create_vuln_def(scanner_type, scanner_id, name, description, solution)
  end
end

kdi_output = generate_kdi_file

# puts JSON.pretty_generate kdi_output

f = File.new(@output_filename, 'w')
f.write(JSON.pretty_generate(kdi_output))
f.close
