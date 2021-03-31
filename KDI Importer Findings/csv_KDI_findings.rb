require 'json'
require 'csv'
# require 'pry'

@data_file = ARGV[0]
@has_header = ARGV[1]
@mapping_file = ARGV[2]
@skip_autoclose = ARGV[3] #defaults to false
@output_filename = ARGV[4] #json filename for converted data

@debug = false
$map_locator = ''

@output_filename = "#{@output_filename}.json" unless @output_filename.match(/\.json$/)

#### SAUSAGE MAKING METHODS
module Kenna
module KdiHelpers


  def generate_kdi_file
    { :skip_autoclose => (@skip_autoclose.eql?('true') ? true : false), :assets => $assets.uniq, :vuln_defs => $vuln_defs.uniq }
  end

  def create_asset(file,url,external_id,application,tags,owner)

    tmpassets = []
    success = true

    #this case statement will check for dup assets based on the main locator as declared in the options input file
    #comment out the entire block if you want all deduplicaton to happen in Kenna

    case $map_locator
      when "file"
        return success unless $assets.select{|a| a[:file] == file}.empty?
      when "external_id"
        return success unless $assets.select{|a| a[:external_id] == external_id}.empty?
      when "url"
        return success unless $assets.select{|a| a[:url] == url}.empty?
      else
        puts "Error: main locator not provided" if @debug
        success = false

    end

    tmpassets << {:file => "#{file}"} unless file.nil? || file.empty?
    tmpassets << {:url => "#{url}"} unless url.nil? || url.empty?
    tmpassets << {:external_id => "#{external_id}"} unless external_id.nil? || external_id.empty?
    tmpassets << {:application => "#{application}"} unless application.nil? || application.empty?
    tmpassets << {:tags => tags} unless tags.nil? || tags.empty?
    tmpassets << {:owner => "#{owner}"} unless owner.nil? || owner.empty?
    tmpassets << {:vulns => []}
    tmpassets << {:findings => []}

    success = false if file.to_s.empty? && url.to_s.empty? && application.to_s.empty? 


    $assets << tmpassets.reduce(&:merge) unless !success

    return success
  end

  def create_asset_findings(file,url,external_id,scanner_type,scanner_id,additional_fields,created,severity,
                    last_seen,triage_state,due_date)

    # find the asset
    case $map_locator
      when "file"
        asset = $assets.select{|a| a[:file] == file }.first
      when "url"
        asset = $assets.select{|a| a[:url] == url }.first
      when "external_id"
        asset = $assets.select{|a| a[:external_id] == external_id }.first
      else
        "Error: main locator not provided" if @debug
    end

    put "Unknown asset, can't associate a vuln!" unless asset
    returm unless asset

    # associate the asset
    assetfindings = []
    assetfindings << {:scanner_type => "#{scanner_type}",:scanner_identifier => "#{scanner_id}",}
    assetfindings << {:additional_fields => additional_fields} unless additional_fields.nil?
    assetfindings << {:created_at => "#{created}"} unless created.nil?
    assetfindings << {:severity => severity} unless severity.nil? || severity == 0
    assetfindings << {:last_seen_at => "#{last_seen}"} unless last_seen.nil?
    assetfindings << {:due_date => due_date} unless due_date.nil?
    assetfindings << {:triage_state => "#{triage_state}"}

    asset[:findings] << assetfindings.reduce(&:merge)

  end

  def create_vuln_def(scanner_type,scanner_id,cve_id,wasc_id,cwe_id,name,description,solution)
    vuln_def = []
    vuln_def << {:scanner_type => "#{scanner_type}",:scanner_identifier => "#{scanner_id}",}
    vuln_def << {:cve_identifiers => "#{cve_id}"} unless cve_id.nil? || cve_id.empty?
    vuln_def << {:wasc_identifier => "#{wasc_id}"} unless wasc_id.nil? || wasc_id.empty?
    vuln_def << {:cwe_identifier => "#{cwe_id}"} unless cwe_id.nil? || cwe_id.empty?
    vuln_def << {:name => "#{name}"} unless name.nil? || name.empty?
    vuln_def << {:description => "#{description}"} unless description.nil? || description.empty?
    vuln_def << {:solution => "#{solution}"} unless solution.nil? || solution.empty?

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

CSV.parse(File.open(@mapping_file, 'r:iso-8859-1:utf-8'){|f| f.read}, :headers => true) do |row|

  $mapping_array << Array[row[0],row[1]]
  $mapping_array.compact

end
#headers = 
$date_format_in = "#{$mapping_array.assoc('date_format').last}" 
$map_locator = "#{$mapping_array.assoc('locator').last}"           
map_file = "#{$mapping_array.assoc('file').last}"             
map_url = "#{$mapping_array.assoc('url').last}"                              
map_external_id = "#{$mapping_array.assoc('external_id').last}"                                   
map_application = "#{$mapping_array.assoc('application').last}"                  
map_tags = "#{$mapping_array.assoc('tags').last}" 
map_tag_prefix = "#{$mapping_array.assoc('tag_prefix').last}"                 
map_owner = "#{$mapping_array.assoc('owner').last}"                 

# binding.pry

map_scanner_source = "#{$mapping_array.assoc('scanner_source').last}"                   
map_scanner_type = "#{$mapping_array.assoc('scanner_type').last}"    
map_scanner_id = "#{$mapping_array.assoc('scanner_id').last}"
map_scanner_id.encode!("utf-8")      
map_additional_fields = "#{$mapping_array.assoc('additional_fields').last}"          
map_created = "#{$mapping_array.assoc('created').last}"               
map_severity = "#{$mapping_array.assoc('severity').last}"               
map_last_seen = "#{$mapping_array.assoc('last_seen').last}"
map_triage_state = "#{$mapping_array.assoc('triage_state').last}"                      
map_cve_id = "#{$mapping_array.assoc('cve_id').last}"            
map_wasc_id = "#{$mapping_array.assoc('wasc_id').last}"            
map_cwe_id = "#{$mapping_array.assoc('cwe_id').last}"                
map_name = "#{$mapping_array.assoc('name').last}"              
map_description = "#{$mapping_array.assoc('description').last}"             
map_solution = "#{$mapping_array.assoc('solution').last}"  
severity_map_string = "#{$mapping_array.assoc('severity_map').last}"
triage_state_map_string = "#{$mapping_array.assoc('triage_state_map').last}"
severity_map = JSON.parse(severity_map_string) unless severity_map_string.nil? || severity_map_string.empty?
triage_state_map = JSON.parse(triage_state_map_string) unless triage_state_map_string.nil? || triage_state_map_string.empty?   
# Configure Date format
###########################
# CUSTOMIZE Date format
###########################
#date_format_in = "%m/%d/%Y %H:%M"
date_format_KDI = "%Y-%m-%d-%H:%M:%S"

include Kenna::KdiHelpers

CSV.parse(File.open(@data_file, 'r:iso-8859-1:utf-8'){|f| f.read}, :headers => @has_header.eql?('true') ? true : false) do |row|

# binding.pry

  ##################
  #  CSV MAPPINGS  #
  ##################
  # Asset settings #
  ##################
    locator = row["#{$map_locator}"]     # field used to compare for dupes
    file = row["#{map_file}"]                 #(string) path to affected file   
    url = row["#{map_url}"]                   #(string) URL pointing to asset
    external_id = row["#{map_external_id}"]                #(string) ExtID of asset-Often used as an int org name for asset
    application = row["#{map_application}"]                   #(string) ID/app Name


  #########################
  # Asset Metadata fields #
  #########################
    tag_list = map_tags.split(',')   #(string) list of strings that correspond to tags on an asset
    prefix_list = map_tag_prefix.split(',')
    additional_fields_list = map_additional_fields.split(',') if !map_additional_fields.nil?
    
    # binding.pry

    #puts tag_list
    tags = []
    count = 0
    tag_list.each do |col|
      col = col.gsub(/\A['"]+|['"]+\Z/, "")
      if !row[col].nil? && !row[col].empty? then
        if prefix_list.empty? then
          tags << "#{row[col]}"
        else
          tags << prefix_list[count] + "#{row[col]}"
        end
      end
      count+=1
    end
    tags.compact if !tags.nil? && !tags.empty?

    
    additional_fields = nil
    if !additional_fields_list.nil? && !additional_fields_list.empty? then
      additional_fields_list.each do |col|
        col = col.gsub(/\A['"]+|['"]+\Z/, "")
        if !row[col].nil? && !row[col].empty? then
          if additional_fields.nil? then
            additional_fields = {col => row[col]}
          else
            additional_fields.merge!({col => row[col]})
          end
        end
      end
    end

    additional_fields.compact if !additional_fields.nil? && !additional_fields.empty?

    owner = row["#{map_owner}"]                 #(string) Some string that identifies an owner of an asset

    #########################
    # Vulnerability Section #
    #########################
      if map_scanner_source == "static" then
        scanner_type = "#{map_scanner_type}"    #(string) - default is freeform if nil from CSV
      else
        scanner_type = row["#{map_scanner_type}"]     #(string) - default is freeform if nil from CSV
      end
      raise "no scanner type found!" unless !scanner_type.nil? && !scanner_type.empty?
      scanner_id = row["#{map_scanner_id}"]
      raise "no scanner id found!" unless !scanner_id.nil? && !scanner_id.empty?
      #additional_fields = JSON.pretty_generate(additional_fields) if !additional_fields.nil? && !additional_fields.empty?       #(string) - Details about vuln
      created = row["#{map_created}"] 
      if severity_map.nil? || severity_map.empty? then             #(string) - Date vuln created
        severity = row["#{map_severity}"].to_i  unless  row["#{map_severity}"].nil? || row["#{map_severity}"].empty?    #(Integer) - scanner severity
      else
        severity = severity_map[row["#{map_severity}"]].to_i  unless  row["#{map_severity}"].nil? || row["#{map_severity}"].empty?    #(Integer) - scanner severity
      end
      last_seen = row["#{map_last_seen}"]
      if triage_state_map.nil? || triage_state_map.empty? then
        triage_state = row["#{map_triage_state}"]            #(string) #Rqd Def if nil; open triage_state by default if not in import
      else
        triage_state = triage_state_map[row["#{map_triage_state}"]]
      end 

    ############################
    # Vulnerability Definition #
    ############################

    #in vuln section ##  scanner =
    #in vuln section ##  scanner_id =
      cve_id = row["#{map_cve_id}"]            #(string) Any CVE(s)?
      wasc_id = row["#{map_wasc_id}"]                #(string) Any WASC?
      cwe_id = row["#{map_cwe_id}"]                 #(string) Any CWE?
      name = row["#{map_name}"]               #(string) Name/title of Vuln
      description = row["#{map_description}"]             #(string) Description
      solution = row["#{map_solution}"]          #(string) Solution


##call the methods that will build the json now##

  triage_state = "new" if triage_state.nil? || triage_state.empty?
  # Convert the dates
  created = DateTime.strptime(created,$date_format_in).strftime(date_format_KDI) unless created.nil? || created.empty?

  if last_seen.nil? || last_seen.empty? then
      #last_seen = "2019-03-01-14:00:00"
     last_seen = DateTime.now.strftime(date_format_KDI)
  else
    last_seen = DateTime.strptime(last_seen,$date_format_in).strftime(date_format_KDI)
  end

  closed = DateTime.strptime(closed,$date_format_in).strftime(date_format_KDI) unless closed.nil?

  ### CREATE THE ASSET
  done  = create_asset(file,url,external_id,application,tags,owner)
  puts "create assset = #{done}"
  next if !done
  
  ### ASSOCIATE THE ASSET TO THE VULN
  create_asset_findings(file,url,external_id,scanner_type,scanner_id,additional_fields,created,severity,
                    last_seen,triage_state,closed)

  # CREATE A VULN DEF THAT HAS THE SAME ID AS OUR VULN
  create_vuln_def(scanner_type,scanner_id,cve_id,wasc_id,cwe_id,name,description,solution)

end

kdi_output = generate_kdi_file

#puts JSON.pretty_generate kdi_output

f = File.new(@output_filename, 'w')
f.write(JSON.pretty_generate kdi_output)
f.close     

