require 'json'
require 'csv'
# require 'URI'

@data_file = ARGV[0]
@has_header = ARGV[1]
@mapping_file = ARGV[2]
@skip_autoclose = ARGV[3] #defaults to false
@output_filename = ARGV[4] #json filename for converted data
# DBro - Added for ASSET ONLY Run 
ARGV.length >= 6 ? @assets_only = ARGV[5] : @assets_only = "false" #Optional TRUE/FALSE param to indicate ASSET ONLY import. Defaults to false
ARGV.length == 7 ? @domain_suffix = ARGV[6] : @domain_suffix = "" #Optional domain suffix for hostnames.

@debug = true
$map_locator = ''

@output_filename = "#{@output_filename}.json" unless @output_filename.match(/\.json$/)

#### SAUSAGE MAKING METHODS
module Kenna
module KdiHelpers


  def generate_kdi_file
    { :skip_autoclose => (@skip_autoclose.eql?('true') ? true : false), :assets => $assets.uniq, :vuln_defs => $vuln_defs.uniq }
  end

  def create_asset(file,ip_address,mac_address,hostname,ec2,netbios,url,fqdn,external_id,database,application,tags,owner,os,os_version,priority)

    tmpassets = []
    success = true

    #this case statement will check for dup assets based on the main locator as declared in the options input file
    #comment out the entire block if you want all deduplicaton to happen in Kenna

    case $map_locator
      when "ip_address"
        return success unless $assets.select{|a| a[:ip_address] == ip_address}.empty?
      when "hostname"
        return success unless $assets.select{|a| a[:hostname] == hostname}.empty?
      when "file"
        return success unless $assets.select{|a| a[:file] == file}.empty?
      when "mac_address"
        return success unless $assets.select{|a| a[:mac_address] == mac_address}.empty?
      when "netbios"
        return success unless $assets.select{|a| a[:netbios] == netbios}.empty?
      when "ec2"
        return success unless $assets.select{|a| a[:ec2] == ec2}.empty?
      when "fqdn"
        return success unless $assets.select{|a| a[:fqdn] == fqdn}.empty?
      when "external_id"
        return success unless $assets.select{|a| a[:external_id] == external_id}.empty?
      when "database"
        return success unless $assets.select{|a| a[:database] == database}.empty?
      when "url"
        return success unless $assets.select{|a| a[:url] == url}.empty?
      else
        puts "Error: main locator not provided" if @debug
        success = false

    end

    tmpassets << {:file => "#{file}"} unless file.nil? || file.empty?
    tmpassets << {:ip_address => ip_address} unless ip_address.nil? || ip_address.empty?
    tmpassets << {:mac_address => mac_address} unless mac_address.nil? || mac_address.empty?
    tmpassets << {:hostname => hostname} unless hostname.nil? || hostname.empty?
    tmpassets << {:ec2 => "#{ec2}"} unless ec2.nil? || ec2.empty?
    tmpassets << {:netbios => "#{netbios}"} unless netbios.nil? || netbios.empty?
    tmpassets << {:url => "#{url}"} unless url.nil? || url.empty?
    tmpassets << {:fqdn => "#{fqdn}"} unless fqdn.nil? || fqdn.empty?
    tmpassets << {:external_id => "#{external_id}"} unless external_id.nil? || external_id.empty?
    tmpassets << {:database => "#{database}"} unless database.nil? || database.empty?
    tmpassets << {:application => "#{application}"} unless application.nil? || application.empty?
    tmpassets << {:tags => tags} unless tags.nil? || tags.empty?
    tmpassets << {:owner => "#{owner}"} unless owner.nil? || owner.empty?
    tmpassets << {:os => "#{os}"} unless os.nil? || os.empty?
    tmpassets << {:os_version => "#{os_version}"} unless os_version.nil? || os_version.to_s.empty?
    tmpassets << {:priority => priority} unless priority.nil? || priority.to_s.empty? 
    tmpassets << {:vulns => []}

    success = false if file.to_s.empty? && ip_address.to_s.empty? && mac_address.to_s.empty? && hostname.to_s.empty? && ec2.to_s.empty? && netbios.to_s.empty? && url.to_s.empty? && database.to_s.empty? && external_id.to_s.empty? && fqdn.to_s.empty? && application.to_s.empty?


    $assets << tmpassets.reduce(&:merge) unless !success

    return success
  end

  def create_asset_vuln(hostname,ip_address,file, mac_address,netbios,url,ec2,fqdn,external_id,database,scanner_type,scanner_id,details,created,scanner_score,last_fixed,
                    last_seen,status,closed,port)

    # find the asset
    case $map_locator
      when "ip_address"
        asset = $assets.select{|a| a[:ip_address] == ip_address }.first
      when "hostname"
        asset = $assets.select{|a| a[:hostname] == hostname }.first
      when "file"
        asset = $assets.select{|a| a[:file] == file }.first
      when "mac_address"
        asset = $assets.select{|a| a[:mac_address] == mac_address }.first
      when "netbios"
        asset = $assets.select{|a| a[:netbios] == netbios }.first
      when "url"
        asset = $assets.select{|a| a[:url] == url }.first
      when "ec2"
        asset = $assets.select{|a| a[:ec2] == ec2 }.first
      when "fqdn"
        asset = $assets.select{|a| a[:fqdn] == fqdn }.first
      when "external_id"
        asset = $assets.select{|a| a[:external_id] == external_id }.first
      when "database"
        asset = $assets.select{|a| a[:database] == database }.first
      else
        "Error: main locator not provided" if @debug
    end

    puts "Unknown asset, can't associate a vuln!" unless asset
    return unless asset

    # associate the asset
    assetvulns = []
    assetvulns << {:scanner_type => "#{scanner_type}",:scanner_identifier => "#{scanner_id}",}
    assetvulns << {:details => "#{details}"} unless details.nil?
    assetvulns << {:created_at => "#{created}"} unless created.nil?
    assetvulns << {:scanner_score => scanner_score} unless scanner_score.nil? || scanner_score == 0
    assetvulns << {:last_fixed_on => "#{last_fixed}"} unless last_fixed.nil?
    assetvulns << {:last_seen_at => "#{last_seen}"} unless last_seen.nil?
    assetvulns << {:closed_at => "#{closed}"} unless closed.nil?
    assetvulns << {:port => port,} unless port.nil?
    assetvulns << {:status => "#{status}"}

    asset[:vulns] << assetvulns.reduce(&:merge)

  end

  def create_vuln_def(scanner_type,scanner_id,cve_id,wasc_id,cwe_id,name,description,solution)
    vuln_def = []
    vuln_def << {:scanner_type => "#{scanner_type}",:scanner_identifier => "#{scanner_id}",}
    vuln_def << {:cve_identifiers => "#{cve_id}"} unless cve_id.nil? || cve_id.empty?
    vuln_def << {:wasc_identifiers => "#{wasc_id}"} unless wasc_id.nil? || wasc_id.empty?
    vuln_def << {:cwe_identifiers => "#{cwe_id}"} unless cwe_id.nil? || cwe_id.empty?
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

CSV.parse(File.open(@mapping_file, 'r:iso-8859-1:utf-8'){|f| f.read}, :headers => true) do |row|

  $mapping_array << Array[row[0],row[1]]
  $mapping_array.compact

end
#headers = 
$date_format_in = "#{$mapping_array.assoc('date_format').last}" 
$map_locator = "#{$mapping_array.assoc('locator').last}"           
map_file = "#{$mapping_array.assoc('file').last}"
map_ip_address = "#{$mapping_array.assoc('ip_address').last}"                
map_mac_address = "#{$mapping_array.assoc('mac_address').last}"                   
map_hostname = "#{$mapping_array.assoc('hostname').last}"                  
map_ec2 = "#{$mapping_array.assoc('ec2').last}"                  
map_netbios = "#{$mapping_array.assoc('netbios').last}"                                
map_url = "#{$mapping_array.assoc('url').last}"                   
map_fqdn = "#{$mapping_array.assoc('fqdn').last}"             
map_external_id = "#{$mapping_array.assoc('external_id').last}"                
map_database = "#{$mapping_array.assoc('database').last}"                    
map_application = "#{$mapping_array.assoc('application').last}"                  
map_tags = "#{$mapping_array.assoc('tags').last}" 
map_tag_prefix = "#{$mapping_array.assoc('tag_prefix').last}"                 
map_owner = "#{$mapping_array.assoc('owner').last}"                 
map_os = "#{$mapping_array.assoc('os').last}"                
map_os_version = "#{$mapping_array.assoc('os_version').last}"                  
map_priority = "#{$mapping_array.assoc('priority').last}" 


if @assets_only == "false" then # DBro - Added for ASSET ONLY Run 
  map_scanner_source = "#{$mapping_array.assoc('scanner_source').last}"                   
  map_scanner_type = "#{$mapping_array.assoc('scanner_type').last}"    
  map_scanner_id = "#{$mapping_array.assoc('scanner_id').last}"
  map_scanner_id.encode!("utf-8")      
  map_details = "#{$mapping_array.assoc('details').last}"          
  map_created = "#{$mapping_array.assoc('created').last}"               
  map_scanner_score = "#{$mapping_array.assoc('scanner_score').last}"      
  map_last_fixed = "#{$mapping_array.assoc('last_fixed').last}"          
  map_last_seen = "#{$mapping_array.assoc('last_seen').last}"
  map_status = "#{$mapping_array.assoc('status').last}"             
  map_closed = "#{$mapping_array.assoc('closed').last}"               
  map_port = "#{$mapping_array.assoc('port').last}"         
  map_cve_id = "#{$mapping_array.assoc('cve_id').last}"            
  map_wasc_id = "#{$mapping_array.assoc('wasc_id').last}"            
  map_cwe_id = "#{$mapping_array.assoc('cwe_id').last}"                
  map_name = "#{$mapping_array.assoc('name').last}"              
  map_description = "#{$mapping_array.assoc('description').last}"             
  map_solution = "#{$mapping_array.assoc('solution').last}"  
  score_map_string = "#{$mapping_array.assoc('score_map').last}"
  status_map_string = "#{$mapping_array.assoc('status_map').last}"
  score_map = JSON.parse(score_map_string) unless score_map_string.nil? || score_map_string.empty?
  status_map = JSON.parse(status_map_string) unless status_map_string.nil? || status_map_string.empty?
end      # DBro - Added for ASSET ONLY Run    

# Configure Date format
###########################
# CUSTOMIZE Date format
###########################
#date_format_in = "%m/%d/%Y %H:%M"
date_format_KDI = "%Y-%m-%d-%H:%M:%S"

include Kenna::KdiHelpers

CSV.parse(File.open(@data_file, 'r:bom|utf-8'){|f| f.read}, :headers => @has_header.eql?('true') ? true : false) do |row|


  ##################
  #  CSV MAPPINGS  #
  ##################
  # Asset settings #
  ##################
    locator = row["#{$map_locator}"]     # field used to compare for dupes
    file = row["#{map_file}"]                 #(string) path to affected file
    ip_address = row["#{map_ip_address}"]                  #(string) ip_address of internal facing asset
    mac_address = row["#{map_mac_address}"]                     #(mac format-regex) MAC address asset
    hostname = row["#{map_hostname}"]                  #(string) hostname name/domain name of affected asset
    ec2 = row["#{map_ec2}"]                    #(string) Amazon EC2 instance id or name
    netbios = row["#{map_netbios}"]                 #(string) netbios name
    url = row["#{map_url}"]
    url = url.strip unless url.nil?                  #(string) URL pointing to asset
    fqdn = row["#{map_fqdn}"]              #(string) fqdn of asset
    external_id = row["#{map_external_id}"]                #(string) ExtID of asset-Often used as an int org name for asset
    database = row["#{map_database}"]                    #(string) Name of database
    application = row["#{map_application}"]                   #(string) ID/app Name

    # DBro - Added for ASSET ONLY Run 
    if @domain_suffix != "" && (@assets_only == "false" || @assets_only == false) then hostname += ".#{@domain_suffix}" end

  #########################
  # Asset Metadata fields #
  #########################
    tag_list = map_tags.split(',')   #(string) list of strings that correspond to tags on an asset
    prefix_list = map_tag_prefix.split(',')
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
    owner = row["#{map_owner}"]                 #(string) Some string that identifies an owner of an asset
    os = row["#{map_os}"]                 #(string) Operating system of asset
    os_version = row["#{map_os_version}"]                  #(string) OS version
    priority = row["#{map_priority}"].to_i   unless  row["#{map_priority}"].nil? || row["#{map_priority}"].empty? #(Integer) Def:10 - Priority of asset (int 1 to 10).Adjusts asset score.

  if @assets_only == "false" then # DBro - Added for ASSET ONLY Run 
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
      details = row["#{map_details}"]            #(string) - Details about vuln
      created = row["#{map_created}"] 
      if score_map.nil? || score_map.empty? then             #(string) - Date vuln created
        scanner_score = row["#{map_scanner_score}"].to_i  unless  row["#{map_scanner_score}"].nil? || row["#{map_scanner_score}"].empty?    #(Integer) - scanner score
      else
        scanner_score = score_map[row["#{map_scanner_score}"]].to_i  unless  row["#{map_scanner_score}"].nil? || row["#{map_scanner_score}"].empty?    #(Integer) - scanner score
      end
      last_fixed = row["#{map_last_fixed}"]            #(string) - Last fixed date
      last_seen = row["#{map_last_seen}"]
      if status_map.nil? || status_map.empty? then
        status = row["#{map_status}"]            #(string) #Rqd Def if nil; open status by default if not in import
      else
        status = status_map[row["#{map_status}"]]
      end 
      closed = row["#{map_closed}"]                #(string) Date it was closed
      port = row["#{map_port}"].to_i  unless row["#{map_port}"].nil? ||row["#{map_port}"].empty? #(Integer) Port if associated with vuln

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
  end # DBro - Added for ASSET ONLY Run 

##call the methods that will build the json now##

  status = "open" if status.nil? || status.empty?
  # Convert the dates
  created = DateTime.strptime(created,$date_format_in).strftime(date_format_KDI) unless created.nil? || created.empty?
  last_fixed = DateTime.strptime(last_fixed,$date_format_in).strftime(date_format_KDI) unless last_fixed.nil? || last_fixed.empty?

if last_seen.nil? || last_seen.empty? then
    #last_seen = "2019-03-01-14:00:00"
   last_seen = DateTime.now.strftime(date_format_KDI)
else
  last_seen = DateTime.strptime(last_seen,$date_format_in).strftime(date_format_KDI)
end

  closed = DateTime.strptime(closed,$date_format_in).strftime(date_format_KDI) unless closed.nil?


  ### CREATE THE ASSET
  done  = create_asset(file,ip_address,mac_address,hostname,ec2,netbios,url,fqdn,external_id,database,application,tags,owner,os,os_version,priority)
  #puts "create assset = #{done}"
  next if !done
  
  ### ASSOCIATE THE ASSET TO THE VULN



  if @assets_only == "false" then # DBro - Added for ASSET ONLY Run 
    create_asset_vuln(hostname,ip_address,file, mac_address,netbios,url,ec2,fqdn,external_id,database,scanner_type,scanner_id,details,created,scanner_score,last_fixed,
                    last_seen,status,closed,port)

    # CREATE A VULN DEF THAT HAS THE SAME ID AS OUR VULN
    create_vuln_def(scanner_type,scanner_id,cve_id,wasc_id,cwe_id,name,description,solution)
  end

end

kdi_output = generate_kdi_file

#puts JSON.pretty_generate kdi_output

f = File.new(@output_filename, 'w')
f.write(JSON.pretty_generate kdi_output)
f.close     

