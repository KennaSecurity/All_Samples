require 'rest-client'
require 'json'
require 'csv'
require 'mail'


#These are the arguments we are expecting to get
@token = ARGV[0]
@csv_file = ARGV[1]
@send_email = ARGV[2] #true or false. if false no other params needed
@send_email == "true" ? @mail_server = ARGV[3] : @mail_server = "" 
@send_email == "true" ? @port = ARGV[4] : @port = "" 
@send_email == "true" ? @user_name = ARGV[5] : @user_name = "" 
@send_email == "true" ? @password = ARGV[6] : @password = "" 
@send_email == "true" ? from_address = ARGV[7] : from_address = "" 

#Variables we'll need later
@base_url = 'https://api.kennasecurity.com/asset_groups/'
@fixes_url = 'https://api.kennasecurity.com/fixes/'
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token }

csv_headers = 
      [
        "Fix Title",
        "URL",
        "CVEs",
        "IP Address",
        "Hostname",
        "URL Locator",
        "Database",
        "MAC Address",
        "NetBIOS",
        "EC2",
        "Fully Qualified Domain Name",
        "File",
        "Application Name",
        "Diagnosis",
        "Solution",
        "ID",
        "Operating System",
        "Fix Published Date",
        "Scanner IDs"
      ]


num_lines = CSV.read(@csv_file).length
puts "Found #{num_lines} lines."

options = { :address              => "#{@mail_server}",
            :port                 => @port,
            :user_name            => "#{@user_name}",
            :password             => "#{@password}",
            :authentication       => 'plain',
            :enable_starttls_auto => true  }

Mail.defaults do
  delivery_method :smtp, options
end

## Iterate through CSV
CSV.foreach(@csv_file, :headers => true){|row|

  current_line = $.
  risk_meter_id = nil
  email_recipients = nil

  risk_meter_id = row[0]
  risk_meter_name = row[1]
  email_recipients = row[2]

  #report_url = "#{@base_url}#{risk_meter_id}/top_fixes"
  report_url = "https://api.kennasecurity.com/fixes/search?search_id=#{risk_meter_id}"

  #puts report_url
    
    begin
    query_return = RestClient::Request.execute(
      method: :get,
      url: report_url,
      headers: @headers
    ) 

    json_data = JSON.parse(query_return.body)["fixes"]

    filename = "fixes#{Time.now}.csv"

    CSV.open(filename , 'w') do |csv|
    csv << csv_headers

      json_data.each do |fix|
        fix_title = fix.fetch("title")
        fix_url = fix.fetch("url")
        fix_diagnosis = fix.fetch("diagnosis")
        fix_consequence = fix.fetch("consequence")
        fix_solution = fix.fetch("solution")
        fix_id = fix.fetch("id")
        fix_assets = fix["assets"]
        scanner_ids = fix.fetch("scanner_ids")
        fix_cves = fix.fetch("cves")
        patch_publication_date = fix.fetch("patch_publication_date")
        asset_ids = Array.new 
        fix_assets.each do |asset|
          asset_ids  << asset.fetch("id")
        end
        asset_meta = Array.new
        asset_url = "https://api.kennasecurity.com/assets/search?status\%5B\%5D=active&id\%5B\%5D=#{asset_ids.join("&id\%5B\%5D=")}"
        asset_return = RestClient::Request.execute(
          method: :get,
          url: asset_url,
          headers: @headers
        )
        assets_return_meta = JSON.parse(asset_return.body)["meta"]
        pages = assets_return_meta.fetch("pages")
        endloop = pages + 1
        (1...endloop).step(1) do |i|
          puts "paging url = #{query_url}&page=#{i}" if @debug

          asset_return = RestClient::Request.execute(
            method: :get,
            url: "#{asset_url}&page=#{i}",
            headers: @headers
          )
        
          asset_json = JSON.parse(asset_return.body)["assets"]
          asset_json.each do |asset|
            if asset.fetch("ip_address").nil? then
              ip_address = ''
            else
              ip_address = asset.fetch("ip_address")
            end
            if asset.fetch("operating_system").nil? then
              os = ''
            else
              os = asset.fetch("operating_system")
            end
            if asset.fetch("hostname").nil? then
              hostname = ''
            else
              hostname = asset.fetch("hostname")
            end
            if asset.fetch("url").nil? then
              url_locator = ''
            else
              url_locator = asset.fetch("url")
            end
            if asset.fetch("database").nil? then
              database = ''
            else
              database = asset.fetch("database")
            end
            if asset.fetch("mac_address").nil? then
              mac = ''
            else
              mac = asset.fetch("mac_address")
            end
            if asset.fetch("netbios").nil? then
              netbios = ''
            else
              netbios = asset.fetch("netbios")
            end
            if asset.fetch("ec2").nil? then
              ec2 = ''
            else
              ec2 = asset.fetch("ec2")
            end
            if asset.fetch("fqdn").nil? then
              fqdn = ''
            else
              fqdn = asset.fetch("fqdn")
            end
            if asset.fetch("file").nil? then
              file = ''
            else
              file = asset.fetch("file")
            end
            if asset.fetch("application").nil? then
              application = '' 
            else
              application = asset.fetch("application")
            end
            csv << [fix_title,
              fix_url,
              fix_cves.join(","),
              ip_address,
              hostname,
              url_locator,
              database,
              mac,
              netbios,
              ec2,
              fqdn,
              file,
              application,
              fix_diagnosis,
              fix_solution,
              fix_id,
              os,
              patch_publication_date,
              scanner_ids.join(" ")]
         end
        end  
      end

      if @send_email == "true"
        Mail.deliver do
          to "#{email_recipients}"
          from "#{from_address}"
          subject "Fixes Report for #{risk_meter_name}"
          body "Fixes Report for #{risk_meter_name} - #{DateTime.now}"
          add_file :filename => "#{filename}", :content => File.read(filename)
        end


        File.delete(filename)
      end

   end

  # Let's put our code in safe area
    rescue Exception => e  
       print "Exception occured: " + e.message + e.backtrace.inspect  
    end 

}

