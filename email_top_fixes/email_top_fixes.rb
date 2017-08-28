require 'rest-client'
require 'json'
require 'csv'
require 'mail'


#These are the arguments we are expecting to get
@token = ARGV[0]
@csv_file = ARGV[1]
@mail_server = ARGV[2]
@port = ARGV[3]
@user_name = ARGV[4]
@password = ARGV[5]
from_address = ARGV[6]


#Variables we'll need later
@base_url = 'https://api.kennasecurity.com/asset_groups/'
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token }

csv_headers = 
      [
        "Fix Title",
        "Risk Meter Name",
        "Group Number",
        "Fix Number",
        "Current Risk Score",
        "Risk Score Reduction Amount",
        "CVEs",
        "Asset ID",
        "IP Address",
        "Operating System",
        "Hostname",
        "URL",
        "Database",
        "MAC Address",
        "NetBIOS locator",
        "EC2 locator",
        "Fully Qualified Domain Name",
        "File",
        "Application Name",
        "Diagnosis",
        "Solution",
        "ID"
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
  email_recipients = row[1]

  report_url = "#{@base_url}#{risk_meter_id}/top_fixes"

  puts report_url
    
    begin
    query_return = RestClient::Request.execute(
      method: :get,
      url: report_url,
      headers: @headers
    ) 

    json_data = JSON.parse(query_return.body)["asset_group"]

    risk_meter_name = json_data.fetch("name").gsub('/','-').gsub(' ','_')
    current_risk_score = json_data.fetch("risk_meter_score")

    filename = "#{risk_meter_name.gsub(/\s+/,"_")}.csv"
    puts filename

    CSV.open(filename , 'w') do |csv|
    csv << csv_headers

      top_fix_data = json_data["top_fixes"]

      top_fix_data.each do |fix_group|
        fix_group_number = fix_group.fetch("fix_group_number")
        fix_risk_reduction = fix_group.fetch("risk_score_reduction")
        fixes_data = fix_group["fixes"]
        fix_index = 0
        fixes_data.each do |fix|
          fix_title = fix.fetch("title")
          fix_id = fix.fetch("id")
          fix_index += 1
          fix_cves = fix.fetch("cves")
          fix_diagnosis = fix.fetch("diagnosis")
          fix_solution = fix.fetch("solution")
          fix_assets = fix["assets"]
          fix_assets.each do |asset|
            asset_id = asset.fetch("id")
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
              url = ''
            else
              url = asset.fetch("url")
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
                    risk_meter_name,
                    fix_group_number,
                    fix_index,
                    current_risk_score,
                    fix_risk_reduction,
                    fix_cves.join(","),
                    asset_id,
                    ip_address,
                    os,
                    hostname,
                    url,
                    database,
                    mac,
                    netbios,
                    ec2,
                    fqdn,
                    file,
                    application,
                    fix_diagnosis,
                    fix_solution,
                    fix_id]

          end
        end
      end

      puts "after the csv file generation"
      puts from_address

      Mail.deliver do
        to "#{email_recipients}"
        from "#{from_address}"
        subject "Top Fixes Report for #{risk_meter_name}"
        body "Top Fixes Report for #{risk_meter_name} - #{DateTime.now}"
        add_file :filename => "#{filename}", :content => File.read(filename)
      end


     File.delete(filename)

   end

  # Let's put our code in safe area
    rescue Exception => e  
       print "Exception occured: " + e.backtrace.inspect  
    end 

}

