require 'rest-client'
require 'json'
require 'csv'
require 'mail'


#These are the arguments we are expecting to get
@token = ARGV[0]
@csv_file = ARGV[1] #data file with minimum of risk meter id (col1)
@include_extra_columns = ARGV[2] #include patch_published_date and scanner_ids in output
@due_date_column = ARGV[3] #number of days ahead that should be used to set due date when email is sent now+x
@custom_field_meta = ARGV[4] #csv file with any extra columns that should be put into custom fields
@top_fix_count_column = ARGV[5] #column in the data file which says how many top fix groups to send starting with number 1
@send_email = ARGV[6] #true or false. if false no other params needed
@send_email == "true" ? @recipient_column = ARGV[7] : @recipient_column = ""
@send_email == "true" ? @mail_server = ARGV[8] : @mail_server = "" 
@send_email == "true" ? @port = ARGV[9] : @port = "" 
@send_email == "true" ? @user_name = ARGV[10] : @user_name = "" 
@send_email == "true" ? @password = ARGV[11] : @password = "" 
@send_email == "true" ? from_address = ARGV[12] : from_address = "" 


#Variables we'll need later
@base_url = 'https://api.kennasecurity.com/asset_groups/'
@fixes_url = 'https://api.kennasecurity.com/fixes/'
@vuln_url = 'https://api.kennasecurity.com/vulnerabilities/search?'
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token }
start_time = Time.now
@output_filename = "email_top_fixes_log-#{start_time.strftime("%Y%m%dT%H%M")}.txt"
@custom_field_columns = [] 
@max_retries = 2
@debug = false

def checkForDueDate(vulnids)
  puts "checking if Due Date null" if @debug
  id_array = []
  vuln_url = "#{@vuln_url}id%5B%5D="
  vuln_url = "#{vuln_url}#{vulnids.join("&id%5B%5D=")}&q=-_exists_%3Adue_date"
  begin
    vuln_return = RestClient::Request.execute(
      :method => :get,
      :url => vuln_url,
      :headers => @headers
    ) 
    vuln_json = JSON.parse(vuln_return.body)["vulnerabilities"]
    vuln_json.each do |vuln|
      id_array << vuln.fetch("id") 
    end
  rescue RestClient::TooManyRequests => e
    retry
  rescue RestClient::UnprocessableEntity => e

  rescue RestClient::BadRequest => e
    log_output = File.open(@output_filename,'a+')
    log_output << "vuln BadRequest: #{vuln_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
    log_output.close
    puts "vuln BadRequest: #{e.message}"
  rescue RestClient::Exception => e
    @retries ||= 0
    if @retries < @max_retries
      @retries += 1
      sleep(15)
      retry
    else
      log_output = File.open(@output_filename,'a+')
      log_output << "vuln General RestClient error #{vuln_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
      log_output.close
      puts "Unable to get vulns: #{e.message}"
    end
  rescue Exception => e
    log_output = File.open(@output_filename,'a+')
    log_output << "Unable to get vulns - general exception: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
    log_output.close
    puts "Unable to get vulns: #{e.backtrace.inspect}"
  end
  return id_array
end

def bulkUpdate(vulnids, newdate, cfstring)
  puts "startin bulk update" if @debug
  json_string = nil
  json_string = "{\"vulnerability_ids\": #{vulnids}, "
  json_string = "#{json_string}\"vulnerability\": {"
  if !@due_date_column.empty? then
    json_string = "#{json_string}\"due_date\": \"#{newdate}\""
    if !cfstring.empty? then
      json_string = "#{json_string}, "
    end
  end
  
  if !cfstring.empty? then
    json_string = "#{json_string}\"custom_fields\": {#{cfstring}}"
  end

  json_string = "#{json_string}}}"

  post_url = "https://api.kennasecurity.com/vulnerabilities/bulk"
  begin
    query_post_return = RestClient::Request.execute(
      :method => :put,
      :url => post_url,
      :payload => json_string,
      :headers => @headers
    )
  rescue RestClient::TooManyRequests =>e
    retry
  rescue RestClient::UnprocessableEntity => e

  rescue RestClient::BadRequest => e
    log_output = File.open(@output_filename,'a+')
    log_output << "Async BadRequest: #{post_url}...#{e.message} (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
    log_output.close
    puts "Async BadRequest: #{e.message}"
  rescue RestClient::Exception => e
    @retries ||= 0
    if @retries < @max_retries
      @retries += 1
      sleep(15)
      retry
    else
      log_output = File.open(@output_filename,'a+')
      log_output << "Async General RestClient error #{post_url}... #{e.message}(time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
      log_output.close
      puts "Async Unable to get vulns: #{e.message}"
    end
  rescue Exception => e
    log_output = File.open(@output_filename,'a+')
    log_output << "Unable to get vulns - general exception: #{e.backtrace.inspect}... (time: #{Time.now.to_s}, start time: #{start_time.to_s})\n"
    log_output.close
    puts "Unable to get vulns: #{e.backtrace.inspect}"
  end
  log_output = File.open(@output_filename,'a+')
  log_output << "bulk vuln update status: #{JSON.parse(query_post_return.body)}... time: #{Time.now.to_s}\n"
  log_output.close
end


if !@custom_field_meta.empty? then

  CSV.foreach(@custom_field_meta, :headers => true, :encoding => "UTF-8"){|row|

    @custom_field_columns << Array[row[0],row[1]]

  }
end

csv_headers = []
csv_headers << "Fix Title"
csv_headers << "Risk Meter Name"
csv_headers << "Group Number"
csv_headers << "Fix Number"
csv_headers << "Current Risk Score"
csv_headers << "Risk Score Reduction Amount"
csv_headers << "CVEs"
if @include_extra_columns == "true" then
  csv_headers << "Scanner IDs"
end
csv_headers << "Asset ID"
csv_headers << "IP Address"
csv_headers << "Operating System"
csv_headers << "Hostname"
csv_headers << "URL"
csv_headers << "Database"
csv_headers << "MAC Address"
csv_headers << "NetBIOS locator"
csv_headers << "EC2 locator"
csv_headers << "Fully Qualified Domain Name"
csv_headers << "File"
csv_headers << "Application Name"
csv_headers << "Diagnosis"
csv_headers << "Solution"
if @include_extra_columns == "true" then
  csv_headers << "Fix Published Date"
end
csv_headers << "ID"

num_lines = CSV.read(@csv_file).length
puts "Found #{num_lines} lines."

if @send_email == "true" then

  options = { :address              => "#{@mail_server}",
              :port                 => @port,
              :user_name            => "#{@user_name}",
              :password             => "#{@password}",
              :authentication       => 'plain',
              :enable_starttls_auto => true  }

  Mail.defaults do
    delivery_method :smtp, options
  end
end

## Iterate through CSV
CSV.foreach(@csv_file, :headers => true){|row|

  current_line = $.
  risk_meter_id = nil
  email_recipients = ""
  due_date = ""

  risk_meter_id = row[0]
  if @send_email == "true" then
    email_recipients = row["#{@recipient_column}"]
  end

  if !@due_date_column.empty? then
    due_date = row["#{@due_date_column}"]
  end

  custom_field_string = ""
  if !@custom_field_columns.empty? then
    @custom_field_columns.each{|item|
      row_value = row[item[0]] 
      if row_value.nil? then
        row_value = " "
      end
      custom_field_string << "\"#{item[1]}\":\"#{row_value}\","
    }
    custom_field_string = custom_field_string[0...-1]
  end

  new_date = ""
  if !@due_date_column.empty? then
    increase = row["#{@due_date_column}"]
    if increase.nil? then
      new_date = " "
    else
      new_date = DateTime.now.next_day(increase.to_i)
      new_date = new_date.strftime('%FT%TZ')
    end
    
  end
  
  max_fix_count = row["#{@top_fix_count_column}"].to_i

  report_url = "#{@base_url}#{risk_meter_id}/top_fixes"
    
    begin
    query_return = RestClient::Request.execute(
      :method => :get,
      :url => report_url,
      :headers => @headers
    ) 

    json_data = JSON.parse(query_return.body)["asset_group"]

    risk_meter_name = json_data.fetch("name").gsub('/','-').gsub(' ','_')
    current_risk_score = json_data.fetch("risk_meter_score")

    filename = "#{risk_meter_name.gsub(/\s+/,"_")}.csv"

    CSV.open(filename , 'w') do |csv|
      vulnerability_ids = []

      csv << csv_headers

      top_fix_data = json_data["top_fixes"]
      fix_count = 1
      top_fix_data.each do |fix_group|
        break if fix_count > max_fix_count
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
          if @include_extra_columns == "true" || !@due_date_column.empty? || !custom_field_meta.empty?  then
            fix_url = "#{@fixes_url}#{fix_id}"
            query_return = RestClient::Request.execute(
              :method => :get,
              :url => fix_url,
              :headers => @headers
            ) 
            fix_detail_data = JSON.parse(query_return.body)["fix"]
            if @include_extra_columns == "true" 
              patch_publication_date = fix_detail_data.fetch("patch_publication_date")
              scanner_ids = fix_detail_data.fetch("scanner_ids")
            end
            fix_vulns = fix_detail_data["vulnerabilities"]
            fix_vulns.each do |vuln|
              vulnerability_ids << vuln.fetch("id")
            end
          end
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

            row_data = []
              row_data << fix_title
              row_data << risk_meter_name
              row_data << fix_group_number
              row_data << fix_index
              row_data << current_risk_score
              row_data << fix_risk_reduction
              row_data << fix_cves.join(",")
              if @include_extra_columns == "true" then
                row_data << scanner_ids.join(" ")
              end
              row_data << asset_id
              row_data << ip_address
              row_data << os
              row_data << hostname
              row_data << url
              row_data << database
              row_data << mac
              row_data << netbios
              row_data << ec2
              row_data << fqdn
              row_data << file
              row_data << application
              row_data << fix_diagnosis
              row_data << fix_solution
              if @include_extra_columns == "true" then
                row_data << patch_publication_date
              end
              row_data << fix_id
            csv << row_data

          end
        end
        fix_count += 1
      end

      if @send_email == "true" then
        Mail.deliver do
          to "#{email_recipients}"
          from "#{from_address}"
          subject "Top Fixes Report for #{risk_meter_name}"
          body "Top Fixes Report for #{risk_meter_name} - #{DateTime.now}"
          add_file :filename => "#{filename}", :content => File.read(filename)
        end


        File.delete(filename)
      end

    if !@due_date_column.empty? || !custom_field_meta.empty? then
      id_array = []
      request_array = []
      vulnerability_ids.each do |item| 
        
        request_array << item

        if request_array.length > 450
          request_array = checkForDueDate(request_array)
          id_array.concat(request_array)
          request_array = []
        end
        if id_array.length > 1000 then
          bulkUpdate(id_array,new_date,custom_field_string)
          id_array = []
        end
      end
      puts "outside the each loop"
      request_array = checkForDueDate(request_array)
      id_array.concat(request_array) if !request_array.empty?
      bulkUpdate(id_array,new_date,custom_field_string) if !id_array.empty?
    end

   end

    rescue Exception => e  
       print "Exception occured: " + e.message + e.backtrace.inspect  
    end 

}

