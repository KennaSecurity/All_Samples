require 'rest-client'
require 'json'
require 'csv'


#These are the arguments we are expecting to get
@token = ARGV[0]
@csv_file = ARGV[1]


#Variables we'll need later
@post_url = 'https://api.kennasecurity.com/asset_groups?historical=false'

@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token }
#fix_string = "fix_title_keyword%3A%28Adobe+OR+Java+OR+JBoss+OR+Apache+OR+JRE+OR+JDK+OR+Oracle+OR+JRockit+OR+IIS+OR+Tomcat+OR+%28Microsoft+AND+SQL+AND+Server%29+OR+Cygwin+OR+WebSphere+OR+PHP+OR+%28Computer+AND+Associates%29+OR+DB2+OR+Wireshark+OR+Firefox+OR+WebLogic+OR+Chrome+OR+SharePoint+OR+Silverlight+OR+%28Visual+AND+Basic%29+OR+Symantec+OR+%28Microsoft+AND+XML+AND+Editor%29+OR+Intel+OR+NetBIOS+OR+FTP+OR+SNMP+OR+SSL+OR+TLS+OR+IPMI+OR+DRAC%29+AND+-fix_title_keyword%3A%28Database+OR+jmx%29+AND-tag%3AAG_CMDB_Export_Mainframe_PROD"

num_lines = CSV.read(@csv_file).length
puts "Found #{num_lines} lines."

## Iterate through CSV
CSV.foreach(@csv_file, :headers => true){|row|
  # "Reading line #{$.}... "
  current_line = $.
  parent_id = nil
  display_name = nil
  rm_query = nil

  parent_id = row[0]
  display_name = row["display_name"]
  rm_query = row["rm_query"]

  json_data = {
      "asset_group" =>
        {
          "name" => "#{display_name}",
          "query" =>
            {
              "vulnerability" => 
              { 
                "q" =>  "#{rm_query}"
              }
            }     
        }
    }

    #puts "parent_id: #{parent_id}"
    #puts "is nil: #{parent_id.nil?}"

          if !parent_id.nil?
            query_url = "https://api.kennasecurity.com/asset_groups/#{parent_id}/children"
          else  
            query_url = @post_url
          end

          #puts query_url

          #puts json_data
          begin
            query_post_return = RestClient::Request.execute(
              method: :post,
              url: query_url,
              payload: json_data,
              headers: @headers
            ) 

            #print query_post_return

          rescue Exception => e

              puts e.message  
              puts e.backtrace.inspect  

          end



}
