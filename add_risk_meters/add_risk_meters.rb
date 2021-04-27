# frozen_string_literal: true

require 'rest-client'
require 'json'
require 'csv'

# These are the arguments we are expecting to get
@token = ARGV[0]
@csv_file = ARGV[1]

# Variables we'll need later
@post_url = 'https://api.kennasecurity.com/asset_groups?historical=false'
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token }

fix_string = 'fix_title_keyword%3A%28Adobe+OR+Java+OR+JBoss+OR+Apache+OR+JRE+OR+JDK+OR+Oracle+OR+JRockit+OR+IIS+OR+Tomcat+OR+%28Microsoft+AND+SQL+AND+Server%29+OR+Cygwin+OR+WebSphere+OR+PHP+OR+%28Computer+AND+Associates%29+OR+DB2+OR+Wireshark+OR+Firefox+OR+WebLogic+OR+Chrome+OR+SharePoint+OR+Silverlight+OR+%28Visual+AND+Basic%29+OR+Symantec+OR+%28Microsoft+AND+XML+AND+Editor%29+OR+Intel+OR+NetBIOS+OR+FTP+OR+SNMP+OR+SSL+OR+TLS+OR+IPMI+OR+DRAC%29+AND+-fix_title_keyword%3A%28Database+OR+jmx%29+AND-tag%3AAG_CMDB_Export_Mainframe_PROD'

num_lines = CSV.read(@csv_file).length
puts "Found #{num_lines} lines."

## Iterate through CSV
CSV.foreach(@csv_file, headers: true) do |row|
  # "Reading line #{$.}... "
  current_line = $INPUT_LINE_NUMBER
  app_name = nil

  app_name = row[0]

  json_data = {
    'asset_group' =>
      {
        'name' => "APP: #{app_name}: Actual Risk Score",
        'query' =>
          { 'status' => ['active'],
            'tags' => [app_name.to_s] }
      }
  }

  puts json_data
  begin
    query_post_return = RestClient::Request.execute(
      method: :post,
      url: @post_url,
      payload: json_data,
      headers: @headers
    )
  rescue Exception => e
    puts e.message
    puts e.backtrace.inspect
  end

  json_data = {
    'asset_group' =>
      {
        'name' => "APP: #{app_name}: Appplication Vuln(s)",
        'query' =>
          {
            'status' => ['active'],
            'tags' => [app_name.to_s],
            'vulnerability' =>
            {
              'q' => fix_string.to_s,
              'service_ticket_status' => ['none'],
              'custom_fields:7952:Deferred' => ['none']
            }
          }
      }
  }

  puts json_data
  begin
    query_post_return = RestClient::Request.execute(
      method: :post,
      url: @post_url,
      payload: json_data,
      headers: @headers
    )
  rescue Exception => e
    puts e.message
    puts e.backtrace.inspect
  end

  # json_data = {
  #   "asset_group" =>
  #     {
  #       "name" => "APP: #{app_name}: Deferred Vuln(s)",
  #       "query" =>
  #         {
  #           "status" => ["active"],
  #           "tags" => ["#{app_name}"],
  #           "vulnerability" =>
  #           {
  #             "custom_fields:7952:Deferred" => ["True","Yes"]
  #           }
  #         }
  #     }
  # }

  #       puts json_data
  #       begin
  #         query_post_return = RestClient::Request.execute(
  #           method: :post,
  #           url: @post_url,
  #           payload: json_data,
  #           headers: @headers
  #         )

  #       rescue Exception => e

  #           puts e.message
  #           puts e.backtrace.inspect

  #       end
end
