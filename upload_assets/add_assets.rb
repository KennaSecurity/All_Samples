# kenna-bulk-custom-field-update
require 'rest-client'
require 'json'
require 'csv'


#These are the arguments we are expecting to get - header file can be send as third parameter if not included as row 1 in csv
@token = ARGV[0]
@primary_locator = ARGV[1]
@csv_file = ARGV[2]
ARGV.length == 4 ? @tag_column_file = ARGV[3] : @tag_column_file = nil


#Variables we'll need later
@post_url = 'https://api.kennasecurity.com/assets'
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token }

tag_columns = []


# Encoding characters
enc_colon = "%3A"
enc_dblquote = "%22"
enc_space = "%20"

## Set columns to use for tagging, if a @tag_column_file is provided

tag_columns = File.readlines(@tag_column_file).map{|line| line.strip}.uniq.reject(&:empty?) if !@tag_column_file.nil?
num_lines = CSV.read(@csv_file).length
puts "Found #{num_lines} lines."

## Iterate through CSV
CSV.foreach(@csv_file, :headers => true){|row|
  # "Reading line #{$.}... "
  current_line = $.
  ip_address = nil
  hostname = nil
  url = nil
  mac_address = nil
  database = nil
  netbios = nil
  fqdn = nil
  file_name = nil
  application_name = nil

  #your csv column names should match these if you don't want to change the script
  next if row['ip_address'].nil?
  ip_address = row['ip_address']
  hostname = row['hostname']
  url = row['url']
  mac_address = row['mac_address']
  database = row['database']
  netbios = row['netbios']
  fqdn = row['fqdn']
  file_name = row['file']
  application_name = row['application']

    
          puts "#{ip_address}"
          json_data = {
            'asset' => {
              'primary_locator' => "#{@primary_locator}",
              'ip_address' => "#{ip_address}",
              'hostname' => "#{hostname}",
              'database' => "#{database}",
              'url' => "#{url}",
              'mac_address' => "#{mac_address}",
              'netbios' => "#{netbios}",
              'fqdn' => "#{fqdn}",
              'file' => "#{file_name}",
              'application' => "#{application_name}"
            }
          }
          #puts json_data
          begin
            query_post_return = RestClient::Request.execute(
              method: :post,
              url: @post_url,
              payload: json_data,
              headers: @headers
            )
          rescue RestClient::UnprocessableEntity 

            puts "#{query_post_return}"

          rescue RestClient::BadRequest
            
            puts "Unable to add....Primary Locator data missing for this item."  

          end
}

