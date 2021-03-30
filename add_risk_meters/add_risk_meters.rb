require 'rest-client'
require 'json'
require 'csv'


#These are the arguments we are expecting to get
@token = ARGV[0]
@csv_file = ARGV[1]


#Variables we'll need later
@post_url = 'https://api.kennasecurity.com/asset_groups?'
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token }

num_lines = CSV.read(@csv_file).length
puts "Found #{num_lines} lines."

## Iterate through CSV
CSV.foreach(@csv_file, :headers => true){|row|
  # "Reading line #{$.}... "
  current_line = $.
  risk_meter_name = nil
  query_string = nil

  risk_meter_name = row[0]
  query_string = row[1]

  json_data = {
      "asset_group" =>
        {
          "name" => "#{risk_meter_name}",
          "query" => 
            {
              "q" => "#{query_string}"
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

}

puts "End of rows reached. All done!"
