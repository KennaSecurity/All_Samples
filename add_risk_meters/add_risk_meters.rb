require 'rest-client'
require 'json'
require 'csv'


#These are the arguments we are expecting to get
@token = ARGV[0]
@csv_file = ARGV[1]


#Variables we'll need later
@post_url = 'https://api.kennasecurity.com/asset_groups'
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token }

num_lines = CSV.read(@csv_file).length
puts "Found #{num_lines} lines."

## Iterate through CSV
CSV.foreach(@csv_file, :headers => true){|row|
  # "Reading line #{$.}... "
  current_line = $.
  country_code = nil
  tags = nil

  country_code = row["country_code"].strip.gsub(/\A\p{Space}*|\p{Space}*\z/, '')
  tags = row["tags"].strip.gsub(/\A\p{Space}*|\p{Space}*\z/, '')


  json_data = {
      "asset_group" =>
        {
          "name" => "Mem Firm - #{country_code} Total Assets",
          "query" => 
            {"status" => "active",
             "tags" => tags
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

    json_data = {
      "asset_group" =>
        {
          "name" => "Mem Firm - #{country_code} High Risk",
          "query" => 
            {
              "status" => "active",
              "tags" => tags,
              "vulnerability" =>
              { 
                "q" => "vulnerability_score:>66"
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

          json_data = {
      "asset_group" =>
        {
          "name" => "Mem Firm - #{country_code} Past Due",
          "query" => 
            {
              "status" => "active",
              "tags" => tags,
              "vulnerability" =>
              { 
                "q" => "due_date:<now"
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
}

