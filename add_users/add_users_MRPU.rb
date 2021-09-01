# kenna-bulk-custom-field-update
require 'rest-client'
require 'json'
require 'csv'


#These are the arguments we are expecting to get - header file can be send as third parameter if not included as row 1 in csv
@token = ARGV[0]
@csv_file = ARGV[1]
#@fname_col = ARGV[2]
#@lname_col = ARGV[3]
#@roles_col = ARGV[4]
#@email_col = ARGV[5]

#Variables we'll need later
@post_url = 'https://api.kennasecurity.com/users'
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token }

num_lines = CSV.read(@csv_file).length
puts "Found #{num_lines} lines."

## Iterate through CSV
CSV.foreach(@csv_file, :headers => true){|row|
  # "Reading line #{$.}... "
  current_line = $.

  email = row[0]
  fname = row[1]
  lname = row[2]
  phone = row[3]
  roles = row[4].split(",").collect(&:strip)

  #puts roles [remove comment for troubleshooting]

  #build json payload
  json_data = JSON.generate({
    "user" =>
    {
      "firstname"=>fname,
      "lastname"=>lname,
      "email"=>email,
      "phone"=>phone,
      "roles"=>roles
        }
    }
  )

    #puts json_data [remove comment for troubleshooting]

          #builds api request and sends it to the platform
          begin
            query_post_return = RestClient::Request.execute(
              :method => :post,
              :url => @post_url,
              :payload => json_data,
              :headers => @headers
            )

          rescue Exception => e
              puts e.message
              puts e.backtrace.inspect

          end
}

puts "Complete!"
