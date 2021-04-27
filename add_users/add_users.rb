# frozen_string_literal: true

# kenna-bulk-custom-field-update
require 'rest-client'
require 'json'
require 'csv'

# These are the arguments we are expecting to get - header file can be send as third parameter if not included as row 1 in csv
@token = ARGV[0]
@csv_file = ARGV[1]
@fname_col = ARGV[2]
@lname_col = ARGV[3]
@role_col = ARGV[4]
@email_col = ARGV[5]

# Variables we'll need later
@post_url = 'https://api.kennasecurity.com/users'
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token }

num_lines = CSV.read(@csv_file).length
puts "Found #{num_lines} lines."

## Iterate through CSV
CSV.foreach(@csv_file, headers: true) do |row|
  # "Reading line #{$.}... "
  current_line = $INPUT_LINE_NUMBER
  fname = nil
  lname = nil
  email = nil
  role = nil

  fname = row[@fname_col]
  lname = row[@lname_col]
  email = row[@email_col]
  role = row[@role_col]

  json_data = {
    'user' =>
    {
      'firstname' => fname,
      'lastname' => lname,
      'email' => email,
      'role' => role
    }
  }
  # puts json_data
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
end
