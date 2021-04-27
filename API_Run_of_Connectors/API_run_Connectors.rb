# frozen_string_literal: true

# kenna run connectors
require 'rest-client'
require 'json'

@token = ARGV[0]

@conn_api_url = 'https://api.kennasecurity.com/connectors'
@run_postfix = '/run'
@headers = { 'X-Risk-Token' => @token }

# puts "query url = #{query_url}"

query_response = RestClient::Request.execute(
  method: :get,
  url: @conn_api_url,
  headers: @headers
)

query_response_json = JSON.parse(query_response.body)['connectors']

query_response_json.each do |item|
  conn_id = item['id']

  post_url = "#{@conn_api_url}/#{conn_id}#{@run_postfix}"
  p post_url

  query_post_return = RestClient::Request.execute(
    method: :get,
    url: post_url,
    headers: @headers
  )
  success = JSON.parse(query_post_return.body)
  puts success.fetch('success')
end
