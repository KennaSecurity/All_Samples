# frozen_string_literal: true

# kenna-asset-tagger
require 'rest-client'
require 'json'
require 'nokogiri'

@token = ARGV[0]
@my_user = ARGV[1]
@my_pass = ARGV[2]
@tagname = ARGV[3]

@headers = { 'X-Requested-With' => 'RestClient request' }
qualys_url = "https://qualysapi.qualys.com/api/2.0/fo/asset/host?action=list&use_tags=1&tag_set_by=name&tag_set_include=#{@tagname}"
query_response = RestClient::Request.execute(
  method: :get,
  url: qualys_url,
  headers: @headers,
  user: @my_user,
  password: @my_pass
)
@doc = Nokogiri::XML (query_response)

# puts @doc.to_s
@ipcount = @doc.xpath('.//HOST/IP').size
puts @ipcount.to_s
iploop = 1
@doc.xpath('.//HOST/IP').each do |node|
  ipaddr = node.content
  puts "found #{ipaddr} item #{iploop} of #{@ipcount}"

  @asset_api_url = 'https://api.kennasecurity.com/assets'
  @query_url = "#{@asset_api_url}/search?inactive=false&q=ip:#{ipaddr}&inactive=false"
  @headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token, 'accept' => 'application/json' }

  # puts @query_url

  query_response = RestClient::Request.execute(
    method: :get,
    url: @query_url,
    headers: @headers
  )

  meta_response_json = JSON.parse(query_response.body)['meta']
  tot_assets = meta_response_json.fetch('total_count')

  if tot_assets.positive?

    query_response_json = JSON.parse(query_response.body)['assets']
    # p query_response_json.to_s

    assetid = query_response_json[0].fetch('id')

    post_url = "#{@asset_api_url}/#{assetid}"
    # p post_url

    json_data = {
      'asset' => {
        'inactive' => 'true'
      }
    }
    # puts json_data
    begin
      query_post_return = RestClient::Request.execute(
        method: :put,
        url: post_url,
        payload: json_data,
        headers: @headers
      )
    rescue RestClient::UnprocessableEntity
    end
    puts 'item updated in Kenna'
  else
    puts 'item already inactive in Kenna'
  end
  iploop += 1
end
