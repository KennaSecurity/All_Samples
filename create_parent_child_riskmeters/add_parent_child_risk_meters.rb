require 'rest-client'
require 'json'
require 'csv'

#These are the arguments we are expecting to get
@token = ARGV[0]
@csv_file = ARGV[1]

# variables
@headers = {'content-type' => 'application/json', 'X-Risk-Token' => @token }
@base_url = 'https://api.kennasecurity.com/asset_groups'
@child_ref_hash = {}

def construct_json(display_name, rm_query)
  @json_data = {
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
end

def api_call(json_data, query_url)
  begin
    query_post_return = RestClient::Request.execute(
      method: :post,
      url: query_url,
      payload: json_data,
      headers: @headers
    )

  rescue Exception => e
      puts e.message
      puts e.backtrace.inspect
  end
end

def api_call_return_ref(child_ref)
  response = api_call(@json_data, @post_url)
  response_hash = JSON.parse(response)
  @child_ref_hash["#{child_ref}"] = response_hash["asset_group"]["id"]
end

def api_call_without_ref()
  response = api_call(@json_data, @post_url)
end

def child_ref_procedure
  @child_ref ? api_call_return_ref(@child_ref) : api_call_without_ref
end

def parent_ref_procedure()
  if @parent_ref
    @parent_id = @child_ref_hash[@parent_ref]
    @post_url = "#{@base_url}/#{@parent_id}/children"
    child_ref_procedure
  else
    @post_url = "#{@base_url}?historical=false"
    child_ref_procedure
  end
end

num_lines = CSV.read(@csv_file).length
puts "Found #{num_lines - 1} lines for processing."

## Iterate through CSV
CSV.foreach(@csv_file, :headers => true){|row|
  # "Reading line #{$.}... "
  current_line = $.

  @parent_id = row["parent_id"]
  @parent_ref = row["parent_ref"]
  @child_ref = row["child_ref"]
  @display_name = row["display_name"]
  @rm_query = row["rm_query"]

  construct_json(@display_name, @rm_query)

  if @parent_id
    @post_url = "#{@base_url}/#{@parent_id}/children"
    child_ref_procedure
  else
    parent_ref_procedure
  end
}
