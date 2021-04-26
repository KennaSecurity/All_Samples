# frozen_string_literal: false

require 'rest-client'
require 'json'
require 'csv'
require 'mail'
require 'date'

@token = ARGV[0]
@csv_file = ARGV[1] # that contains the risk meter ID and emails
@send_email = ARGV[2] # true or false. if false no other params needed

@csv_file_smtp = @send_email == 'true' ? ARGV[3] : ''
@recipient_column = @send_email == 'true' ? ARGV[4] : ''
from_address = @send_email == 'true' ? ARGV[9] : ''

# @send_email == 'true' ? @csv_file_smtp = ARGV[3] : @csv_file_smtp = ''
# @send_email == 'true' ? @recipient_column = ARGV[4] : @recipient_column = ''
# @send_email == 'true' ? @mail_server = ARGV[5] : @mail_server = ''
# @send_email == 'true' ? @port = ARGV[6] : @port = ''
# @send_email == 'true' ? @user_name = ARGV[7] : @user_name = ''
# @send_email == 'true' ? @password = ARGV[8] : @password = ''
# @send_email == 'true' ? from_address = ARGV[9] : from_address = ''

# In case your Kenna Instance is in US
@base_url = 'https://api.kennasecurity.com/asset_groups/'
@fixes_url = 'https://api.kennasecurity.com/fixes/'

# In case your Kenna Instance is in EU
# @base_url = 'https://api.eu.kennasecurity.com/asset_groups/'
# @fixes_url = 'https://api.eu.kennasecurity.com/fixes/'

@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token }

if @send_email == 'true'
  CSV.foreach(@csv_file_smtp, headers: true) do |row_s|
    v_mail_server = row_s[0]
    v_port = row_s[1]
    v_user_name = row_s[2]
    v_password = row_s[3]

    options = {
      address: v_mail_server.to_s,
      port: v_port,
      user_name: v_user_name.to_s,
      password: v_password.to_s,
      authentication: 'plain',
      enable_starttls_auto: true
    }

    Mail.defaults do
      delivery_method :smtp, options
    end
  end

end

csv_headers = [
  'Risk ID Number',
  'Risk Meter Name',
  'Current Risk Score'
]

todays_date = Date.today.to_s
puts "Score on #{todays_date}"

num_lines = CSV.read(@csv_file).length
puts "Found #{num_lines} lines."

# Iterate through CSV
CSV.foreach(@csv_file, headers: true) do |row|
  # current_line = $.
  risk_meter_id = nil
  email_recipients = ''
  risk_meter_name = ''

  risk_meter_id = row[0]

  email_recipients = row[@recipient_column.to_s] if @send_email == 'true'

  # Going directly to the Risk Meter History Score to get the needed information
  report_url = "#{@base_url}#{risk_meter_id}/report_query/historical_risk_meter_scores?start_date=#{todays_date}"

  puts report_url

  begin
    query_return = RestClient::Request.execute(
      method: :get,
      url: report_url,
      headers: @headers
    )

    json_data = JSON(query_return.body)

    risk_meter_name = json_data.fetch('name').gsub('/', '-').gsub(' ', '_')
    current_risk_score = json_data['risk_meter_scores']

    risk_score = current_risk_score.fetch(Date.today.to_s)

    filename = "#{risk_meter_name.gsub(/\s+/, '_')}.csv"

    CSV.open(filename, 'w') do |csv|
      csv << csv_headers

      csv << [
        risk_meter_id,
        risk_meter_name,
        risk_score
      ]
    end

    # Let's put our code in safe area
  rescue StandardError => e
    print "Exception occured: #{e.backtrace.inspect}"
  end

  # Cheking if the risk meter is greater than 0
  if risk_score.positive? && @send_email == 'true'
    Mail.deliver do
      to email_recipients.to_s
      from from_address.to_s
      subject "Critical Vulns Added to #{risk_meter_name}"
      body "A change happened to #{risk_meter_name} - on #{DateTime.now}"
      add_file filename: filename.to_s, content: File.read(filename)
    end

  end

  File.delete(filename)
end
