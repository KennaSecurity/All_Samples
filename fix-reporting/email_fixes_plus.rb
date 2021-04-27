# frozen_string_literal: true

require 'rest-client'
require 'json'
require 'csv'
require 'mail'

# These are the arguments we are expecting to get
@token = ARGV[0]
@csv_file = ARGV[1]
@send_email = ARGV[2] # true or false. if false no other params needed
@mail_server = @send_email == 'true' ? ARGV[3] : ''
@port = @send_email == 'true' ? ARGV[4] : ''
@user_name = @send_email == 'true' ? ARGV[5] : ''
@password = @send_email == 'true' ? ARGV[6] : ''
from_address = @send_email == 'true' ? ARGV[7] : ''

# Variables we'll need later
@base_url = 'https://api.kennasecurity.com/asset_groups/'
@fixes_url = 'https://api.kennasecurity.com/fixes/'
@headers = { 'content-type' => 'application/json', 'X-Risk-Token' => @token }

csv_headers =
  [
    'Fix Title',
    'URL',
    'CVEs',
    'IP Address',
    'Hostname',
    'URL Locator',
    'Database',
    'MAC Address',
    'NetBIOS',
    'EC2',
    'Fully Qualified Domain Name',
    'File',
    'Application Name',
    'Diagnosis',
    'Solution',
    'ID',
    'Operating System',
    'Fix Published Date',
    'Scanner IDs'
  ]

num_lines = CSV.read(@csv_file).length
puts "Found #{num_lines} lines."

options = { address: @mail_server.to_s,
            port: @port,
            user_name: @user_name.to_s,
            password: @password.to_s,
            authentication: 'plain',
            enable_starttls_auto: true }

Mail.defaults do
  delivery_method :smtp, options
end

## Iterate through CSV
CSV.foreach(@csv_file, headers: true) do |row|
  current_line = $INPUT_LINE_NUMBER
  risk_meter_id = nil
  email_recipients = nil

  risk_meter_id = row[0]
  risk_meter_name = row[1]
  email_recipients = row[2]

  # report_url = "#{@base_url}#{risk_meter_id}/top_fixes"
  report_url = "https://api.kennasecurity.com/fixes/search?search_id=#{risk_meter_id}"

  # puts report_url

  begin
    query_return = RestClient::Request.execute(
      method: :get,
      url: report_url,
      headers: @headers
    )

    json_data = JSON.parse(query_return.body)['fixes']

    filename = "fixes#{Time.now}.csv"

    CSV.open(filename, 'w') do |csv|
      csv << csv_headers

      json_data.each do |fix|
        ip_address = nil
        os = nil
        hostname = nil
        netbios = nil
        url_locator = nil
        database = nil
        mac = nil
        ec2 = nil
        fqdn = nil
        file = nil
        application = nil

        fix_title = fix.fetch('title')
        fix_url = fix.fetch('url')
        fix_diagnosis = fix.fetch('diagnosis')
        fix_consequence = fix.fetch('consequence')
        fix_solution = fix.fetch('solution')
        fix_id = fix.fetch('id')
        fix_assets = fix['assets']
        scanner_ids = fix.fetch('scanner_ids')
        fix_cves = fix.fetch('cves')
        patch_publication_date = fix.fetch('patch_publication_date')
        asset_ids = []
        fix_assets.each do |asset|
          asset_ids << asset.fetch('id')
        end
        asset_meta = []
        asset_url = "https://api.kennasecurity.com/assets/search?status\%5B\%5D=active&id\%5B\%5D=#{asset_ids.join("&id\%5B\%5D=")}"
        asset_return = RestClient::Request.execute(
          method: :get,
          url: asset_url,
          headers: @headers
        )
        assets_return_meta = JSON.parse(asset_return.body)['meta']
        pages = assets_return_meta.fetch('pages')
        endloop = pages + 1
        (1...endloop).step(1) do |i|
          puts "paging url = #{query_url}&page=#{i}" if @debug

          asset_return = RestClient::Request.execute(
            method: :get,
            url: "#{asset_url}&page=#{i}",
            headers: @headers
          )

          asset_json = JSON.parse(asset_return.body)['assets']
          puts asset_json
          asset_json.each do |asset|
            ip_address = if asset.fetch('ip_address').nil?
                           ''
                         else
                           asset.fetch('ip_address')
                         end
            os = if asset.fetch('operating_system').nil?
                   ''
                 else
                   asset.fetch('operating_system')
                 end
            hostname = if asset.fetch('hostname').nil?
                         ''
                       else
                         asset.fetch('hostname')
                       end
            url_locator = if asset.fetch('url').nil?
                            ''
                          else
                            asset.fetch('url')
                          end
            database = if asset.fetch('database').nil?
                         ''
                       else
                         asset.fetch('database')
                       end
            mac = if asset.fetch('mac_address').nil?
                    ''
                  else
                    asset.fetch('mac_address')
                  end
            netbios = if asset.fetch('netbios').nil?
                        ''
                      else
                        asset.fetch('netbios')
                      end
            ec2 = if asset.fetch('ec2').nil?
                    ''
                  else
                    asset.fetch('ec2')
                  end
            fqdn = if asset.fetch('fqdn').nil?
                     ''
                   else
                     asset.fetch('fqdn')
                   end
            file = if asset.fetch('file').nil?
                     ''
                   else
                     asset.fetch('file')
                   end
            application = if asset.fetch('application').nil?
                            ''
                          else
                            asset.fetch('application')
                          end
          end
        end
        csv << [fix_title,
                fix_url,
                fix_cves.join(','),
                ip_address,
                hostname,
                url_locator,
                database,
                mac,
                netbios,
                ec2,
                fqdn,
                file,
                application,
                fix_diagnosis,
                fix_solution,
                fix_id,
                os,
                patch_publication_date,
                scanner_ids.join(' ')]
      end

      if @send_email == 'true'
        Mail.deliver do
          to email_recipients.to_s
          from from_address.to_s
          subject "Fixes Report for #{risk_meter_name}"
          body "Fixes Report for #{risk_meter_name} - #{DateTime.now}"
          add_file filename: filename.to_s, content: File.read(filename)
        end

        File.delete(filename)
      end
    end

    # Let's put our code in safe area
  rescue Exception => e
    print "Exception occured: #{e.message}#{e.backtrace.inspect}"
  end
end
