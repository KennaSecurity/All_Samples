require 'rest-client'
require 'optparse'
require 'json'
require 'csv'

my_parser = OptionParser.new do |parser|
  parser.banner = "\nKenna Audit Logs Parser. Usage: audit_parser.rb [options]"
  parser.on '-d', '--date=DATE', 'Narrow search to a particulate date. Format: YYYY-MM-DD'
  parser.on '-i', '--id=ID', Integer, 'Search by a given user ID; has higher priority than username'
  parser.on '-f', '--filename=FILENAME', 'Mandatory argument. Filename should be provided for reading the log file'
  parser.on '-u', '--username=USERNAME', 'Search by a given user account'
  parser.on '-k', '--kenna_object=KENNA_OBJECT', 'Kenna object to be searched. Valid Kenna objects are: ',
                  '"risk_meters", "assets", "vulns", "users", "risk_score_overides", "user_logins", "api_keys", "connectors", "exports"',
                  'Valid operations (-o flag) for each Kenna object are captured below: ',
                  'risk_meters - operations: "created", "updated", "deleted", "all"',
                  'assets - operations: this option is not applicable and will be ignored if used',
                  'vulns - operations: "human", "dynamic", and "all"',
                  'users - operations: "created", "updated", "deleted", and "all"',
                  'risk_score_overides - operations: this is not applicable and so will be ignored',
                  'connectors - operations: "created", "updated", "deleted", and "all"',
                  'user_logins - operations: this is not applicable and so will be ignored',
                  'api_keys - operations: "created", "revoked", and "all"',
                  'exports - operations: "created", "retrieved", "all", "allexports_ui", "allexports_api"'
  parser.on '-o', '--operation=OPERATION', 'Operation to search for on a Kenna object. see details above'
  parser.on '-r', '--reference_id=REFERENCE', 'A Reference value/id used (where applicable) to narrow search e.g. risk meter ID, user ID',
                  'applicable for the following kenna objects: "risk_meters", "users", "connectors", and "assets"'
  parser.on '-s', '--save', 'Save script output to a file. Useful for full automation so user is not prompted to save',
                  'By default, script provides a 10-second window for the user to save results to file.'
  parser.on '-a', '--asset_extras=', Array, "Used with Asset search. Search for an asset using it's locator",
                  "Example: netbios_locator,asset_netbios\n"
end

@options = {}
my_parser.parse!(into: @options)

## Methods used in the program
def exit_msg
  puts "**Exiting program ..!"
  puts "Good bye"
  exit(0)
end

def save_utility(header_array)
  if (@results_array.length > 0 && @options[:save])
    save_file(header_array)
  elsif @results_array.length > 0
    puts "would you like to save your results? (Y/N)"
    begin
      Timeout.timeout(10) {
        file_save = gets.chomp
        if file_save.downcase == 'y'
          save_file(header_array)
        elsif file_save.downcase == 'n'
          puts "You have selected the option to not save results"
          exit_msg
        else
          puts "You have selected an invalid option. Valid options are Y or N"
          exit_msg
        end
      }
    rescue
      puts "\nNo valid option was selected to save the file (Y or N)\n"
      exit_msg
    end
  else
    puts "\nYour query did not yield any results\n"
    exit_msg
  end
end

def save_file(header_array)
  puts "Saving file ..."
  @csv_file = "#{@options[:kenna_object]}_#{(Time.now).to_s.gsub(/\s+/,"").gsub(/:/, "")}.csv"
  csv_headers = header_array
  csv = CSV.open(@csv_file, 'w')
  csv << csv_headers
  @results_array.each do |nested_array|
    csv << nested_array
  end
  puts "Results saved in #{@csv_file}"
  exit_msg
end

def display_rm_results(my_regex)
  header_array = ["RiskMeter Name", "RiskMeter ID", "User ID", "IP Address", "User email", "Audit Action", "Change Date"]
  @results_array = []
  match_num = 0
  puts "\n%-30s %-15s %-15s %-18s %-40s %-20s %-40s" % header_array
  File.foreach(@options[:filename]) do |line|
    matches = my_regex.match(line)
    if matches
      logmatch = JSON.parse(line)
      risk_meter_name = logmatch["audit_log_event"]["details"]["name"]
      risk_meter_id = logmatch["audit_log_event"]["details"]["id"]
      changer_user_id = logmatch["audit_log_event"]["kenna_user_id"]
      changer_IP_address = logmatch["audit_log_event"]["ip_address"]
      changer_email = logmatch["audit_log_event"]["user_email"]
      audit_action = logmatch["audit_log_event"]["name"]
      date_of_change = logmatch["audit_log_event"]["occurred_at"]
      @results_array[match_num] = risk_meter_name, risk_meter_id, changer_user_id, changer_IP_address, changer_email, audit_action, date_of_change
      match_num += 1
      puts "%-30s %-15s %-15s %-18s %-40s %-20s %-40s" % [risk_meter_name, risk_meter_id, changer_user_id, changer_IP_address, changer_email, audit_action, date_of_change]
    end
  end
  puts "\n"
  save_utility(header_array)
end

def display_user_results(my_regex)
  header_array = ["Updated ID", "First Name", "Last Name", "Updated email", "IP Address", "User Email", "Audit Action", "Change Date"]
  @results_array = []
  match_num = 0
  puts "\n%-15s %-25s %-25s %-40s %-18s %-40s %-15s %-25s" % header_array
  File.foreach(@options[:filename]) do |line|
    matches = my_regex.match(line)
    if matches
      logmatch = JSON.parse(line)
      updated_user_id = logmatch["audit_log_event"]["details"]["target_user_id"]
      logmatch["audit_log_event"]["details"]["fields"] ?  updated_fname = logmatch["audit_log_event"]["details"]["fields"]["first_name"] : updated_fname = "Not Applicable"
      logmatch["audit_log_event"]["details"]["fields"] ? updated_lname = logmatch["audit_log_event"]["details"]["fields"]["last_name"] : updated_lname = "Not Applicable"
      logmatch["audit_log_event"]["details"]["fields"] ? updated_email = logmatch["audit_log_event"]["details"]["fields"]["user_email"] : updated_email = "Not Applicable"
      changer_user_id = logmatch["audit_log_event"]["kenna_user_id"]
      changer_IP_address = logmatch["audit_log_event"]["ip_address"]
      changer_email = logmatch["audit_log_event"]["user_email"]
      audit_action = logmatch["audit_log_event"]["name"]
      date_of_change = logmatch["audit_log_event"]["occurred_at"]
      @results_array[match_num] = updated_user_id,updated_fname, updated_lname, updated_email, changer_user_id, changer_IP_address, changer_email, audit_action, date_of_change
      match_num += 1
      puts "%-15s %-15s %-15s %-40s %-18s %-40s %-15s %-25s" % [updated_user_id,updated_fname, updated_lname, updated_email, changer_user_id, changer_IP_address, changer_email, audit_action, date_of_change]
    end
  end
  puts "\n"
  save_utility(header_array)
end

def display_apikey_results(my_regex)
  header_array = ["Updated ID", "Updater ID", "IP Address", "User Email", "Audit Action", "Change Date"]
  @results_array = []
  match_num = 0
  puts "\n%-15s %-15s %-18s %-40s %-20s %-40s" % header_array
  File.foreach(@options[:filename]) do |line|
    matches = my_regex.match(line)
    if matches
      logmatch = JSON.parse(line)
      updated_user_id = logmatch["audit_log_event"]["details"]["target_user_id"]
      changer_user_id = logmatch["audit_log_event"]["kenna_user_id"]
      changer_IP_address = logmatch["audit_log_event"]["ip_address"]
      changer_email = logmatch["audit_log_event"]["user_email"]
      audit_action = logmatch["audit_log_event"]["name"]
      date_of_change = logmatch["audit_log_event"]["occurred_at"]
      @results_array[match_num] = updated_user_id, changer_user_id, changer_IP_address, changer_email, audit_action, date_of_change
      match_num += 1
      puts "%-15s %-15s %-18s %-40s %-15s %-25s" % [updated_user_id, changer_user_id, changer_IP_address, changer_email, audit_action, date_of_change]
    end
  end
  puts "\n"
  save_utility(header_array)
end

def display_login_results(my_regex)
  header_array = ["User ID", "IP Address", "User Email", "Audit Action", "Login Date"]
  @results_array = []
  match_num = 0
  puts "\n%-15s %-18s %-40s %-20s %-40s" % header_array
  File.foreach(@options[:filename]) do |line|
    matches = my_regex.match(line)
    if matches
      logmatch = JSON.parse(line)
      login_user_id = logmatch["audit_log_event"]["kenna_user_id"]
      user_IP_address = logmatch["audit_log_event"]["ip_address"]
      user_email = logmatch["audit_log_event"]["user_email"]
      audit_action = logmatch["audit_log_event"]["name"]
      login_date = logmatch["audit_log_event"]["occurred_at"]
      @results_array[match_num] = [login_user_id, user_IP_address, user_email, audit_action, login_date]
      match_num += 1
      puts "\n%-15s %-18s %-40s %-20s %-40s" % [login_user_id, user_IP_address, user_email, audit_action, login_date]
    end
  end
  puts "\n"
  save_utility(header_array)
end

def display_asset_results(my_regex)
  header_array = ["Asset ID", "Inactivity Flag?", "IP Address", "MAC Address", "NetBIOS", "Application Name", "URL", "File Name", "Changer IP", "User email", "Audit Action", "Change Date"]
  @results_array = []
  match_num = 0
  puts "\n%-15s %-25s %-18s %-20s %-25s %-28s %-30s %-30s %-18s %-40s %-20s %-40s" % header_array
  File.foreach(@options[:filename]) do |line|
    matches = my_regex.match(line)
    if matches
      logmatch = JSON.parse(line)
      asset_id = logmatch["audit_log_event"]["details"]["asset_id"]
      if logmatch["audit_log_event"]["details"]["fields"]["inactive"]
        logmatch["audit_log_event"]["details"]["fields"]["inactive"] == "1" ? inactivity_flag = "Asset set to Inactive" : inactivity_flag = "Asset set to Active"
      else
        inactivity_flag = "Not Applicable"
      end
      asset_IP = logmatch["audit_log_event"]["details"]["fields"]["ip_address_locator"] || nil
      logmatch["audit_log_event"]["details"]["fields"]["mac_address_locator"] ? asset_mac = logmatch["audit_log_event"]["details"]["fields"]["mac_address_locator"] : asset_mac = nil
      logmatch["audit_log_event"]["details"]["fields"]["netbios_locator"] ? asset_netbios = logmatch["audit_log_event"]["details"]["fields"]["netbios_locator"] : asset_netbios = nil
      logmatch["audit_log_event"]["details"]["fields"]["application_locator"] ? asset_application = logmatch["audit_log_event"]["details"]["fields"]["application_locator"] : asset_application = nil
      logmatch["audit_log_event"]["details"]["fields"]["url_locator"] ? asset_URL = logmatch["audit_log_event"]["details"]["fields"]["url_locator"] : asset_URL = nil
      logmatch["audit_log_event"]["details"]["fields"]["file_locator"] ? asset_file = logmatch["audit_log_event"]["details"]["fields"]["file_locator"] : asset_file = nil
      changer_IP_address = logmatch["audit_log_event"]["ip_address"]
      changer_email = logmatch["audit_log_event"]["user_email"]
      audit_action = logmatch["audit_log_event"]["name"]
      date_of_change = logmatch["audit_log_event"]["occurred_at"]
      @results_array[match_num] = [asset_id, inactivity_flag, asset_IP, asset_mac, asset_netbios, asset_application, asset_URL, asset_file, changer_IP_address, changer_email, audit_action, date_of_change]
      match_num += 1
      puts "%-15s %-25s %-18s %-20s %-25s %-28s %-30s %-30s %-18s %-40s %-20s %-40s" % [asset_id, inactivity_flag, asset_IP, asset_mac, asset_netbios, asset_application, asset_URL, asset_file, changer_IP_address, changer_email, audit_action, date_of_change]
    end
  end
  puts "\n"
  save_utility(header_array)
end

def display_export_results(my_regex)
  header_array = ["Export User", "Export user IP", "Export user email", "Export Action", "Export Type", "Export Query", "Export Date"]
  @results_array = []
  match_num = 0
  puts "%-15s %-18s %-40s %-20s %-15s %-60s %-40s" % header_array
  File.foreach(@options[:filename]) do |line|
    matches = my_regex.match(line)
    if matches
      logmatch = JSON.parse(line)
      export_user_id = logmatch["audit_log_event"]["kenna_user_id"]
      export_user_IP = logmatch["audit_log_event"]["ip_address"]
      export_user_email = logmatch["audit_log_event"]["user_email"]
      audit_action = logmatch["audit_log_event"]["name"]
      export_query = logmatch["audit_log_event"]["details"]["query"]
      export_type = logmatch["audit_log_event"]["details"]["export_type"]
      date_of_export = logmatch["audit_log_event"]["occurred_at"]
      @results_array[match_num] = [export_user_id, export_user_IP, export_user_email, audit_action, export_type, export_query, date_of_export]
      match_num += 1
      puts "%-15s %-18s %-40s %-20s %-15s %-60s %-40s" % [export_user_id, export_user_IP, export_user_email, audit_action, export_type, export_query, date_of_export]
    end
  end
  puts "\n"
  save_utility(header_array)
end

def display_connector_results(my_regex)
  header_array = ["Connector ID", "Connector Name", "User ID", "User IP", "User email", "Audit Action", "Change Date"]
  @results_array = []
  match_num = 0
  puts "%-15s %-20s %-15s %-18s %-40s %-20s %-40s" % header_array
  File.foreach(@options[:filename]) do |line|
    matches = my_regex.match(line)
    if matches
      logmatch = JSON.parse(line)
      updated_connector_id = logmatch["audit_log_event"]["details"]["connector_id"]
      logmatch["audit_log_event"]["details"]["fields"] ? updated_connector_name = logmatch["audit_log_event"]["details"]["fields"]["name"] : updated_connector_name = logmatch["audit_log_event"]["details"]["name"]
      changer_user_id = logmatch["audit_log_event"]["kenna_user_id"]
      changer_IP_address = logmatch["audit_log_event"]["ip_address"]
      changer_email = logmatch["audit_log_event"]["user_email"]
      audit_action = logmatch["audit_log_event"]["name"]
      date_of_change = logmatch["audit_log_event"]["occurred_at"]
      @results_array[match_num] = [updated_connector_id, updated_connector_name, changer_user_id, changer_IP_address, changer_email, audit_action, date_of_change]
      match_num += 1
      puts "%-15s %-20s %-15s %-18s %-40s %-20s %-40s" % [updated_connector_id, updated_connector_name, changer_user_id, changer_IP_address, changer_email, audit_action, date_of_change]
    end
  end
  puts "\n"
  save_utility(header_array)
end

def display_vulnstat_results(my_regex)
  header_array = ["Vuln ID", "User ID", "IP Address", "User email", "Vuln Status", "Audit Action", "Change Date"]
  @results_array = []
  match_num = 0
  puts "%-20s %-15s %-18s %-40s %-20s %-20s %-40s" % header_array
  File.foreach(@options[:filename]) do |line|
    matches = my_regex.match(line)
    if matches
      logmatch = JSON.parse(line)
      vuln_id = logmatch["audit_log_event"]["details"]["vulnerability_id"]
      user_id = logmatch["audit_log_event"]["kenna_user_id"]
      user_IP = logmatch["audit_log_event"]["ip_address"]
      user_email = logmatch["audit_log_event"]["user"]
      vuln_status = logmatch["audit_log_event"]["details"]["fields"]["status"]
      audit_action = logmatch["audit_log_event"]["name"]
      change_date = logmatch["audit_log_event"]["occurred_at"]
      @results_array[match_num] = [vuln_id, user_id, user_IP, user_email, vuln_status, audit_action, change_date]
      match_num += 1
      puts "%-20s %-15s %-18s %-40s %-20s %-20s %-40s" % [vuln_id, user_id, user_IP, user_email, vuln_status, audit_action, change_date]
    end
  end
  puts "\n"
  save_utility(header_array)
end

def display_riskoveride_results(my_regex)
  header_array = ["Vuln ID", "New Score", "User ID", "IP Address", "User email", "Audit Action", "Change Date"]
  @results_array = []
  match_num = 0
  puts "%-20s %-15s %-15s %-18s %-40s %-20s %-40s" % header_array
  File.foreach(@options[:filename]) do |line|
    matches = my_regex.match(line)
    if matches
      logmatch = JSON.parse(line)
      vuln_id = logmatch["audit_log_event"]["details"]["vulnerability_id"]
      new_risk_score = logmatch["audit_log_event"]["details"]["fields"]["risk_score"]
      user_id = logmatch["audit_log_event"]["kenna_user_id"]
      user_IP = logmatch["audit_log_event"]["ip_address"]
      user_email = logmatch["audit_log_event"]["user"]
      audit_action = logmatch["audit_log_event"]["name"]
      change_date = logmatch["audit_log_event"]["occurred_at"]
      @results_array[match_num] = [vuln_id, new_risk_score, user_id, user_IP, user_email, audit_action, change_date]
      match_num += 1
      puts "%-20s %-15s %-15s %-18s %-40s %-20s %-40s" % [vuln_id, new_risk_score, user_id, user_IP, user_email, audit_action, change_date]
    end
  end
  puts "\n"
  save_utility(header_array)
end

def asset_search
  locators = ["hostname_locator", "netbios_locator", "url_locator", "ip_address_locator", "file_locator", "fqdn_locator", "mac_address_locator"]
  @options[:reference_id] ? ref_field = "#{@options[:reference_id]}" : ref_field = ""
  if @options[:asset_extras]
    unless @options[:asset_extras].length == 2 && locators.include?(@options[:asset_extras][0])
      puts "\nWrong asset parameters passed"
      puts "Search format is locator,locator_value e.g. ip_address_locator,127.0.0.1\n"
      puts "Valid locator values: hostname_locator, netbios_locator, url_locator, ip_address_locator, file_locator, fqdn_locator, mac_address_locator\n"
      abort("\nExiting Program ...")
    else
      case @options[:asset_extras][0]
      when "hostname_locator"
        asset_extra_fields = '.*fields.*hostname_locator":"' + "#{@options[:asset_extras][1]}"
      when "netbios_locator"
        asset_extra_fields = '.*fields.*"netbios_locator":"' + "#{@options[:asset_extras][1]}"
      when "url_locator"
        asset_extra_fields = '.*fields.*url_locator":"' + "#{@options[:asset_extras][1]}"
      when "file_locator"
        asset_extra_fields = '.*fields.*file_locator":"' + "#{@options[:asset_extras][1]}"
      when "fqdn_locator"
        asset_extra_fields = '.*fields.*fqdn_locator":"' + "#{@options[:asset_extras][1]}"
      when "ip_address_locator"
        asset_extra_fields = '.*fields.*ip_address_locator":"' + "#{@options[:asset_extras][1]}"
      when "mac_address_locator"
        asset_extra_fields = '.*fields.*mac_address_locator":"' + "#{@options[:asset_extras][1]}"
      else
        puts "This shouldn't be flagged. Please contact the author if this ever comes up :)"
      end
    end
  else
    asset_extra_fields = ""
  end

  if @options[:id]
    reg_assetupdated = '{"details":{"asset_id":"' + ref_field + ".*#{asset_extra_fields}.*" + '.*"kenna_user_id":' + "#{@options[:id]}.*" + '"name":"AssetUpdated"' + @ref_date
    reg_assetupdated = Regexp.new((reg_assetupdated), "i")
    display_asset_results(reg_assetupdated)
  elsif @options[:username]
    reg_assetupdated = '{"details":{"asset_id":"' + ref_field + asset_extra_fields + '.*"user_email":"' + "#{@options[:username]}.*" + '"name":"AssetUpdated"' + @ref_date
    reg_assetupdated = Regexp.new((reg_assetupdated), "i")
    display_asset_results(reg_assetupdated)
  else
    reg_assetupdated = '{"details":{"asset_id":"' + ref_field + ".*#{asset_extra_fields}.*" + '.*,"name":"AssetUpdated"' + @ref_date
    reg_assetupdated = Regexp.new((reg_assetupdated), "i")
    display_asset_results(reg_assetupdated)
  end
end

def vulns_search
  case @options[:operation]
  when "human"
    if @options[:id]
      reg_vulnstatchanges = '{"audit_log_event":{"client_id":.*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"VulnerabilityStatusChange".*{"status":.*by_human"}},"uuid":' + @ref_date
      reg_vulnstatchanges = Regexp.new((reg_vulnstatchanges), "i")
      display_vulnstat_results(reg_vulnstatchanges)
    elsif @options[:username]
      reg_vulnstatchanges = '{"audit_log_event":{"client_id":.*"user":"' + "#{@options[:username]}" + ".*" + '"name":"VulnerabilityStatusChange".*{"status":.*by_human"}},"uuid":' + @ref_date
      reg_vulnstatchanges = Regexp.new((reg_vulnstatchanges), "i")
      display_vulnstat_results(reg_vulnstatchanges)
    else
      reg_vulnstatchanges = '{"audit_log_event":{"client_id":.*,"name":"VulnerabilityStatusChange".*{"status":.*by_human"}},"uuid":' + @ref_date
      reg_vulnstatchanges = Regexp.new((reg_vulnstatchanges), "i")
      display_vulnstat_results(reg_vulnstatchanges)
    end
  when "dynamic"
    if @options[:id]
      reg_vulnstatchanges = '{"audit_log_event":{"client_id":.*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"VulnerabilityStatusChange".*{"status":"(open|closed)"}},"uuid":' + @ref_date
      reg_vulnstatchanges = Regexp.new((reg_vulnstatchanges), "i")
      display_vulnstat_results(reg_vulnstatchanges)
    elsif @options[:username]
      reg_vulnstatchanges = '{"audit_log_event":{"client_id":.*"user":"' + "#{@options[:username]}" + ".*" + '"name":"VulnerabilityStatusChange".*{"status":"(open|closed)"}},"uuid":' + @ref_date
      reg_vulnstatchanges = Regexp.new((reg_vulnstatchanges), "i")
      display_vulnstat_results(reg_vulnstatchanges)
    else
      reg_vulnstatchanges = '{"audit_log_event":{"client_id":.*,"name":"VulnerabilityStatusChange".*{"status":"(open|closed)"}},"uuid":' + @ref_date
      reg_vulnstatchanges = Regexp.new((reg_vulnstatchanges), "i")
      display_vulnstat_results(reg_vulnstatchanges)
    end
  when "all"
    if @options[:id]
      reg_vulnstatchanges = '{"audit_log_event":{"client_id":.*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"VulnerabilityStatusChange"' + @ref_date
      reg_vulnstatchanges = Regexp.new((reg_vulnstatchanges), "i")
      display_vulnstat_results(reg_vulnstatchanges)
    elsif @options[:username]
      reg_vulnstatchanges = '{"audit_log_event":{"client_id":.*"user":"' + "#{@options[:username]}" + ".*" + '"name":"VulnerabilityStatusChange"' + @ref_date
      reg_vulnstatchanges = Regexp.new((reg_vulnstatchanges), "i")
      display_vulnstat_results(reg_vulnstatchanges)
    else
      reg_vulnstatchanges = '{"audit_log_event":{"client_id":.*,"name":"VulnerabilityStatusChange"' + @ref_date
      reg_vulnstatchanges = Regexp.new((reg_vulnstatchanges), "i")
      display_vulnstat_results(reg_vulnstatchanges)
    end
  else
    puts "Wrong vuln status change search operation"
    puts "Possible values are 'human', 'dynamic', and 'all'"
    abort("Exiting program ...")
  end
end

def risk_meter_search
  @options[:reference_id] ? ref_field = '"id":' + "#{@options[:reference_id]}.*" : ref_field = ""
  case @options[:operation]
  when "created"
    if @options[:id]
      reg_rmcreated = "#{ref_field}" + '"fields":\[{"name":"saved_search".*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"RiskMeterCreated"' + @ref_date
      puts reg_rmcreated
      reg_rmcreated = Regexp.new((reg_rmcreated), "i")
      display_rm_results(reg_rmcreated)
    elsif @options[:username]
      reg_rmcreated = "#{ref_field}" + '"fields":\[{"name":"saved_search".*' + "#{@options[:username]}" + ".*" + '"name":"RiskMeterCreated"' + @ref_date
      reg_rmcreated = Regexp.new((reg_rmcreated), "i")
      display_rm_results(reg_rmcreated)
    else
      reg_rmcreated = "#{ref_field}" + '"fields":\[{"name":"saved_search".*"name":"RiskMeterCreated"' + @ref_date
      reg_rmcreated = Regexp.new((reg_rmcreated), "i")
      display_rm_results(reg_rmcreated)
    end
  when "updated"
    if @options[:id]
      reg_rmupdated = "#{ref_field}" + '"fields":\[{"name":"saved_search".*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"RiskMeterUpdated"' + @ref_date
      reg_rmupdated = Regexp.new((reg_rmupdated), "i")
      display_rm_results(reg_rmupdated)
    elsif @options[:username]
      reg_rmupdated = "#{ref_field}" + '"fields":\[{"name":"saved_search".*' + "#{@options[:username]}" + ".*" + '"name":"RiskMeterUpdated"' + @ref_date
      reg_rmupdated = Regexp.new((reg_rmupdated), "i")
      display_rm_results(reg_rmupdated)
    else
      reg_rmupdated = "#{ref_field}" + '"fields":\[{"name":"saved_search".*"name":"RiskMeterUpdated"' + @ref_date
      reg_rmupdated = Regexp.new((reg_rmupdated), "i")
      display_rm_results(reg_rmupdated)
    end
  when "deleted"
    if @options[:id]
      reg_rmdeleted = "#{ref_field}" + '"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"RiskMeterDeleted","uuid"' + @ref_date
      reg_rmdeleted = Regexp.new((reg_rmdeleted), "i")
      display_rm_results(reg_rmdeleted)
    elsif @options[:username]
      reg_rmdeleted = "#{ref_field}" + '"user_email":.*' + "#{@options[:username]}" + ".*" + '"name":"RiskMeterDeleted","uuid"' + @ref_date
      reg_rmdeleted = Regexp.new((reg_rmdeleted), "i")
      display_rm_results(reg_rmdeleted)
    else
      reg_rmdeleted = "#{ref_field}" + '"name":"RiskMeterDeleted","uuid"' + @ref_date
      reg_rmdeleted = Regexp.new((reg_rmdeleted), "i")
      display_rm_results(reg_rmdeleted)
    end
  when "all"
    if @options[:id]
      reg_rmall = "#{ref_field}" + '"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"RiskMeter(Deleted|Created|Updated)","uuid"' + @ref_date
      reg_rmall = Regexp.new((reg_rmall), "i")
      display_rm_results(reg_rmall)
    elsif @options[:username]
      reg_rmall = "#{ref_field}" + '"user_email":.*' + "#{@options[:username]}" + ".*" + '"name":"RiskMeter(Deleted|Created|Updated)","uuid"' + @ref_date
      reg_rmall = Regexp.new((reg_rmall), "i")
      display_rm_results(reg_rmall)
    else
      reg_rmall = "#{ref_field}" + '"name":"RiskMeter(Deleted|Created|Updated)","uuid"' + @ref_date
      reg_rmall = Regexp.new((reg_rmall), "i")
      display_rm_results(reg_rmall)
    end
  else
    puts "Wrong risk meter search operation"
    puts "Possible values are 'created', 'updated', 'deleted', and 'all'"
    exit_msg
  end
end

def user_update_search
  @options[:reference_id] ? ref_field = @options[:reference_id] : ref_field = "" ## added
  case @options[:operation]
  when "created"
    if @options[:id]
      reg_usercreated = '{"details":{"target_user_id":' + "#{ref_field}" + '.*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"UserCreated"' + @ref_date
      reg_usercreated = Regexp.new((reg_usercreated), "i")
      display_user_results(reg_usercreated)
    elsif @options[:username]
      reg_usercreated = '{"details":{"target_user_id":' + "#{ref_field}" + '.*"user_email":"' "#{@options[:username]}" + ".*" + '"name":"UserCreated"' + @ref_date
      reg_usercreated = Regexp.new((reg_usercreated), "i")
      display_user_results(reg_usercreated)
    else
      reg_usercreated = '{"details":{"target_user_id":' + "#{ref_field}" + '.*,"name":"UserCreated"' + @ref_date
      reg_usercreated = Regexp.new((reg_usercreated), "i")
      display_user_results(reg_usercreated)
    end
  when "updated"
    if @options[:id]
      reg_userupdated = '{"details":{"target_user_id":' + "#{ref_field}" + '.*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"UserUpdated"' + @ref_date
      reg_userupdated = Regexp.new((reg_userupdated), "i")
      display_user_results(reg_userupdated)
    elsif @options[:username]
      reg_userupdated = '{"details":{"target_user_id":' + "#{ref_field}" + '.*"user_email":"' + "#{@options[:username]}" + ".*" + '"name":"UserUpdated"' + @ref_date
      reg_userupdated = Regexp.new((reg_userupdated), "i")
      display_user_results(reg_userupdated)
    else
      reg_userupdated = '{"details":{"target_user_id":' + "#{ref_field}" + '.*,"name":"UserUpdated"' + @ref_date
      reg_userupdated = Regexp.new((reg_userupdated), "i")
      display_user_results(reg_userupdated)
    end
  when "deleted"
    if @options[:id]
      reg_userdeleted = '{"details":{"target_user_id":' + "#{ref_field}" + '.*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"UserDeleted"' + @ref_date
      reg_userdeleted = Regexp.new((reg_userdeleted), "i")
      display_user_results(reg_userdeleted)
    elsif @options[:username]
      reg_userdeleted = '{"details":{"target_user_id":' + "#{ref_field}" + '.*"user_email":"' + "#{@options[:username]}" + ".*" + '"name":"UserDeleted"' + @ref_date
      reg_userdeleted = Regexp.new((reg_userdeleted), "i")
      display_user_results(reg_userdeleted)
    else
      reg_userdeleted = '{"details":{"target_user_id":' + "#{ref_field}" + '.*,"name":"UserDeleted"' + @ref_date
      reg_userdeleted = Regexp.new((reg_userdeleted), "i")
      display_user_results(reg_userdeleted)
    end
  when "all"
    if @options[:id]
      reg_userall = '{"details":{"target_user_id":' + "#{ref_field}" + '.*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"User(Deleted|Updated|Created)"' + @ref_date
      reg_userall = Regexp.new((reg_userall), "i")
      display_user_results(reg_userall)
    elsif @options[:username]
      reg_userall = '{"details":{"target_user_id":' + "#{ref_field}" + '.*"user_email":"' + "#{@options[:username]}" + ".*" + '"name":"User(Deleted|Updated|Created)"' + @ref_date
      reg_userall = Regexp.new((reg_userall), "i")
      display_user_results(reg_userall)
    else
      reg_userall = '{"details":{"target_user_id":' + "#{ref_field}" + '.*,"name":"User(Deleted|Updated|Created)"' + @ref_date
      reg_userall = Regexp.new((reg_userall), "i")
      display_user_results(reg_userall)
    end
  else
    puts "Wrong user search operation"
    puts "Possible values are 'created', 'updated', 'deleted', and 'all'"
    exit_msg
  end
end

def api_key_searches
  case @options[:operation]
  when "created"
    if @options[:id]
      reg_apikeycreated = '{"details":{"target_user_id".*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"ApiKeyCreated"' + @ref_date
      reg_apikeycreated = Regexp.new((reg_apikeycreated), "i")
      display_apikey_results(reg_apikeycreated)
    elsif @options[:username]
      reg_apikeycreated = '{"details":{"target_user_id".*' + "#{@options[:username]}" + ".*" + '"name":"ApiKeyCreated"' + @ref_date
      reg_apikeycreated = Regexp.new((reg_apikeycreated), "i")
      display_apikey_results(reg_apikeycreated)
    else
      reg_apikeycreated = '{"details":{"target_user_id".*,"name":"ApiKeyCreated"' + @ref_date
      reg_apikeycreated = Regexp.new((reg_apikeycreated), "i")
      display_apikey_results(reg_apikeycreated)
    end
  when "revoked"
    if @options[:id]
      reg_apikeyrevoked = '{"details":{"target_user_id".*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"ApiKeyRevoked"' + @ref_date
      reg_apikeyrevoked = Regexp.new((reg_apikeyrevoked), "i")
      display_apikey_results(reg_apikeyrevoked)
    elsif @options[:username]
      reg_apikeyrevoked = '{"details":{"target_user_id".*' + "#{@options[:username]}" + ".*" + '"name":"ApiKeyRevoked"' + @ref_date
      reg_apikeyrevoked = Regexp.new((reg_apikeyrevoked), "i")
      display_apikey_results(reg_apikeyrevoked)
    else
      reg_apikeyrevoked = '{"details":{"target_user_id".*,"name":"ApiKeyRevoked"' + @ref_date
      reg_apikeyrevoked = Regexp.new((reg_apikeyrevoked), "i")
      display_apikey_results(reg_apikeyrevoked)
    end
  when "all"
    if @options[:id]
      reg_apikeyall = '{"details":{"target_user_id".*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"ApiKey(Created|Revoked)"' + @ref_date
      reg_apikeyall = Regexp.new((reg_apikeyall), "i")
      display_apikey_results(reg_apikeyall)
    elsif @options[:username]
      reg_apikeyall = '{"details":{"target_user_id".*' + "#{@options[:username]}" + ".*" + '"name":"ApiKey(Created|Revoked)"' + @ref_date
      reg_apikeyall = Regexp.new((reg_apikeyall), "i")
      display_apikey_results(reg_apikeyall)
    else
      reg_apikeyall = '{"details":{"target_user_id".*,"name":"ApiKey(Created|Revoked)"' + @ref_date
      reg_apikeyall = Regexp.new((reg_apikeyall), "i")
      display_apikey_results(reg_apikeyall)
    end
  else
    puts "Wrong API key search operation"
    puts "Possible values are 'created', 'revoked', and 'all'"
    exit_msg
  end
end

def login_searches
  if @options[:id]
    reg_userlogin = '{"details":{},"ip_address".*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"SessionCreated","uuid":' + @ref_date
    reg_userlogin = Regexp.new((reg_userlogin), "i")
    display_login_results(reg_userlogin)
  elsif @options[:username]
    puts "Options found"
    puts "Searching for all logins by a user account ..."
    reg_userlogin = '{"details":{},"ip_address".*' + "#{@options[:username]}" + ".*" + '"name":"SessionCreated","uuid":' + @ref_date
    reg_userlogin = Regexp.new((reg_userlogin), "i")
    display_login_results(reg_userlogin)
  else
    reg_userlogin = '{"details":{},"ip_address".*,"name":"SessionCreated","uuid":' + @ref_date
    reg_userlogin = Regexp.new((reg_userlogin), "i")
    display_login_results(reg_userlogin)
  end
end

def export_searches
  case @options[:operation]
  when "created"
    if @options[:id]
      reg_exportcreated = '{"details":{"query":.*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"ExportCreated"' + @ref_date
      reg_exportcreated = Regexp.new((reg_exportcreated), "i")
      display_export_results(reg_exportcreated)
    elsif @options[:username]
      reg_exportcreated = '{"details":{"query":.*user_email":"' + "#{@options[:username]}" + ".*" + '"name":"ExportCreated"' + @ref_date
      reg_exportcreated = Regexp.new((reg_exportcreated), "i")
      display_export_results(reg_exportcreated)
    else
      reg_exportcreated = '{"details":{"query":.*user_email":.*,"name":"ExportCreated"' + @ref_date
      reg_exportcreated = Regexp.new((reg_exportcreated), "i")
      display_export_results(reg_exportcreated)
    end
  when "retrieved"
    if @options[:id]
      reg_exportretrieved = '{"details":{"query":.*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"ExportRetrieved"' + @ref_date
      reg_exportretrieved = Regexp.new((reg_exportretrieved), "i")
      display_export_results(reg_exportcreated)
    elsif @options[:username]
      reg_exportretrieved = '{"details":{"query":.*user_email":"' + "#{@options[:username]}" + ".*" + '"name":"ExportRetrieved"' + @ref_date
      reg_exportretrieved = Regexp.new((reg_exportretrieved), "i")
      display_export_results(reg_exportretrieved)
    else
      reg_exportretrieved = '{"details":{"query":.*user_email":.*,"name":"ExportRetrieved"' + @ref_date
      reg_exportretrieved = Regexp.new((reg_exportretrieved), "i")
      display_export_results(reg_exportretrieved)
    end
  when "all"
    if @options[:id]
      reg_exportall = '{"details":{"query":.*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"Export(Created|Retrieved)"' + @ref_date
      reg_exportall = Regexp.new((reg_exportall), "i")
      display_export_results(reg_exportall)
    elsif @options[:username]
      reg_exportall = '{"details":{"query":.*user_email":"' + "#{@options[:username]}" + ".*" + '"name":"Export(Created|Retrieved)"' + @ref_date
      reg_exportall = Regexp.new((reg_exportall), "i")
      display_export_results(reg_exportall)
    else
      reg_exportall = '{"details":{"query":.*user_email":.*,"name":"Export(Created|Retrieved)"' + @ref_date
      reg_exportall = Regexp.new((reg_exportall), "i")
      display_export_results(reg_exportall)
    end
  when "allexports_ui"
    if @options[:id]
      reg_exportall = '{"details":{"query":.*' + '"export_format":("csv"|"gzip").*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"Export(Created|Retrieved)"' + @ref_date
      reg_exportall = Regexp.new((reg_exportall), "i")
      display_export_results(reg_exportall)
    elsif @options[:username]
      reg_exportall = '{"details":{"query":.*' + '"export_format":("csv"|"gzip").*user_email":"' + "#{@options[:username]}" + ".*" + '"name":"Export(Created|Retrieved)"' + @ref_date
      reg_exportall = Regexp.new((reg_exportall), "i")
      display_export_results(reg_exportall)
    else
      reg_exportall = '{"details":{"query":.*"export_format":("csv"|"gzip").*user_email":.*,"name":"Export(Created|Retrieved)"' + @ref_date
      reg_exportall = Regexp.new((reg_exportall), "i")
      display_export_results(reg_exportall)
    end
  when "allexports_api"
    if @options[:id]
      reg_exportall = '{"details":{"query":.*' + '"export_format":("json"|"jsonl"|"xml").*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"Export(Created|Retrieved)"' + @ref_date
      reg_exportall = Regexp.new((reg_exportall), "i")
      display_export_results(reg_exportall)
    elsif @options[:username]
      reg_exportall = '{"details":{"query":.*' + '"export_format":("json"|"jsonl"|"xml").*user_email":"' + "#{@options[:username]}" + ".*" + '"name":"Export(Created|Retrieved)"' + @ref_date
      reg_exportall = Regexp.new((reg_exportall), "i")
      display_export_results(reg_exportall)
    else
      reg_exportall = '{"details":{"query":.*"export_format":("json"|"jsonl"|"xml").*user_email":.*,"name":"Export(Created|Retrieved)"' + @ref_date
      reg_exportall = Regexp.new((reg_exportall), "i")
      display_export_results(reg_exportall)
    end
  else
    puts "Wrong user search operation"
    puts "Possible values are 'created', 'retrieved', 'all', 'allexports_ui', and allexports_api"
    exit_msg
  end
end

def connector_search
  @options[:reference_id] ? ref_field = @options[:reference_id] : ref_field = ""
  case @options[:operation]
  when "created"
    if @options[:id]
      reg_concreated = '{"details":{"connector_id":' + ref_field + '.*"kenna_user_id":' + "#{@options[:id]}.*" + '"name":"ConnectorCreated"' + @ref_date
      reg_concreated = Regexp.new((reg_concreated), "i")
      display_connector_results(reg_concreated)
    elsif @options[:username]
      reg_concreated = '{"details":{"connector_id":' + ref_field + '.*"user_email":"' + "#{@options[:username]}.*" + '"name":"ConnectorCreated"' + @ref_date
      reg_concreated = Regexp.new((reg_concreated), "i")
      display_connector_results(reg_concreated)
    else
      reg_concreated = '{"details":{"connector_id":' + ref_field + '.*name":"ConnectorCreated"' + @ref_date
      reg_concreated = Regexp.new((reg_concreated), "i")
      display_connector_results(reg_concreated)
    end
  when "updated"
    if @options[:id]
      reg_conupdated = '{"details":{"connector_id":' + ref_field + '.*"kenna_user_id":' + "#{@options[:id]}.*" + '"name":"ConnectorUpdated"' + @ref_date
      reg_conupdated = Regexp.new((reg_conupdated), "i")
      display_connector_results(reg_conupdated)
    elsif @options[:username]
      reg_conupdated = '{"details":{"connector_id":' + ref_field + '.*"user_email":"' + "#{@options[:username]}.*" + '"name":"ConnectorUpdated"' + @ref_date
      reg_conupdated = Regexp.new((reg_conupdated), "i")
      display_connector_results(reg_conupdated)
    else
      reg_conupdated = '{"details":{"connector_id":' + ref_field + '.*name":"ConnectorUpdated"' + @ref_date
      reg_conupdated = Regexp.new((reg_conupdated), "i")
      display_connector_results(reg_conupdated)
    end
  when "deleted"
    if @options[:id]
      reg_condeleted = '{"details":{"connector_id":' + ref_field + '.*"kenna_user_id":' + "#{@options[:id]}.*" + '"name":"ConnectorDeleted"' + @ref_date
      reg_condeleted = Regexp.new((reg_condeleted), "i")
      display_connector_results(reg_condeleted)
    elsif @options[:username]
      reg_condeleted = '{"details":{"connector_id":' + ref_field + '.*"user_email":"' + "#{@options[:username]}.*" + '"name":"ConnectorDeleted"' + @ref_date
      reg_condeleted = Regexp.new((reg_condeleted), "i")
      display_connector_results(reg_condeleted)
    else
      reg_condeleted = '{"details":{"connector_id":' + ref_field + '.*name":"ConnectorDeleted"' + @ref_date
      reg_condeleted = Regexp.new((reg_condeleted), "i")
      display_connector_results(reg_condeleted)
    end
  when "all"
    if @options[:id]
      reg_conall = '{"details":{"connector_id":' + ref_field + '.*"kenna_user_id":' + "#{@options[:id]}.*" + '"name":"Connector(Created|Updated|Deleted)"' + @ref_date
      reg_conall = Regexp.new((reg_conall), "i")
      display_connector_results(reg_conall)
    elsif @options[:username]
      reg_conall = '{"details":{"connector_id":' + ref_field + '.*"user_email":"' + "#{@options[:username]}.*" + '"name":"Connector(Created|Updated|Deleted)"' + @ref_date
      reg_conall = Regexp.new((reg_conall), "i")
      display_connector_results(reg_conall)
    else
      reg_conall = '{"details":{"connector_id":' + ref_field + '.*name":"Connector(Created|Updated|Deleted)"' + @ref_date
      reg_conall = Regexp.new((reg_conall), "i")
      display_connector_results(reg_conall)
    end
  else
    puts "Wrong connector search operation"
    puts "Possible values are 'created', 'updated', 'deleted', and 'all'"
    exit_msg
  end
end

def risk_score_overide_search
  if @options[:id]
    reg_riskoveride = '{"client_id".*"kenna_user_id":' + "#{@options[:id]}" + ".*" + '"name":"RiskScoreOverridden"' + @ref_date
    reg_riskoveride = Regexp.new((reg_riskoveride), "i")
    display_riskoveride_results(reg_riskoveride)
  elsif @options[:username]
    reg_riskoveride = '{"client_id".*"user":.*' + "#{@options[:username]}" + ".*" + '"name":"RiskScoreOverridden"' + @ref_date
    reg_riskoveride = Regexp.new((reg_riskoveride), "i")
    display_riskoveride_results(reg_riskoveride)
  else
    reg_riskoveride = '{"client_id":.*,"name":"RiskScoreOverridden"' + @ref_date
    reg_riskoveride = Regexp.new((reg_riskoveride), "i")
    display_riskoveride_results(reg_riskoveride)
  end
end

if @options.empty?
  abort(my_parser.help)
end

if @options[:filename].nil?
  puts "Filename parameter (-f) is a mandatory argument"
  exit_msg
end

abort("\n**The file doesn't exist. Please check the file and try again\n") unless File.exists?(@options[:filename])

# Check if a date was provided
@options[:date] ? @ref_date = '.*"occurred_at":"' + @options[:date] : @ref_date = ""

case @options[:kenna_object]
when "risk_meters"
  risk_meter_search
when "assets"
  asset_search
  # test_asset_search
when "vulns"
  vulns_search
when "users"
  user_update_search
when "risk_score_overides"
  risk_score_overide_search
when "connectors"
  connector_search
when "user_logins"
  login_searches
when "api_keys"
  api_key_searches
when "exports"
  export_searches
else
  puts "Error: Incorrect kenna object indicated"
  puts "Possible search options:"
  puts "  risk_meters"
  puts "  assets"
  puts "  vulns"
  puts "  users"
  puts "  risk_score_overides"
  puts "  connectors"
  puts "  api_keys"
  puts "  exports"
  exit_msg
end
