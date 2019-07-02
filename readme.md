Welcome to the Kenna Security Samples wiki!

These scripts are written to assist customers in automating common functions on the Kenna Security Platform or to integrate data not natively support via Kenna Connectors. Scripts use the fully documented and supported [Kenna Security REST API](https://api.kennasecurity.com/introduction). These scripts wrap additional logic around the API calls and are available as SAMPLES only. They are not part of the Kenna Engineering program and do not participate in a formal SDLC program. 

Most of the scripts written here are in Ruby. You can run ruby from a desktop but for scheduled jobs against your Kenna Security instance, a server space is recommended. 

* Server should be sized based on the expected data file processing size but usually those sizes are not extreme and do not require a heavy duty server. 

* The server machine should be able to make calls via https to the Kenna API (sometimes 443 access is allowed by default and sometimes firewall access from servers must be explicitly granted). 

* Many customers store the files (CMDB extracts, vuln reports) they are going to process directly on the server disk space for these files should be considered.

* If you plan on writing scripts that access other internal APIs or file directories, the machine would need access to those items. 

* For automation purposes, the server should be either part of the centralized scheduler process or have a scheduler on it that can be accessed by the team (windows server has a scheduler). 

* Finally, the machine will need access to install ruby. 
  * https://www.ruby-lang.org
  * https://rubygems.org
  * https://rubyinstaller.org (for windows)

For additional information about how you can use the Kenna API (employed in the sample scripts) to enhance/supplement your Kenna implementation, contact [Kenna Customer Success](mailto:customersuccess@kennascurity.com).

All the code samples in this GitHub repository are offered “as is” and include no warranty of any kind. Use them at your own risk. In no event will Kenna be liable to end user or any other party for damages of any kind arising from the use of these samples.
