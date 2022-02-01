# Kenna Toolkit using GitHub Actions
A repo for testing Github actions with the Kenna toolkit

# Background
The Kenna Toolkit provides a way to push data into the Kenna platform through the connectors / utilities contained in it. 
This toolkit is packaged as a container which contains all the required dependencies to run these connectors. 
Due to security requirements of organizations, some Kenna customers may be unable to install additional software on their workstations, or have a server provisioned for them. 
GitHub actions present another way for customers to run toolkit tasks without these limitations.
It also provides simplicity for these tasks to be run without having to setup your own server infrastructure.

# Setup
1. Create a repository (call it any name)
2. Create a .yml file in the .github/workflows directory
3. Edit the created .yml file using the code in the sample template (toolkit.yml) provided
   * Sample template contains instructions for both on-demand (manual runs) and scheduled workflows
   * The on-demand workflow is the default. Remove comments ('#') comments on lines 3 - 5 to setup a scheduled workflow. Comment out line 8
5. Make edits to the run command for the desired connector task or utility you would like to run
6. Commit your changes
7. For the created repository, navigate to 'Settings' and locate the 'Secrets' section
8. Create relevant secret(s) for your run parameters. In the sample, a secret 'API_KEY' is created for the default task. 

Ensure security considerations are made, and your repo is not made public with your run details.

# Running the task
* Scheduled tasks will run based on the configured schedule. Please make appropriate billing considerations
* To run on-demand tasks, follow these steps: 
  * Go to the Actions tab of your repository
  * Select the configured workflow
  * Click on the 'Run Workflow' to reveal the drop down button
  * Click on the 'Run Workflow' green button.  

# Dependencies
* No software dependencies are required. 
* GitHub account to create a repository
* Authorized Kenna API token for running the connector task
