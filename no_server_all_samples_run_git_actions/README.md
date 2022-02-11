# Kenna All_Sample scripts using GitHub Actions
A different approach to running Ruby scripts without installing it on your environment.

## Backgroup
Knowing how difficult it is sometimes to get approval to run Ruby on our customer's environment, we tried to find a way that our customers could use the scripts that Kenna provides without the need to install Ruby.
The process discussed on this document will use the GitHub Actions to run almost any script that is under the Kenna All_Samples repository

## Setup
1. Create a GitHub account in case you do not have one
2. Create a new [repository](https://docs.github.com/en/get-started/quickstart/create-a-repo):
   - There is a plus (+) sign at the top right corner. Click on that and select "New Repository"
   - Select the "Owner" (normally you), and git it a "Name"
     - We recommend keeping the repository "private," so no one else can see or run your GitHub Actions
     - Select "Add a README file" under the "Initialize this repository with"
     - Click on "Create repository"
       - Your new repository should be now created
       - If you want, you can click on the pencil icon in the "README.md" box to edit your readme file.
3. Create a new folder called .github/workflows and inside of it a file called AllSamples_AssetTagger.yml (The file could have any other name. You will need to create a different .yml file for each script that you want to run.)
   - On your root repository, click on "Add file" and then "Create new file"
   - The first thing to do is to give the file a name. This is the moment that you can create the above needed folder as well
   - In the "Name your file" field, type: .github/workflows/AllSamples_AssetTagger.yml
     - You will notice that a folder structure was created
   - In the "Edit new file" box add the following (or you could use the .yml file in this folder as an example)

     ```
     # Name of the GitHub Action
     name: AllSample_AssetTagger
     # When the command will run (there are different options that you can use)
     on: workflow_dispatch
     # Here is another option for the "on" statment
     #  schedule:
     #    - cron: "45 5 * * *"  
     jobs:
       # Name of the job that you will be able to select and manually run
       AllSample_AssetTagger_Job:
         # Server that you are running the action, there are other options that you can choose from
         runs-on: ubuntu-latest
         env:
           # You need to configure your secrets and then you could use it here
           API_TOKEN: ${{ secrets.API_KEY }}
         steps:
           - uses: actions/checkout@v2
           - name: Set up Ruby
             uses: ruby/setup-ruby@477b21f02be01bcb8030d50f37cfec92bfa615b6
             with:
               # Ruby version, you can change the version as well
               ruby-version: 2.7.3
           # Installing all the needed gems to run the script. Depending of the script you are running you might need to add or remove some of these gems
           - name: Install dependencies
             run: |
               gem install rest-client
               gem install json
               gem install tempfile
               gem install fileutils
           - name: List files in the repository
             run: |
               ls ${{ github.workspace }}
               ls -la
           # Command to run the script (the files and scripts that you will run must be on your repository)
           # As you can see, there are some files that I need to read. All of them must be on your own repository and must be referenced here.
           - run: ruby ./Asset_Tagger/asset_tagger.rb $API_TOKEN ./Asset_Tagger/SampleTest.csv ./Asset_Tagger/MetaFile.csv hostname
     ```
   - The above file is only a sample file. You will need to configure it depending on what you want to run
   - The script that you want to run, and all the needed files to run that script, must be on your repository (like the structure that you see here in this folder)
   - Commit your changes
4. Create your secrets:
   - Under your repository, select "Settings." It is right besides "Insights" and "Security"
   - Now, at the left side of the screen, select "Secrets" and then "Actions"
   - Create your own repository secret
   - The secrets name here must be API_KEY (you can change the name, but if you do, you will need to change that in the above script as well)
     - Create relevant secret(s) for your run parameters. In the sample, a secret 'API_KEY' is created for the default task.

Ensure security considerations are made, and your repo is not made public with your run details

## Running the task
- Scheduled tasks will run based on the configured schedule. Please make appropriate billing considerations
- To run on-demand tasks, follow these steps: 
  - Go to the Actions tab of your repository
  - Select the configured workflow
  - Click on the 'Run Workflow' to reveal the drop down button
  - Click on the 'Run Workflow' green button.  

## Disclaimer
All the code samples in this GitHub repository are offered “as is” and include no warranty of any kind. Use them at your own risk. In no event will Kenna be liable to end user or any other party for damages of any kind arising from the use of these samples.
Please check the GitHub billing information. If you pass a certain amount of minutes or space used, you will be charged.
