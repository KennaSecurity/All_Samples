# frozen_string_literal: true

source 'https://rubygems.org'

git_source(:github) do |repo_name|
  repo_name = "#{repo_name}/#{repo_name}" unless repo_name.include?('/')
  "https://github.com/#{repo_name}.git"
end

gem 'json'
gem 'rest-client'

# Only required for file upload types (Guardium and Qualys to Kenna Direct), comment out if unneeded:
gem 'nokogiri'
