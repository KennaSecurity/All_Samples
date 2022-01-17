# Create Parent and/or Child Risk meters

## Introduction
Kenna introduced the possibility of creating child risk meters which helps organizations define a hierarchical structure for their VM program. 

This script will create child risk meters from a csv file. Each child risk meter must define a parent risk meter id, name and an unencoded query string. 
API base URL is api.kennasecurity.com. Edit the code if this is not the correct base URL for you. URL explanations can be found in the API documentation, or by contacting your account representative/support.

Data in the meta file is used for creating the relevant parent or child risk meters.  

## Usage
ruby create_parent_child_meters.rb <API_token> meta_hrm.csv

## Example Usage of the meta file
The table below provides illustrations of how different scenarios are used to create hierarchical risk meters from the meta file. 

|parent_id |display_name |rm_query |parent_ref |child_ref|comments (provided for illustration. this column is not included in the meta file |
| ---------|-------------|---------|-----------|---------|----------------------------------------------------------------------------------|
|281515|xyz_child|vulnerability_score:>65| |xyz_child_level_1| the risk meter (RM) is created as a child of RM with ID 281515. child_ref is saved and will be used for creating another child RM in the current file. |
| |xyz_no_parent|vulnerability_score:>90 AND vulnerability_score:<100| | | no parent ID or parent ref so this will be a parent RM. Also, no child_ref so a child RM is not going to be created off this RM. |
| |xyz_gchild |vulnerability_score:>80 |xyz_child_level_1 | xyz_child_level_2 | no parent ID but parent_ref available matching the child_ref of xyz_child RM in the file so xyz_child will be the parent RM for xyz_gchild RM. child_ref indicates this xyz_gchild RM is to be the parent of yet another RM. |
| |xyz_ggchild |vulnerability_score:>95 |xyz_child_level_2 | | no parent ID but parent_ref matching the child_ref of xyz_gchild so this RM will be the child of xyz_gchild. |

## Requirements
* ruby
* rest-client
* json
* csv
