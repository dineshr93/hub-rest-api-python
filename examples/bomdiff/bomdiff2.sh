#!/bin/bash
#
#
# Copyright (c) 2020 Dinesh Ravi. All rights reserved worldwide. 
#
# Author: R. Dinesh Ravi
#
# Version 1.0
#
# FUNCTION:
# The script is intended to export a bom diff 
#
# ALGORITIHM:
# - Authenticate
# - Find the given project by name
# - Find the given version in the project
# - Get the BoM diff for the project version
# - Get legal information for each component
# - If a component is a child project and sub-project processing is on recurse the process
#
# Usage:
# ./bomdiff.sh -u https://myblackduck -a <api_token> -p <project name> -v <version name> -w <version name> -f <output_notice.txt>
# bash bomdiff.sh -u https://blackduck.ebgroup.elektrobit.com -a NGNkM2YzZGUtNDJjOC00MjIxLTgxNWItMDUyYjRlZjZjMTM5OjY2Y2NhNWU5LWZjMWQtNDY3Ni05NzU5LTZmZThkYTRhYmEyYw== -p ASTERIX2_PROGRAM -v AED2_ANDROID_S_2_2024-04-16_00-45 -w AED2_ANDROID_S_2_2024-04-11_00-45
#
# Example:
# ./export_legal_bom.sh -u https://mymallord -a top-secret-api-token -p example-project -v 1 -f notice.txt


# Globals for input
ACCESS_TOKEN=""
WEB_URL=""
PROJECT_NAME=""
VERSION_NAME=""
PROJECT2_NAME=""
VERSION2_NAME=""
OUTPUT_LEGAL_COMPLIANCE_FILE=""
SAVE_LICENSE_TEXT=true
SAVE_DEEP_LICENSES=false
SAVE_COPY_RIGHT_NOTICES=true
TRUNCATE_COPYRIGHTS=true
PROCESS_SUB_PROJECTS=true
CLEAN_COPYRIGHTS=true

# As long as there is at least one more argument, keep looping
while [[ $# -gt 0 ]]; do
    key="$1"
    case "$key" in
        # Project name to find
        -p|--project-name)
            shift
            PROJECT_NAME="$1"
        ;;
        # Access token arg passed as space
        -a|--access-token)
            shift
            ACCESS_TOKEN="$1"
        ;;
        # HUB url arg passed as space
        -u|--hub-url)
            shift
            WEB_URL="$1"
        ;;
        # Project version name to find
        -v |--project-version)
            shift
            VERSION_NAME="$1"
        ;;
        # Project version name to find
        -w |--project-version2)
            shift
            VERSION2_NAME="$1"
        ;;
        *)
            # Do whatever you want with extra options
            echo "Unknown option '$key'"
        ;;
    esac
    # Shift after checking all the cases to get the next option
    shift
done

# Function to validate inputs
function validate_inputs()
{
    # Check all required inputs are provided
    if [[ -z "${ACCESS_TOKEN}"  || -z "${WEB_URL}" || -z "${PROJECT_NAME}" ]]
    then
        echo "Script inputs missing please use the following format: ./export_bom.sh -u https://myblackduck -a <api_token> -p <project name> -v <version name> -f <output txt file>"
        exit 1
    else
        echo "Inputs validated..."
    fi
}

# validate script requirements
function validate_requirements()
{
    # Check if jq and curl are installed
    local jq=$(command -v jq)
    local curl=$(command -v curl)

    if [[ -z "${jq}" || -z "${curl}" ]]
    then
        echo "jq and curl are required for this script"
        echo "aborting..."
        exit 1
    else
        echo "Tool requirements verified"
    fi
}

# Authenticate
function authenticate()
{
    local response=$(curl -s --insecure -X POST -H "Content-Type:application/json" -H "Authorization: token $ACCESS_TOKEN" \
    "$WEB_URL/api/tokens/authenticate")

    bearer_token=$(echo "${response}" | jq --raw-output '.bearerToken')
    if [ -z ${bearer_token} ]
    then
        echo "Could not authenticate, aborting..."
        echo "Error: $response"
        exit 1
    else
        echo "Authenticated successfully..."
    fi
}

# Find project by name
function get_project()
{
    local response=$(curl -s --insecure -X GET -H "Content-Type:application/json" -H "Authorization: bearer $bearer_token" \
    "$WEB_URL/api/projects?q=name:$PROJECT_NAME")

    response=$(echo "${response}" | jq --raw-output '.items[] | select(.name=='\""$PROJECT_NAME"\"')')
    if [ -z "${response}" ]
    then
        echo "Could not find a project with name: $PROJECT_NAME ...aborting"
        exit 1
    else
        echo "Found project: $PROJECT_NAME"
        PROJECT_LINK=$(echo "${response}" | jq --raw-output '._meta .links[] | select(.rel=="versions") | .href')
    fi
}

# Find a project version given its name
function get_project_version()
{
    local responseMain=$(curl -s --insecure -X GET -H "Content-Type:application/json" -H "Authorization: bearer $bearer_token" \
    "$PROJECT_LINK?offset=0&limit=25")

    # sort
    responseSorted=$(echo "${responseMain}" | jq --raw-output '.items |= sort_by(.lastScanDate)') 
    # List all versions
    echo "==============Listing all versions=============="
    echo "${responseSorted}" | jq --raw-output '.items[] | .versionName'
    echo "==================================="
    # last element contains latest snapshot
    VERSION_NAME=$(echo "${responseSorted}" | jq --raw-output '.items[-1] | .versionName ')
    # last 2nd element contains previous to latest snapshot
    VERSION2_NAME=$(echo "${responseSorted}" | jq --raw-output '.items[-2] | .versionName ')
    
    #echo "Comparing new snapshot -> $VERSION_NAME"
    #echo "with old snapshot -> $VERSION2_NAME"


    response=$(echo "${responseMain}" | jq --raw-output '.items[] | select(.versionName=='\""$VERSION_NAME"\"')')
    if [ -z "${response}" ]
    then
        echo "Could not find version: $VERSION_NAME for project: $PROJECT_NAME"
        echo "aborting..."
        exit 1
    else
        VERSION_LINK=$(echo "${response}" | jq --raw-output '._meta .href')
        echo "new: $VERSION_NAME -> $VERSION_LINK"
        echo 
    fi
    response2=$(echo "${responseMain}" | jq --raw-output '.items[] | select(.versionName=='\""$VERSION2_NAME"\"')')
    if [ -z "${response2}" ]
    then
        echo "Could not find version: $VERSION2_NAME for project: $PROJECT_NAME"
        echo "aborting..."
        exit 1
    else
        VERSION2_LINK=$(echo "${response2}" | jq --raw-output '._meta .href')
        echo "old: $VERSION2_NAME -> $VERSION2_LINK"
        echo 
    fi
    
}

function dump_bom()
{
    # Find all components in a BOM
    echo "Getting components..."
    local bom=$(curl -# --insecure -X GET -H "Accept: application/vnd.blackducksoftware.bill-of-materials-6+json" -H "Authorization: bearer $bearer_token" \
     "$VERSION2_LINK/comparison?comparedProjectVersion=$VERSION_LINK")
    # added
    local bomAdded=$(curl -# --insecure -X GET -H "Accept: application/vnd.blackducksoftware.bill-of-materials-6+json" -H "Authorization: bearer $bearer_token" \
     "$VERSION2_LINK/comparison?comparedProjectVersion=$VERSION_LINK&filter=componentState:ADDED&limit=2000")
    # vsAdded
    local bomAddedvs=$(curl -# --insecure -X GET -H "Accept: application/vnd.blackducksoftware.bill-of-materials-6+json" -H "Authorization: bearer $bearer_token" \
     "$VERSION2_LINK/comparison?comparedProjectVersion=$VERSION_LINK&filter=componentVersionState:ADDED&limit=2000")
    # Removed
    local bomRemoved=$(curl -# --insecure -X GET -H "Accept: application/vnd.blackducksoftware.bill-of-materials-6+json" -H "Authorization: bearer $bearer_token" \
     "$VERSION2_LINK/comparison?comparedProjectVersion=$VERSION_LINK&filter=componentState:REMOVED&limit=2000")
    # vsRemoved
    local bomRemovedvs=$(curl -# --insecure -X GET -H "Accept: application/vnd.blackducksoftware.bill-of-materials-6+json" -H "Authorization: bearer $bearer_token" \
     "$VERSION2_LINK/comparison?comparedProjectVersion=$VERSION_LINK&filter=componentVersionState:REMOVED&limit=2000")
    # CHANGED
    local bomChanged=$(curl -# --insecure -X GET -H "Accept: application/vnd.blackducksoftware.bill-of-materials-6+json" -H "Authorization: bearer $bearer_token" \
     "$VERSION2_LINK/comparison?comparedProjectVersion=$VERSION_LINK&filter=componentState:CHANGED&limit=2000")
    # vsCHANGED
    local bomChangedvs=$(curl -# --insecure -X GET -H "Accept: application/vnd.blackducksoftware.bill-of-materials-6+json" -H "Authorization: bearer $bearer_token" \
     "$VERSION2_LINK/comparison?comparedProjectVersion=$VERSION_LINK&filter=componentVersionState:CHANGED&limit=2000")
     

    echo "==========================="
    # echo "${bom}" | jq -r '.'
    
    local totalCount=$(echo "${bom}" | jq -r '.totalCount')
    local totalAddedComponents=$(echo "${bom}" | jq -r '.totalAddedComponents')
    local totalRemovedComponents=$(echo "${bom}" | jq -r '.totalRemovedComponents')
    local totalChangedComponents=$(echo "${bom}" | jq -r '.totalChangedComponents')
    local totalUnchangedComponentVersions=$(echo "${bom}" | jq -r '.totalUnchangedComponentVersions')
    local totalAddedComponentVersions=$(echo "${bom}" | jq -r '.totalAddedComponentVersions')
    local totalRemovedComponentVersions=$(echo "${bom}" | jq -r '.totalRemovedComponentVersions')
    local totalChangedComponentVersions=$(echo "${bom}" | jq -r '.totalChangedComponentVersions')
    local itemsAdd=$(echo "${bomAdded}" | jq -r '.items[] | [.component.componentName,.component.componentVersionName,.component.origins[].externalId]')
    local itemsAddvs=$(echo "${bomAddedvs}" | jq -r '.items[] | [.component.componentName,.component.componentVersionName,.component.origins[].externalId]')
    local itemsRemoved=$(echo "${bomRemoved}" | jq -r '.items[] | [.component.componentName,.component.componentVersionName,.component.origins[].externalId]')
    local itemsRemovedvs=$(echo "${bomRemovedvs}" | jq -r '.items[] | [.component.componentName,.component.componentVersionName,.component.origins[].externalId]')
    local itemsChanged=$(echo "${bomChanged}" | jq -r '.items[] | [.component.componentName,.component.componentVersionName,.component.origins[].externalId]')
    local itemsChangedvs=$(echo "${bomChangedvs}" | jq -r '.items[] | [.component.componentName,.component.componentVersionName,.component.origins[].externalId]')

    
    echo "totalCount $totalCount components..."
    echo "totalAddedComponents $totalAddedComponents"
    echo "totalRemovedComponents $totalRemovedComponents"
    echo "totalChangedComponents $totalChangedComponents"
    echo "totalUnchangedComponentVersions $totalUnchangedComponentVersions"
    echo "totalAddedComponentVersions $totalAddedComponentVersions"
    echo "totalRemovedComponentVersions $totalRemovedComponentVersions"
    echo "totalChangedComponentVersions $totalChangedComponentVersions"

    echo "====ADDED===="
    echo "$itemsAdd"    

    echo "====AddedVersionState===="
    echo "$itemsAddvs"    

    echo "=====REMOVED====="
    echo "$itemsRemoved"    

    echo "=====RemovedVersionState====="
    echo "$itemsRemovedvs"    

    echo "====Changed====="
    echo "$itemsChanged"    

    echo "=====ChangedVersionState====="
    echo "$itemsChangedvs"    

   
}

function get_bom_data()
{
    local count=0
    local totalCount=$(echo "${bom}" | jq -r '.totalCount')
    
    echo "Retrieving local data for $totalCount components..."
    progress_bar "$count" "$totalCount" "starting..."
    
    local items=$(jq -n '[]')
    
    for row in $(echo "${bom}" | jq -r '.items[] | @base64')
    do
        _jq()
        {
            echo ${row} | base64 --decode | jq -r ${1}
        }
        
        local component=$(_jq '.')

        local componentName=$(echo "${component}" | jq -r '.componentName')
        local componentVersionName=$(echo "${component}" | jq -r '.componentVersionName')


        count=$((count+1))
        progress_bar "$count" "$totalCount" "processing $componentName: $componentVersionName"
        
        echo "Component: $componentName, Version: $componentVersionName" >> $OUTPUT_LEGAL_COMPLIANCE_FILE

        # get the license title
        get_license_title

        if [ "${SAVE_LICENSE_TEXT}" = true ]
        then
            get_license_text
        fi

        if [ "${SAVE_DEEP_LICENSES}" = true ]
        then
            get_deep_license_data
        fi

        if [ "${SAVE_COPY_RIGHT_NOTICES}" = true ]
        then
            get_copyright_notices
        fi

        # required for sub projects
        local componentType=$(echo "${component}" | jq -r '.componentType')

        # if the component is a sub-project get its nested components recursively
        if [ "${componentType}" = "SUB_PROJECT" ] && [ "${PROCESS_SUB_PROJECTS}" = true ]
        then
            process_sub_project
        fi

        echo "---------------------------------------------------" >> $OUTPUT_LEGAL_COMPLIANCE_FILE

    done
    
    # End progress bar
    progress_bar "$count" "$totalCount" "Component data retrieved"
    printf "\n"
}

function run()
{
    # echo "============================== Starting =============================="
    validate_inputs
    # echo "----------------------------------------------------------------------"
    validate_requirements
    echo "----------------------------------------------------------------------"
    authenticate
    echo "----------------------------------------------------------------------"
    get_project
    echo "----------------------------------------------------------------------"
    get_project_version
    echo "----------------------------------------------------------------------"
    dump_bom
    echo "======================================================================"
}

################################ MAIN ####################################
run
##########################################################################
