'''
Created on August 15, 2023
@author: swright

##################### DISCLAIMER ##########################
##  This script was created for a specific purpose and   ##
##   SHOULD NOT BE USED as a general purpose utility.    ##
##   For general purpose utility use                     ##
##      /examples/client/generate_sbom.py                ##
###########################################################

Copyright (C) 2023 Synopsys, Inc.
http://www.blackducksoftware.com/

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements. See the NOTICE file
distributed with this work for additional information
regarding copyright ownership. The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.

This script will parse a provided SPDX file and import the SBOM to the
specified Project Name and Project Version. 

Then it will search each component specified in the SPDX file to determine
if the component was succesfully imported. Any missing components will be
added as a custom component and then added to the Project+Verion's BOM.

All missing components are saved to a file in JSON format for future reference.

Requirements

- python3 version 3.8 or newer recommended
- The following packages are used by the script and should be installed 
  prior to use:	
    argparse
    blackduck
    sys
    logging
    time
    json
    pprint
    spdx_tools
    re
    pathlib

- Blackduck instance
- API token with sufficient privileges

Install python packages with the following command:

 pip3 install argparse blackduck sys logging time json pprint pathlib spdx_tools

usage: parse_spdx.py [-h] --base-url BASE_URL --token-file TOKEN_FILE
                     --spdx-file SPDX_FILE --out-file OUT_FILE --project
                     PROJECT_NAME --version VERSION_NAME
                     [--license LICENSE_NAME] [--no-verify]
                     [--no-spdx-validate]

Parse SPDX file and verify if component names are in current SBOM for given
project-version

optional arguments:
  -h, --help            show this help message and exit
  --base-url BASE_URL   Hub server URL e.g. https://your.blackduck.url
  --token-file TOKEN_FILE
                        Access token file
  --spdx-file SPDX_FILE
                        SPDX input file
  --out-file OUT_FILE   Unmatched components file
  --project PROJECT_NAME
                        Project that contains the BOM components
  --version VERSION_NAME
                        Version that contains the BOM components
  --license LICENSE_NAME
                        License name to use for custom components (default:
                        "NOASSERTION")
  --no-verify           Disable TLS certificate verification
  --no-spdx-validate    Disable SPDX validation
'''

from blackduck import Client
import argparse
import sys
import logging
import time
import json
import re
from pprint import pprint
from pathlib import Path
from spdx_tools.spdx.model.document import Document
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.parser.error import SPDXParsingError
from spdx_tools.spdx.parser.parse_anything import parse_file

# Used when we are polling for successful upload and processing
global MAX_RETRIES
global SLEEP
MAX_RETRIES = 30
SLEEP = 10

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] {%(module)s:%(lineno)d} %(levelname)s - %(message)s"
)

logging.getLogger("blackduck").setLevel(logging.CRITICAL)

# Validates BD project and version
# Inputs:
#   projname - Name of project
#   vername  - Name of version
# Returns: Project object, Version object
def get_proj_ver(projname, vername):
    # Fetch Project (can only have 1)
    params = {
        'q': [f"name:{projname}"]
    }
    projects = [p for p in bd.get_resource('projects', params=params)
      if p['name'] == projname]
    assert len(projects) != 0, \
      f"Failed to locate project: {projname}"
    assert len(projects) == 1, \
      f"There should one project named {projname}. Found {len(projects)}"
    project = projects[0]

    # Fetch Version (can only have 1)
    params = {
        'q': [f"versionName:{vername}"]
    }
    versions = [v for v in bd.get_resource('versions', project, params=params)
      if v['versionName'] == vername]
    assert len(versions) != 0, \
      f"Failed to find project version: {vername}"
    assert len(versions) == 1, \
      f"There should be 1 version named {vername}. Found {len(versions)}"
    version = versions[0]

    logging.debug(f"Found {project['name']}:{version['versionName']}")
    return(project, version)

# Returns SPDX Document object on success, otherwise exits on parse failure
# Input: file = Filename to process
# Returns: SPDX document object
def spdx_parse(file):
    print("Parsing SPDX file...")
    start = time.process_time()
    try:
        document: Document = parse_file(file)
    except SPDXParsingError:
        logging.exception("Failed to parse spdx file")
        sys.exit(1)

    print('SPDX parsing took {:.2f}s'.format(time.process_time() - start))
    return(document)

# Validates the SPDX file. Logs all validation messages as warnings.
# Input: SPDX document object
def spdx_validate(document):
    print("Validating SPDX file...")
    start = time.process_time()
    validation_messages = validate_full_spdx_document(document)
    print('SPDX validation took {:.2f}s'.format(time.process_time() - start))

    for validation_message in validation_messages:
        # Just printing these messages intead of exiting.
        # Later when the file is imported, BD errors will be fatal.
        logging.warning(validation_message.validation_message)

# Returns MIME type to provide to scan API
# Input: filename to check
def get_sbom_mime_type(filename):
    with open(filename, 'r') as f:
        data = f.readlines()
        content = " ".join(data)
    if 'CycloneDX' in content:
        return 'application/vnd.cyclonedx'
    if 'SPDX' in content:
        return 'application/spdx'
    return None

# Poll for notification alerting us of successful BOM computation
#
# Inputs:
#  cl_url - Code Loction URL to match
#  proj_version_url - Project Version URL to match
#  summaries_url - Summaries URL from codelocation
#
# Returns on success. Errors are fatal.
def poll_notifications_for_success(cl_url, proj_version_url, summaries_url):
    retries = MAX_RETRIES
    sleep_time = SLEEP

    params = {
        'filter': ["notificationType:VERSION_BOM_CODE_LOCATION_BOM_COMPUTED"],
        'sort'  : ["createdAt: ASC"]
    }

    while (retries):
        retries -= 1
        for result in bd.get_items("/api/notifications", params=params):
            if 'projectVersion' not in result['content']:
               # Shouldn't be possible due to the filter
               continue
            # We're checking the entire list of notifications, but ours should
            # be near the top.
            if result['content']['projectVersion'] == proj_version_url and \
               result['content']['codeLocation'] == cl_url and \
               result['content']['scanSummary'] == summaries_url:
               print("BOM calculation complete")
               return

        print("Waiting for BOM calculation to complete")
        time.sleep(sleep_time)

    logging.error(f"Failed to verify successful BOM computed in {MAX_RETRIES * sleep_time} seconds")
    sys.exit(1)

# Poll for successful scan of SBOM.
# Inputs:
#
#   sbom_name: Name of SBOM document (not the filename, the name defined
#     inside the json body)
#    proj_version_url: Project version url
#
# Returns on success. Errors will result in fatal exit.
def poll_for_sbom_complete(sbom_name, proj_version_url):
    retries = MAX_RETRIES
    sleep_time = SLEEP
    matched_scan = False
    latest_url = None
    cl_url = None

    # Replace any spaces in the name with a dash to match BD
    sbom_name = sbom_name.replace(' ', '-')

    # Search for the latest scan matching our SBOM name
    params = {
        'q': [f"name:{sbom_name}"],
        'sort': ["updatedAt: ASC"]
    }

    while (retries):
        cls = bd.get_resource('codeLocations', params=params)
        retries -= 1
        if matched_scan:
            # Exit the while()
            break
        # Save the CL data as we go for debugging
        backupcls = []
        for cl in cls:
            backupcls.append(cl)
            if matched_scan:
                # Exit the inner for()
                break
            print(f"Searching scans for {sbom_name}...")
            # Force exact match of: spdx_doc_name + " spdx/sbom"
            # BD appends the "spdx/sbom" string to the name.
            if cl['name'] != sbom_name + " spdx/sbom":
                # No match, keep searching
                print(f"  {cl['name']} != {sbom_name}" + " spdx/sbom")
                continue

            print("  Scan located")
            matched_scan = True
            cl_url = cl['_meta']['href']

            print("Checking for latest-scan info...")
            for link in (cl['_meta']['links']):
                # Locate the scans URL to check for status
                if link['rel'] == "latest-scan":
                    print("  Located latest-scan")
                    latest_url = link['href']
                    break

        # We walked the list of code locations and didn't find a match
        if not matched_scan:
            print(f"  Waiting to locate scan...")
            time.sleep(sleep_time)

    if not matched_scan:
        logging.error(f"No scan found for SBOM: {sbom_name}")
        print("\nCodelocations API data:\n")
        pprint(backupcls)
        sys.exit(1)

    assert latest_url, "Failed to locate latest-scan reference"
    assert cl_url, "Failed to locate codelocation reference"

    # Wait for scanState = SUCCESS
    retries = MAX_RETRIES
    while (retries):
        json_data = bd.get_json(latest_url)
        retries -= 1
        if json_data['scanState'] == "SUCCESS":
            print("BOM upload complete")
            break
        elif json_data['scanState'] == "FAILURE":
            logging.error(f"SPDX Scan Failure: {json_data['statusMessage']}")
            sys.exit(1)
        else:
            # Only other state should be "STARTED" -- keep polling
            print(f"Waiting for scan completion, currently: {json_data['scanState']}")
            time.sleep(sleep_time)

    assert json_data, "Failed to locate scanState data"
    # If there were ZERO matches, there will never be a notification of
    # BOM import success. Short-circuit the check and treat this as success.
    if json_data['matchCount'] == 0:
        print("No BOM KB matches, continuing...")
        return

    # Save the codelocation summaries_url
    summaries_url = json_data['_meta']['href']

    # Check the bom-status endpoint for success
    retries = MAX_RETRIES
    while (retries):
        json_data = bd.get_json(proj_version_url + "/bom-status")
        retries -= 1
        if json_data['status'] == "UP_TO_DATE":
            print("BOM import complete")
            break
        elif json_data['status'] == "UP_TO_DATE_WITH_ERRORS" or \
          json_data['status'] == "PROCESSING_WITH_ERRORS":
            logging.error(f"BOM Import failure: status is {json_data['status']}")
            sys.exit(1)
        else:
            print(f"Waiting for BOM import completion, current status: {json_data['status']}")
            time.sleep(sleep_time)

    if retries == 0:
        logging.error(f"Failed to verify successful SBOM import in {retries * sleep_time} seconds")
        sys.exit(1)

    # Finally check notifications
    poll_notifications_for_success(cl_url, proj_version_url, summaries_url)

    # Any errors above already resulted in fatal exit
    return

# Upload provided SBOM file to Black Duck
# Inputs:
#   filename - Name of file to upload
#   project - Project name to map to
#   version - Version name to map to
def upload_sbom_file(filename, project, version):
    mime_type = get_sbom_mime_type(filename)
    if not mime_type:
        logging.error(f"Could not identify file content for {filename}")
        sys.exit(1)
    files = {"file": (filename, open(filename,"rb"), mime_type)}
    fields = {"projectName": project, "versionName": version}
    response = bd.session.post("/api/scan/data", files = files, data=fields)
    logging.debug(response)

    if response.status_code == 409:
        logging.error(f"File {filename} is already mapped to a different project version")

    if not response.ok:
        logging.error(f"Failed to upload SPDX file")
        try:
            pprint(response.json()['errorMessage'])
        except:
            logging.error(f"Status code: {response.status_code}")
        sys.exit(1)

# Lookup the given pURL in the BD KB.
#
# Inputs:
#   extref - pURL to look up
#
# Returns:
#  If match: API matching data (the "result" object)
#  No match: None
def find_comp_in_kb(extref):
    params = {
            'purl': extref
    }
    for result in bd.get_items("/api/search/kb-purl-component", params=params):
        # Should be exactly 1 match when successful
        return(result)

    # Fall through -- lookup failed
    return(None)

# Locate component name + version in BOM
# Inputs:
#   compname - Component name to locate
#   compver  - Component version to locate
#   projver  - Project version to locate component in BOM
#
# Returns: True on success, False on failure
def find_comp_in_bom(compname, compver, projver):
    have_match = False
    num_match = 0

    # Lookup existing SBOM for a match
    # This is a fuzzy match (see "react" for an example)
    params = {
        'q': [f"componentOrVersionName:{compname}"]
    }

    # Search BOM for specific component name
    comps = bd.get_resource('components', projver, params=params)
    for comp in comps:
        if comp['componentName'].lower() != compname.lower():
            # The BD API search is inexact. Force our match to be precise.
            continue
        if compver == "UNKNOWN":
            # We did not have a version specified in the first place
            return True
        # Check component name + version name
        try:
            if comp['componentVersionName'].lower() == compver.lower():
                return True
        except:
            # Handle situation where it's missing the version name for some reason
            print(f"comp {compname} in BOM has no version!")
            return False
    return False

# Verifies if a custom component and version already exist in the system.
#
# Inputs:
#   compname - Component name to locate
#   compver  - Component version to locate
# Returns:
#  CompMatch - Contains matched component url, None for no match
#  VerMatch  - Contains matched component verison url, None for no match
def find_cust_comp(compname, compver):
    params = {
        'q': [f"name:{compname.lower()}"]
    }

    matched_comp = None
    matched_ver = None
    # Warning: Relies on internal header
    headers = {'Accept': 'application/vnd.blackducksoftware.internal-1+json'}
    for comp in bd.get_resource('components', params=params, headers=headers):
        if compname.lower() == comp['name'].lower():
            # Force exact match
            matched_comp = comp['_meta']['href']
        else:
            # Keep checking search results
            continue

        # Check version
        for version in bd.get_resource('versions', comp):
            if compver.lower() == version['versionName'].lower():
                # Successfully matched both name and version
                matched_ver = version['_meta']['href']
                return(matched_comp, matched_ver)

        # If we got this far, break out of the loop
        # We matched the component, but not the version
        break

    return(matched_comp, matched_ver)

# Find URL of license to use for custom compnent creation
# Inputs:
#   license_name - Name of license to locate (case-sensitive)
#
# Returns: URL of license successfully matched. Failures are fatal.
def get_license_url(license_name):
    params = {
        'q': [f"name:{license_name}"]
    }
    for result in bd.get_items("/api/licenses", params=params):
        # Added precise matching in case of a situation like "NOASSERTION" & "NOASSERTION2"
        if (result['name'] == license_name):
            return(result['_meta']['href'])

    logging.error(f"Failed to find license {license_name}")
    sys.exit(1)

# Create a custom component. The Name and Version strings are converted to
# lowercase strings to ensure a reliable experience (avoiding dup names
# with varying CapItaliZation)
#
# Inputs:
#   name - Name of component to add
#   version - Version of component to add
#   license - License name
# Returns the URL for the newly created component version URL if successful
def create_cust_comp(name, version, license):
    print(f"Adding custom component: {name} {version}")
    license_url = get_license_url(license)
    data = {
        'name': name.lower(),
        'version' : {
          'versionName' : version,
          'license' : {
            'license' : license_url
          },
        }
    }
    response = bd.session.post("api/components", json=data)
    logging.debug(response)
    if not response.ok:
        # Shouldn't be possible. We checked for existence earlier.
        logging.error(response.json()['errors'][0]['errorMessage'])
        logging.error(f"Status code: {response.status_code}")
        sys.exit(1)

    # Should be guaranteed 1 version because we just created it!
    for version in bd.get_items(response.links['versions']['url']):
        return(version['_meta']['href'])

# Create a version for a custom component that already exists.
# Force the version string to be lowercase.
#
# Inputs:
#   comp_url - API URL of the component to update
#   version  - Version to add to existing component
#   license  - License to use for version
#
# Returns: component version url just created
def create_cust_comp_ver(comp_url, version, license):
    license_url = get_license_url(license)
    data = {
      'versionName' : version.lower(),
      'license' : {
          'license' : license_url
      },
    }
    response = bd.session.post(comp_url + "/versions", json=data)
    logging.debug(response)
    if response.status_code == 412:
        # Shouldn't be possible. We checked for existence earlier.
        logging.error(f"Version {version} already exists for component")
        sys.exit(1)

    if not response.ok:
        logging.error(f"Failed to add Version {version} to component")
        sys.exit(1)

    return(response.links['self']['url'])

# Add specified component version url to our project+version SBOM
# Inputs: 
#   proj_version_url: API URL for a project+version to update
#   comp_ver_url: API URL of a component+version to add
# Prints out any errors encountered. Errors are fatal.
def add_to_sbom(proj_version_url, comp_ver_url):
    data = {
        'component': comp_ver_url
    }
    response = bd.session.post(proj_version_url + "/components", json=data)
    if not response.ok:
        logging.error(response.json()['errors'][0]['errorMessage'])
        logging.error(f"Status code: {response.status_code}")
        sys.exit(1)

def parse_command_args():
    parser = argparse.ArgumentParser(description="Parse SPDX file and verify if component names are in current SBOM for given project-version")
    parser.add_argument("--base-url", required=True, help="Hub server URL e.g. https://your.blackduck.url")
    parser.add_argument("--token-file", dest='token_file', required=True,help="Access token file")
    parser.add_argument("--spdx-file", dest='spdx_file', required=True, help="SPDX input file")
    parser.add_argument("--out-file", dest='out_file', required=True, help="Unmatched components file")
    parser.add_argument("--project", dest='project_name', required=True, help="Project that contains the BOM components")
    parser.add_argument("--version", dest='version_name', required=True, help="Version that contains the BOM components")
    parser.add_argument("--license", dest='license_name', required=False, default="NOASSERTION", help="License name to use for custom components (default: NOASSERTION)")
    parser.add_argument("--no-verify", dest='verify', action='store_false', help="Disable TLS certificate verification")
    parser.add_argument("--no-spdx-validate", dest='spdx_validate', action='store_false', help="Disable SPDX validation")
    return parser.parse_args()

# Stub to support invocation as a standalone script
# Parses the command-line args, creates a BD object, and inokes import_sbom
def spdx_main_parse_args():
    args = parse_command_args()
    with open(args.token_file, 'r') as tf:
        access_token = tf.readline().strip()
    bdobj = Client(base_url=args.base_url, token=access_token, verify=args.verify)
    import_sbom(bdobj, args.project_name, args.version_name, args.spdx_file, \
      args.out_file, args.license_name, args.spdx_validate)

# Main entry point
#
# Inputs:
#  bdobj - BD Client Object
#  projname - Name of project
#  vername - Name of version
#  spdxfile - SPDX file location
#  outfile (Optional) - Name of file to write missing component data to in JSON.
#                       Default: No file written
#  license_name - Name of license to use for custom components
#                 Default: NOASSERTION
#  do_spdx_validate - Validate the SPDX file? (Boolean)
#                     Default: True
def import_sbom(bdobj, projname, vername, spdxfile, outfile=None, \
  license_name="NOASSERTION", do_spdx_validate=True):

    global bd
    bd = bdobj

    if (Path(spdxfile).is_file()):
        document = spdx_parse(spdxfile)
        if (do_spdx_validate):
            spdx_validate(document)
    else:
        logging.error(f"Could not open SPDX file: {spdxfile}")
        sys.exit(1)

    # Validate project/version details
    project, version = get_proj_ver(projname, vername)
    proj_version_url = version['_meta']['href']

    # Upload the provided SBOM
    upload_sbom_file(spdxfile, projname, vername)

    # Wait for scan completion. Will exit if it fails.
    poll_for_sbom_complete(document.creation_info.name, proj_version_url)

    # Open unmatched component file to save name, spdxid, version, and
    # origin/purl for later in json format
    if outfile:
        try: outfile = open(outfile, 'w')
        except:
            logging.exception("Failed to open file for writing: " + outfile)
            sys.exit(1)

    # Stats to track
    bom_matches = 0
    kb_matches = 0
    nopurl = 0
    nomatch = 0
    package_count = 0
    cust_comp_count = 0
    cust_ver_count = 0
    # Used for tracking repeated package data
    packages = {}
    # Saved component data to write to file
    comps_out = []

    # Walk through each component in the SPDX file
    for package in document.packages:
        package_count += 1
        # We hope we'll have an external reference (pURL), but we might not.
        extref = None
        purlmatch = False

        if package.name == "":
            # Strange case where the package name is empty. Skip it.
            logging.warning("WARNING: Skipping empty package name. Package info:")
            pprint(package)
            continue

        # Trim any odd leading/trailing space or newlines
        package.name = package.name.strip()

        # matchname/matchver can change, depending on the KB lookup step.
        # These are stored separately to keep the original names handy
        matchname = package.name
        if package.version is None or package.version == "":
            # Default in case one is not specified in SPDX
            package.version = "UNKNOWN"
        package.version = package.version.strip()
        matchver = package.version
        print(f"Processing SPDX package: {matchname} version: {matchver}...")

        # Tracking unique package name + version combos from spdx file
        packages[matchname+matchver] = packages.get(matchname+matchver, 0) + 1

        kb_match = None
        bd_proj = False
        if package.external_references:
            foundpurl = False
            for ref in package.external_references:
                # There can be multiple extrefs; try to locate a pURL.
                # If there are multiple pURLs, use the first one.
                if (ref.reference_type == "purl"):
                    foundpurl = True
                    kb_match = find_comp_in_kb(ref.locator)
                    extref = ref.locator
                    break
                # Skip BD project/versions. These occur in BD-generated BOMs.
                if (ref.reference_type == "BlackDuck-Version"):
                    bd_proj = True
                    break
            if not foundpurl:
                nopurl += 1
                print(f"  No pURL provided for {package.name} {package.version}")
            if (kb_match):
                # Update package name and version to reflect the KB name/ver
                print(f"  KB match for {package.name} {package.version}")
                kb_matches += 1
                matchname = kb_match['componentName']
                matchver = kb_match['versionName']
            else:
                print(f"  No KB match for {package.name} {package.version}")
        else:
            # No external references field was provided
            nopurl += 1
            print(f"  No pURL provided for {package.name} {package.version}")

        if bd_proj:
            print(f"  Skipping BD project/version in BOM: {package.name} {package.version}")
            continue

        if find_comp_in_bom(matchname, matchver, version):
            bom_matches += 1
            print(f"  Found component in BOM: {matchname} {matchver}")
            continue

        # If we've gotten this far, the package is not in the BOM.
        # Now we need to figure out:
        #  - Is it already in the KB and we need to add it? (should be rare)
        #  - Do we need to add a custom component?
        #  - Do we need to add a version to an existing custom component?
        nomatch += 1
        print(f"  Not present in BOM: {matchname} {matchver}")

        # Missing component data to write to a file for reference
        comp_data = {
            "name": package.name,
            "spdx_id": package.spdx_id,
            "version": package.version,
            "origin": extref
        }
        comps_out.append(comp_data)

        # KB match was successful, but it wasn't in the BOM for some reason
        if kb_match:
            print(f"  WARNING: {matchname} {matchver} in KB but not in SBOM")
            add_to_sbom(proj_version_url, kb_match['version'])
            # short-circuit the rest
            continue

        # Check if custom component already exists
        comp_url, comp_ver_url = find_cust_comp(package.name, package.version)

        if not comp_url:
            # Custom component did not exist, so create it
            cust_comp_count += 1
            comp_ver_url = create_cust_comp(package.name, package.version,
              license_name)
        elif comp_url and not comp_ver_url:
            # Custom component existed, but not the version we care about
            cust_ver_count += 1
            print(f"  Adding version {package.version} to custom component {package.name}")
            comp_ver_url = create_cust_comp_ver(comp_url, package.version, \
              license_name)
        else:
            print("  Custom component already exists, not in SBOM")

        # Shouldn't be possible
        assert(comp_ver_url), f"No component URL found for {package.name} {package.version}"

        print(f"  Adding component to SBOM: {package.name} aka {matchname} {package.version}")
        add_to_sbom(proj_version_url, comp_ver_url)

    # Save unmatched components
    if outfile:
        json.dump(comps_out, outfile)
        outfile.close()

    print("\nStats: ")
    print("------")
    print(f" SPDX packages processed: {package_count}")
    print(f" Packages missing from BOM: {nomatch}")
    print(f" BOM matches: {bom_matches}")
    print(f" KB matches: {kb_matches}")
    print(f" Packages missing purl: {nopurl}")
    print(f" Custom components created: {cust_comp_count}")
    print(f" Custom component versions created: {cust_ver_count}")
    #for debugging
    #pprint(packages)
    print(f" {len(packages)} unique packages processed")

if __name__ == "__main__":
    sys.exit(spdx_main_parse_args())
