'''
Created on Dec 19, 2018
Updated on Mar 07, 2024 By Dinesh Ravi

@author: gsnyder

Generate notices report for a given project-version
'''

from blackduck.HubRestApi import HubInstance

import argparse
import json
import logging
import sys
import time
import zipfile
from jinja2 import Environment, FileSystemLoader
import os
import json
import argparse

parser = argparse.ArgumentParser("A program to generate the notices file for a given project-version")
parser.add_argument("project_name")
parser.add_argument("version_name")
# parser.add_argument('-f', "--file_name_base", default="notices_report", help="Base file name to write the report data into. If the report format is TEXT a .zip file will be created, otherwise a .json file")
# parser.add_argument('-c', '--include_copyright_info', action='store_true', help="Set this option to have additional copyright information from the Black Duck KB included in the notices file report.")
# parser.add_argument('-r', '--report_format', default='TEXT', choices=["JSON", "TEXT"], help="Report format - choices are TEXT or HTML")
parser.add_argument('-t', '--report_template', default='notice-template.html', help="Report format - choices are notice-template.html or notice-black.html")

args = parser.parse_args()

templates_dir = os.path.dirname(os.path.abspath(__file__))
env = Environment(loader=FileSystemLoader(templates_dir))
# template = env.get_template('notices-template.html')
template = env.get_template(args.report_template)
file_name_base="bd"
output_file_name="FOSS_Report_"+args.project_name+"_"+args.version_name+'.html'
report_format='JSON'
hub = HubInstance()

logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', stream=sys.stderr, level=logging.DEBUG)

class FailedReportDownload(Exception):
    pass

DOWNLOAD_ERROR_CODES = ['{report.main.read.unfinished.report.contents}', '{report.main.download.unfinished.report}']

def download_report(location, file_name_base, retries=10):
    report_id = location.split("/")[-1]

    if retries:
        logging.debug("Retrieving generated report from {}".format(location))
        # response = hub.download_report(report_id)
        response, report_format = hub.download_notification_report(location)

        if response.status_code == 200:
            if report_format == "TEXT":
                filename = file_name_base + ".zip"
                with open(filename, "wb") as f:
                    f.write(response.content)
            else:
                # JSON format
                filename = file_name_base + ".json"
                with open(filename, "w") as f:
                    json.dump(response.json(), f, indent=3)
            logging.info("Successfully downloaded json file to {} for report {}".format(
                    filename, report_id))
        elif response.status_code == 412 and response.json()['errorCode'] in DOWNLOAD_ERROR_CODES:
            # failed to download, and report generation still in progress, wait and try again infinitely
            # TODO: is it possible for things to get stuck in this forever?
            logging.warning(f"Failed to retrieve report {report_id} for reason {response.json()['errorCode']}.  Waiting 5 seconds then trying infinitely")
            time.sleep(5)
            download_report(location, file_name_base, retries)
        else:
            logging.warning(f"Failed to retrieve report, status code {response.status_code}")
            logging.warning("Probably not ready yet, waiting 5 seconds then retrying (remaining retries={}".format(retries))
            time.sleep(5)
            retries -= 1
            download_report(location, file_name_base, retries)
    else:
        raise FailedReportDownload("Failed to retrieve report {} after multiple retries".format(report_id))

project = hub.get_project_by_name(args.project_name)

if project:
    version = hub.get_version_by_name(project, args.version_name)

    # response = hub.create_version_notices_report(version, args.report_format, include_copyright_info=args.include_copyright_info)
    response = hub.create_version_notices_report(version, 'JSON', include_copyright_info=True)

    if response.status_code == 201:
        logging.info("Successfully created notices report in {} format for project {} and version {}".format(
           'JSON', args.project_name, args.version_name))
        location = response.headers['Location']
        download_report(location, file_name_base)
        time.sleep(5)
        logging.info("Started creating HTML report")
        with open(output_file_name, 'w+',encoding="utf-8") as fh:
            with open(file_name_base+".json", 'r') as lj:
                data = json.load(lj)
                fileContent = data['reportContent'][0]['fileContent']

                fh.write(template.render(componentLicenses=fileContent['componentLicenses'],
                                        licenseTexts=fileContent['licenseTexts'],
                                        componentCopyrightTexts=fileContent['componentCopyrightTexts'],
                                        projectVersion=fileContent['projectVersion']))
                logging.info("Successfully created HTML report")
        logging.info("Cleaning up intermediary bd.json file")
        # os.remove(file_name_base+".json")
        logging.info("Removed bd.json file")


        # Showing how you can interact with the downloaded zip and where to find the
        # output content. Uncomment the lines below to see how it works.

        # with zipfile.ZipFile(zip_file_name_base, 'r') as zipf:
        #   with zipf.open("{}/{}/version-license.txt".format(args.project_name, args.version_name), "r") as license_file:
        #       print(license_file.read())
    else:
        logging.error("Failed to create reports for project {} version {}, status code returned {}".format(
            args.project_name, args.version_name, response.status_code))
else:
    logging.warning("Did not find project with name {}".format(args.project_name))