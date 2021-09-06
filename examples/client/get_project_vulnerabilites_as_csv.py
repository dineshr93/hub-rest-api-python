'''
Export the vulnerabilites from a project as CSV. Can be used to apply batch vulnerability
remediation with vuln_batch_remediation.py
'''
from blackduck import Client
import logging
import csv
import argparse
from pprint import pprint
import os
import sys
from dotenv import load_dotenv

load_dotenv()

API_TOKEN = os.getenv('API_TOKEN')

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] {%(module)s:%(lineno)d} %(levelname)s - %(message)s"
)

def main():
    program_name = os.path.basename(sys.argv[0])
    parser = argparse.ArgumentParser(prog=program_name, usage="%(prog)s [options]", description="Automated Assessment")
    parser.add_argument("--output", required=False,help="csv output path" )
    parser.add_argument("--project", required=True, help="project name")
    parser.add_argument("--base-url", required=False, help="base url", default="https://blackduck.omicron.at")
    parser.add_argument("--version", required=False, help="project version, e.g. latest")
    parser.add_argument("--component", required=False, help="component name")
    args = parser.parse_args()

    component = args.component
    projectname = args.project
    projectversion = args.version
    output = args.output  if  args.output != None else "output.csv"

    csv_file = open(output, mode='w', newline='', encoding='utf-8')
    csv_writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

    bd = Client(
        token=API_TOKEN,
        base_url=args.base_url,
        verify=False  # TLS certificate verification
    )

    for project in bd.get_resource('projects'):
        if (project['name'] == projectname):
            for version in bd.get_resource('versions', project):

                if (projectversion == None):
                    pprint(version['versionName'])

                else:
                    if (version['versionName'] == projectversion):
                        for vulnverable_component in bd.get_resource('vulnerable-components', version):
                            # TODO maybe match component name with regex?
                            if (vulnverable_component['componentName'] == component or component == None):

                                componentName = vulnverable_component["componentName"]
                                componentVersion = vulnverable_component["componentVersionName"]

                                remediation = vulnverable_component['vulnerabilityWithRemediation']
                                
                                name = remediation['vulnerabilityName']
                                status = remediation['remediationStatus']
                                description = remediation['description'].replace('\r', '').replace('\n', '')
                                comment = remediation.get('remediationComment', "").replace('\r', '').replace('\n', '')
                                
                                row =  [name, status, comment, componentName, componentVersion, description]
                                csv_writer.writerow(row)
                        break
            break



if __name__ == "__main__":
    main()
