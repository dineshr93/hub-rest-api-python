#!/usr/bin/env python

# Copyright @ 2024 Dinesh Ravi
# GPL-3.0+


import argparse
import json
import logging
import sys
import requests
from easy_fossy import easy_fossy as fossy
from blackduck.HubRestApi import HubInstance
import time


parser = argparse.ArgumentParser(
    "Retreive BOM component origin information, and additional information, for the given project and version"
)
parser.add_argument("project_name")
parser.add_argument("version")
parser.add_argument("folder_id")
parser.add_argument(
    "-l",
    "--deep_license_info",
    action="store_true",
    help="Include deep license (aka embedded license) information from the Black Duck KB for (KB) components in the BOM",
)
parser.add_argument(
    "-c",
    "--copyright_info",
    action="store_true",
    help="Include copyright info from the Black Duck KB for (KB) components in the BOM",
)
parser.add_argument(
    "-m",
    "--matched_files",
    action="store_true",
    help="Include a list of the matched (aka identified) files and the components they belong to.",
)
parser.add_argument(
    "-u",
    "--un_matched_files",
    action="store_true",
    help="Include a list of un-matched (un-identified) files",
)
parser.add_argument(
    "-s",
    "--string_search",
    action="store_true",
    help="Include any licenses found via string search (i.e. --detect.blackduck.signature.scanner.license.search==true",
)
parser.add_argument(
    "-x",
    "--upload_copyright_bd",
    action="store_true",
    help="upload the copyright to blackduck",
)
parser.add_argument(
    "-y",
    "--upload_to_fossy",
    action="store_true",
    help="upload the package to fossy",
)
parser.add_argument(
    "-a",
    "--all",
    action="store_true",
    help="Shortcut for including everything (i.e. all of it)",
)


args = parser.parse_args()
assignee = "-unassigned-"

if args.all:
    args.deep_license_info = args.copyright_info = args.matched_files = (
        args.un_matched_files
    ) = args.string_search = True

hub = HubInstance()
folder_id = int(args.folder_id)
project = hub.get_project_by_name(args.project_name)
version = hub.get_version_by_name(project, args.version)

bom_components = hub.get_version_components(version).get("items", [])

all_origins = dict()

logging.basicConfig(
    format="%(asctime)s:%(levelname)s:%(message)s",
    stream=sys.stderr,
    level=logging.DEBUG,
)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

all_origin_info = {}

scan_cache = {}

for bom_component in bom_components:
    if "componentVersionName" in bom_component:
        bom_component_name = (
            f"{bom_component['componentName']}:{bom_component['componentVersionName']}"
        )
    else:
        bom_component_name = f"{bom_component['componentName']}"

    # Component details include the home page url and additional home pages
    component_url = bom_component["component"]
    component_details = hub.execute_get(component_url).json()

    #
    # Grab origin info, file-level license info, and file-level copyright info
    #
    all_origin_details = list()
    for origin in bom_component.get("origins", []):
        logging.debug(
            f"Retrieving origin details for {bom_component_name} and origin {origin['name']}"
        )
        origin_url = hub.get_link(origin, "origin")
        origin_details = hub.execute_get(origin_url).json()

        #
        # Add deep license info and copyright info, as appropriate
        #
        info_to_get = []
        if args.deep_license_info:
            info_to_get.extend(
                [
                    ("file-licenses", "file_licenses"),
                    ("file-licenses-fuzzy", "file_licenses_fuzzy"),
                ]
            )

        if args.copyright_info:
            info_to_get.extend(
                [
                    ("file-copyrights", "file_copyrights"),
                    ("component-origin-copyrights", "component_origin_copyrights"),
                ]
            )
        for link_t in info_to_get:
            link_name = link_t[0]
            k = link_t[1]
            logging.debug(f"Retrieving {link_name} for {bom_component_name}")
            url = hub.get_link(origin_details, link_name)
            info = hub.execute_get(url).json().get("items", [])
            origin_details[k] = info

        all_origin_details.append(origin_details)

    all_origin_info.update(
        {
            bom_component_name: {
                "bom_component_info": bom_component,
                "component_details": component_details,
                "component_home_page": component_details.get("url"),
                "additional_home_pages": component_details.get("additionalHomepages"),
                "all_origin_details": all_origin_details,
            }
        }
    )

    if args.matched_files:
        logging.debug(f"Retrieving matched files for {bom_component_name}")
        matched_files_url = (
            hub.get_link(bom_component, "matched-files") + "?limit=99999"
        )
        matched_files = hub.execute_get(matched_files_url).json().get("items", [])
        # Get scan info
        for matched_file in matched_files:
            scan_url = hub.get_link(matched_file, "codelocations")
            if scan_url in scan_cache:
                scan = scan_cache[scan_url]
            else:
                scan = hub.execute_get(scan_url).json()
                scan_cache[scan_url] = scan
            matched_file["scan"] = scan
        all_origin_info[bom_component_name].update({"matched_files": matched_files})

if args.un_matched_files:
    # TODO: Probably need to loop on this with smaller page sizes to handle very large
    # project-versions with many (signature) scans mapped to it
    #
    logging.debug(
        f"Retrieving un-matched files for project {project['name']}, version {version['versionName']}"
    )
    un_matched_files_url = f"{version['_meta']['href']}/matched-files?limit=99999&filter=bomMatchType:unmatched"
    un_matched_files = hub.execute_get(un_matched_files_url).json().get("items", [])
    logging.debug(f"Adding {len(un_matched_files)} un-matched files to the output")
    all_origin_info.update({"un_matched_files": un_matched_files})

if args.string_search:
    #
    # Gathering the information on additional licenses/files identified using the
    # string search features requires we iterate over all the file system scans
    # to retrieve any additional licenses/files "discovered" (i.e. in GUI they are
    # displayed as "discoveries")
    #
    version_id = version["_meta"]["href"].split("/")[-1]
    codelocations_url = hub.get_link(version, "codelocations")
    codelocations = hub.execute_get(codelocations_url).json().get("items", [])

    # all the results will be stored here using the code location
    # name as the key and the value will include all the licenses, files
    # found to have license info in them
    #
    license_search_results = {}

    for codeloc in codelocations:
        license_search_results.update({codeloc["name"]: {"codeloc_info": codeloc}})

        codeloc_id = codeloc["_meta"]["href"].split("/")[-1]
        scans_url = hub.get_link(codeloc, "scans")
        scans = hub.execute_get(scans_url).json().get("items", [])
        latest_scan_url = hub.get_link(codeloc, "latest-scan")
        latest_scan = hub.execute_get(latest_scan_url).json()

        all_scans = []

        # TODO: Do I need to trim to the latest FS scan? Leaving it as list for now
        fs_scans = list(filter(lambda s: s["scanType"] == "FS", scans))

        for fs_scan in fs_scans:
            scan_id = fs_scan["_meta"]["href"].split("/")[-1]
            lic_summary_url = (
                version["_meta"]["href"] + f"/scans/{scan_id}/license-search-summary"
            )
            custom_headers = {"Accept": "*/*"}
            lic_search_summary = (
                hub.execute_get(lic_summary_url, custom_headers=custom_headers)
                .json()
                .get("items", [])
            )

            file_bom_entries = []
            for license_d in lic_search_summary:
                logging.debug(
                    f"Getting {license_d['fileCount']} files where {license_d['licenseName']} was referenced."
                )
                file_bom_entries_url = (
                    hub.get_apibase()
                    + f"/internal/releases/{version_id}/scans/{scan_id}/nodes/0/file-bom-entries?offset=0&limit=100&sort=&allDescendants=true&filter=stringSearchLicense:{license_d['vsl']}"
                )
                file_bom_entries.extend(
                    hub.execute_get(file_bom_entries_url).json().get("items", [])
                )
            all_scans.append(
                {
                    "scan_info": fs_scan,
                    "lic_search_summary": lic_search_summary,
                    "file_bom_entries": file_bom_entries,
                }
            )
        license_search_results[codeloc["name"]].update({"scans": all_scans})

    all_origin_info.update({"license_search_results": license_search_results})

# print(all_origin_info)

# print()
# Save in JSON format to file all_origin_info.json
# filename = "all_origin_info.json"
# with open(filename, "w") as f:
#     json.dump(all_origin_info, f, indent=3)
# logging.info("Successfully saved json to file {} for {}".format(
#     filename, args.project_name+' '+args.version))
session = requests.Session()
session.verify = False


def authenticate() -> str:
    with open(".restconfig.json", "r") as json_file:
        json_file = json.load(json_file)
        # print(json_file)
        api_token = json_file.get("api_token", "")
        baseurl = json_file.get("baseurl", "")
        # print(copyright_link)
        # print(copyright_text)

        # payload = f'{{"copyright" : "{copyright_text}"}}'
        headers = {
            "Accept": "application/vnd.blackducksoftware.user-4+json",
            "Authorization": f"token {api_token}",
        }
        response = session.post(
            url=f"{baseurl}/api/tokens/authenticate",
            headers=headers,
        )
        match response.status_code:
            case 200:

                json_output = json.dumps(response.json())
                json_outputs = json.loads(json_output)
                bearertoken = json_outputs.get("bearerToken", "")
                # print(bearertoken)

                # print(f'updated copyright: {bearertoken}')
                return bearertoken

            case _:
                print(response.text)
                return ""


bearer = authenticate()


def udpate_copyright_for_copyrightlink(copyright_link: str, copyright_text: str):
    """get upload summary for given upload_id
    {

    }
    """

    payload = f'{{"copyright" : "{copyright_text}"}}'
    headers = {
        "Accept": "application/vnd.blackducksoftware.copyright-4+json",
        "Content-Type": "application/vnd.blackducksoftware.copyright-4+json",
        "Authorization": f"bearer {bearer}",
    }
    response = session.post(
        url=copyright_link,
        data=payload,
        headers=headers,
    )
    match response.status_code:
        case 200:
            json_output = json.dumps(response.json())
            json_outputs = json.loads(json_output)
            print(f'updated copyright: {json_outputs.get("updatedCopyright","")}')
        case _:
            print(response.text)


url404 = []
badurl = []
goodurl = []
ignored = []
notmaven = []
use_fossy_to = fossy("config.ini", "prod")
validlibscount = 0
for key, value in all_origin_info.items():
    print(f"Component: {key}")
    # if key.lower().startswith(
    #     ("k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z")
    # ):
    #     continue
    bom_component_info = value.get("bom_component_info", "")
    isIgnored = bom_component_info.get("ignored")
    if isIgnored:
        ignored.append(key)
        continue
    all_origin_details = value.get("all_origin_details", "")

    for origin_detail in all_origin_details:
        originName = origin_detail.get("originName", "")
        if originName != "maven":
            notmaven.append(key)
            continue
        else:
            originId = origin_detail.get("originId", "")
            originIdArray = originId.split(":")
            libName = originIdArray[1]
            libVersion = originIdArray[2]
            originUrl = origin_detail.get("originUrl", "")
            full_file_name = libName + "-" + libVersion + "-sources.jar"
            fullURL = originUrl + full_file_name
            print(fullURL)
            print(originId)
            copyrightupdatelink = ""
            meta = origin_detail.get("_meta", "")
            links = meta.get("links", "")
            for link in links:
                if link.get("rel") == "component-origin-copyrights":
                    copyrightupdatelink = link.get("href")

            try:
                # headers=requests.head(fullURL).headers
                # downloadable = 'attachment' in headers.get('Content-Disposition', '')
                # if downloadable:
                # 	msg = fullURL+ " is "+"downloadable"
                # else:
                # 	msg = fullURL+ " is "+"NOT downloadable"
                # print(msg)
                # get status code
                response = requests.get(fullURL, stream=True)
                status_code = response.status_code
                print(f"Status code: {status_code}")
                if status_code >= 400 and status_code < 500:
                    print(f"{key} URL has status code: {status_code}")
                    url404.append(key)
                    print("********")
                    continue

                print(f"Content-length: {response.headers['content-length']}")
                goodurl.append(key)

                if "http:" in fullURL:
                    logging.debug(f"converting http to https")
                    fullURL = fullURL.replace("http:", "https:")

                # upload to 121 SHM_AOSP folder in fossology production
                if args.upload_to_fossy:
                    print(f"Triggering upload of {key}")
                    use_fossy_to.trigger_analysis_for_url_upload_package(
                        file_download_url=fullURL,
                        # file_name=key,
                        file_name=full_file_name,
                        branch_name="",
                        folder_id=folder_id,
                    )
                    time.sleep(2)
                uploads = use_fossy_to.get_all_uploads_based_on(
                    folder_id=folder_id,
                    is_recursive=True,
                    limit=1000,
                    page=1,
                    search_pattern_key=full_file_name,
                    upload_status="",
                    assignee=assignee,
                    since_yyyy_mm_dd="",
                )
                validlibscount = validlibscount + 1
                print(f"{validlibscount}. {full_file_name}")
                # license listing section
                for count, upload in enumerate(uploads, start=1):
                    print(f"upload_id:{upload.id} ")

                    licenses = use_fossy_to.get_licenses_by_upload_id(upload.id)
                    licenses = [
                        (license.name, license.scannerCount) for license in licenses
                    ]
                    print(f"License Count:{len(licenses)}")
                    print("------")
                    print(licenses)
                    print("------")
                # copyright listing & updating section
                for count, upload in enumerate(uploads, start=1):
                    # print(f"{count}. {upload.uploadname} upload_id:{upload.id} ")
                    copyrights = use_fossy_to.get_copyrights_by_upload_id(upload.id)
                    copyrights = [copyright.content for copyright in copyrights]
                    copyrightsString = ", ".join(copyrights)
                    print(copyrightsString)
                    if args.upload_copyright_bd:
                        udpate_copyright_for_copyrightlink(
                            copyrightupdatelink, copyrightsString
                        )
                    print("======")
                    print()

            except requests.exceptions.RequestException as e:
                print(e)
                print(
                    "for {key} URL does not exist on Internet or file not downloadable"
                )
                badurl.append(key)
                print("********")
            break
print("===================Overview====================")

print(f"Total component {len(all_origin_info)}")
print(f"Total url404s {len(url404)}")
print(f"Total badurls {len(badurl)}")
print(f"Total goodurls {len(goodurl)}")
print(f"Total ignored {len(ignored)}")
print(f"Total notmaven {len(notmaven)}")
print("======== 404 URLs========")
for i, v in enumerate(url404, start=1):
    print(i, v)
print("======== BAD URL========")
for i, v in enumerate(badurl, start=1):
    print(i, v)
print("======== IGNORED Component ========")
for i, v in enumerate(ignored, start=1):
    print(i, v)
print("======== Not maven Component ========")
for i, v in enumerate(notmaven, start=1):
    print(i, v)
print("======== GOOD URL ========")
for i, v in enumerate(goodurl, start=1):
    print(i, v)
