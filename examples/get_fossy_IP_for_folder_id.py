# Copyright @ 2024 Dinesh Ravi
# GPL-3.0+

from easy_fossy import easy_fossy as fossy
from easy_fossy import ClearingStatus, Upload
import argparse

use_fossy_to = fossy("config.ini", "prod")


parser = argparse.ArgumentParser(
    "Retreive BOM component origin information, and additional information, for the given project and version"
)
parser.add_argument("folder_id")
parser.add_argument("assignee", nargs="?", default="-unassigned-")
args = parser.parse_args()


uploads = use_fossy_to.get_all_uploads_based_on(
    folder_id=args.folder_id,
    is_recursive=True,
    limit=1000,
    page=1,
    search_pattern_key="",
    upload_status="",
    assignee=args.assignee,
    since_yyyy_mm_dd="",
)

for count, upload in enumerate(uploads, start=1):
    print(f"{count}. {upload.uploadname} ")
    print(f"upload_id:{upload.id}")
    # license listing section
    licenses = use_fossy_to.get_licenses_by_upload_id(upload.id)
    licenses = [(license.name, license.scannerCount) for license in licenses]
    print(f"License Count:{len(licenses)}")
    print("------")
    print(licenses)
    print("------")
    # copyright listing section
    # print(f"{count}. {upload.uploadname} upload_id:{upload.id} ")
    copyrights = use_fossy_to.get_copyrights_by_upload_id(upload.id)
    copyrights = [copyright.content for copyright in copyrights]
    copyrightsString = ", ".join(copyrights)
    print(copyrightsString)
    print("===============")
