from easy_fossy import easy_fossy as fossy
import os
import urllib.parse
import time
import argparse

use_fossy_to = fossy("config.ini", "prod",verify=False)

# Initialize the argument parser
parser = argparse.ArgumentParser(description='Script to handle URL file download and FOSSology folder upload.')

# Add arguments
parser.add_argument('-f', '--urls_file', type=str, required=True, help='Download URL file')
parser.add_argument('-n', '--folder_num', type=int, required=True, help='FOSSology folder number to upload')

# Parse the arguments
args = parser.parse_args()

file_path = args.urls_file
folder_id = args.folder_num

# Open the file and read it line by line
with open(file_path, 'r') as file:
    for index, line in enumerate(file,start=1):
        # Strip any leading/trailing whitespace (including newline characters)
        url = line.strip()
        # Print the URL (or perform other operations)
        print(index,url)
        # Parse the URL
        parsed_url = urllib.parse.urlparse(url)

        # Extract the file name from the path
        file_name_with_extension  = parsed_url.path.split('/')[-1]
        file_name, _ = os.path.splitext(file_name_with_extension)

        print(f"Triggering upload of {file_name} in folder id {folder_id}")
        use_fossy_to.trigger_analysis_for_url_upload_package(
            file_download_url=url,
            # file_name=key,
            file_name=file_name,
            branch_name="",
            folder_id=folder_id,
        )
        time.sleep(10)
