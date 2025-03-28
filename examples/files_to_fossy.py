from easy_fossy import easy_fossy as fossy
import os
import time
import argparse

use_fossy_to = fossy("config.ini", "prod",verify=False)

# Initialize the argument parser
parser = argparse.ArgumentParser(description='Script to FOSSology pkg upload for a given folder.')

# Add arguments
parser.add_argument('-f', '--pkg_folder', type=str, required=True, help='folder containing packages')
parser.add_argument('-n', '--folder_num', type=int, required=True, help='FOSSology folder number to upload')

# Parse the arguments
args = parser.parse_args()

pkg_folder = args.pkg_folder
folder_id = args.folder_num

# Open the file and read it line by line
for index,file_name in enumerate(os.listdir(pkg_folder)):
    file_path = os.path.join(pkg_folder, file_name)
    if os.path.isfile(file_path):  # Ensure it's a file, not a subdirectory
        print(file_name)


        print(f"Triggering upload of {file_name} in folder id {folder_id}")
        use_fossy_to.trigger_analysis_for_upload_package(
            file_path=file_path,
            folder_id=folder_id)
        
        time.sleep(10)
