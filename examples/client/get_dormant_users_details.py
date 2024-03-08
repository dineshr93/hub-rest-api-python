#!/usr/bin/env python

'''
Copyright (C) 2024 Dinesh Ravi
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
 
'''
import argparse
import json
import logging
import sys

from blackduck import Client

parser = argparse.ArgumentParser("Get all the dormant users")
parser.add_argument("sinceDays", help="give no of days since user is dormant")
parser.add_argument("--base-url", required=True, help="Hub server URL e.g. https://your.blackduck.url")
parser.add_argument("--token-file", dest='token_file', required=True, help="containing access token")
parser.add_argument("--no-verify", dest='verify', action='store_false', help="disable TLS certificate verification")
args = parser.parse_args()


logging.basicConfig(format='%(asctime)s:%(levelname)s:%(message)s', stream=sys.stderr, level=logging.DEBUG)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("blackduck").setLevel(logging.WARNING)

with open(args.token_file, 'r') as tf:
    access_token = tf.readline().strip()

bd = Client(
    base_url=args.base_url,
    token=access_token,
    verify=args.verify
)

# GET
params = {
    'sort':'lastlogindate asc',
    'sinceDays':args.sinceDays
}
headers = {
    'accept': "application/vnd.blackducksoftware.user-4+json"
}
i=0

nolastloginusers=[]
print(f"No of users dormant since {args.sinceDays} days are:")
for d_users in bd.get_items(url="/api/dormant-users",params=params, headers=headers):
    i=i+1
    if d_users.get('lastLogin'):
        print(f" {i} : {d_users['username']} lastLogin: {d_users.get('lastLogin')}")
    else:
        nolastloginusers.append(f" {i} : {d_users['username']} lastLogin: No last Login ")

if len(nolastloginusers)>0:
    print("Users with no login information")
    for nll in nolastloginusers:
        print(nll)