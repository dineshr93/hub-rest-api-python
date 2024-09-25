import argparse
import configparser

# input parser
parser = argparse.ArgumentParser("Give the inputs for producing the config.ini")
parser.add_argument("file_name", help="file_name")
parser.add_argument("group_name", help="group_name")
parser.add_argument("server", help="prod or test")
parser.add_argument("token", help="token")
parser.add_argument("token_expire", help="token_expiry format: YYYY-MM-DD")
parser.add_argument("token_valdity_days", help="token_expiry_days: 365")
parser.add_argument("assignee", nargs="?", default="-unassigned-", help="assignee")
args = parser.parse_args()
server = args.server

config = configparser.ConfigParser()
config.read(args.file_name)

# bearer_token =
# token_valdity_days =
# token_expire =
# group_name =
config.set(args.server, "assignee", args.assignee)
config.set(args.server, "bearer_token", str("Bearer ") + args.token)
config.set(args.server, "token_valdity_days", args.token_valdity_days)
config.set(args.server, "token_expire", args.token_expire)
config.set(args.server, "group_name", args.group_name)

with open(args.file_name, "w") as configfile:
    config.write(configfile)
