#----------------------------------------------------------------------------
# Copyright 2018, FittedCloud, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.
#
#Author: Gregory Fedynyshyn (greg@fittedcloud.com)
#----------------------------------------------------------------------------

import sys
import os
import re
import time
import datetime
import traceback
import argparse
import json
import boto3
import botocore

from collections import namedtuple

DF_BLOCK_SIZE = 1024 # 1K is default for 'df'
DF_MAX_CMD_INVOCATIONS = 1024
FC_AWS_ENV = "AWS_DEFAULT_PROFILE"
FC_TIME_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"

DiskInfo = namedtuple("DiskInfo", "ec2Id, volId, dev, mount_point, timestamp, total_size, used, free")
CommandInfo = namedtuple("CommandInfo", "ec2Id, cmdId, platform")

# We dynamically update regions in our software, but for the
# purposes of this script, hardcoding is fine.
aws_regions = [
    'us-east-1',       # US East (N. Virginia)
    'us-west-2',       # US West (Oregon)
    'us-west-1',       # US West (N. California)
    'eu-west-1',       # EU (Ireland)
    'eu-central-1',    # EU (Frankfurt)
    'ap-southeast-1',  # Asia Pacific (Singapore)
    'ap-northeast-1',  # Asia Pacific (Tokyo)
    'ap-southeast-2',  # Asia Pacific (Sydney)
    'ap-northeast-2',  # Asia Pacific (Seoul)
    'sa-east-1',       # South America (Sao Paulo)
    'us-east-2',       # US East (Ohio)
    'ap-south-1',      # Asia Pacific (Mumbai)
    'ca-central-1',    # Canada (Central)
    'eu-west-2',       # EU (London)
]

# if we send a bulk command out, and one or more instances in the list
# does not have the ssm-agent installed, the entire bulk will fail.
# this function will send commands one at a time.  also allows us to
# check whether EC2 is windows or Linux prior to calling this function.
def ssm_send_command_individual(boto_session, ec2Id, command, platform=""):
    if platform == "windows":
        doc_name = "AWS-RunPowerShellScript"
    else:
        doc_name = "AWS-RunShellScript"
    try:
        output = boto_session.client('ssm').send_command(
            InstanceIds=[ec2Id],
            DocumentName=doc_name,
            Parameters={
                "commands":[
                    command
                ],
                "executionTimeout":["60"] # timeout after 1 minute
            },
            Comment='fc_diskanalyzer' # to make it easier to find out commands
        )
        return output['Command']['CommandId']
    except:
#       e = sys.exc_info()
#       print("ERROR: failed to send SSM command: %s" %str(e))
#       traceback.print_exc()
        return None


# not currently used
# use ssm_send_command_individual isntead
def ssm_send_command(boto_session, ec2id_list, command):
    try:
        output = boto_session.client('ssm').send_command(
            InstanceIds=ec2id_list,
            DocumentName='AWS-RunShellScript',
            Parameters={
                "commands":[
                    command
                ],
                "executionTimeout":["60"] # timeout after 1 minute
            },
            Comment='fc_diskanalyzer' # to make it easier to find out commands
        )
    except:
        e = sys.exc_info()
        print("ERROR: failed to send SSM command: %s" %str(e))
        traceback.print_exc()
        return None
    
    # should be a list of command Id's and associated ec2Id
    return output['Command']['CommandId']


# cmd_list should be single CommandInfo
def ssm_get_command_results(boto_session, cmd_info):
    output = None
    try:
        output = boto_session.client('ssm').get_command_invocation(
                        CommandId=cmd_info.cmdId,
                        InstanceId=cmd_info.ec2Id)
        #print("ssm_get_command_results: %s" %str(output))
    except:
        e = sys.exc_info()
        print("ERROR failed to get command results %s" %str(e))
        traceback.print_exc()
    return output


# not currently used
# cmd_list should be list of CommandInfo's
def ssm_get_command_results_all(boto_session, cmd_info_list):
    output = None
    for item in cmd_info_list:
        try:
            output = boto_session.client('ssm').get_command_invocation(
                            CommandId=item.cmdId,
                            InstanceId=item.ec2Id)
            #print("ssm_get_command_results: %s" %str(output))
        except:
            e = sys.exc_info()
            print("ERROR failed to get command results %s" %str(e))
            traceback.print_exc()
    return output


# not currently used
# can set cmdId to get a single command id, which should return results
# for each instance to which the command was sent.
def ssm_get_command_invocations_by_cmdId(boto_session, cmdId):
    cmd_list = []
    try:
        output = boto_session.client('ssm').list_command_invocations(CommandId=cmdId)
        for cmd in output:
            if cmd['Status'] == 'Success' and \
               cmd['Comment'] == 'fc_diskanalyzer':
                tmp = CommandInfo(ec2Id=cmd['InstanceId'], cmdId=cmdId)
                cmd_list.append(tmp)
        return cmd_list
    except:
        e = sys.exc_info()
        print("ERROR failed to get command results %s" %str(e))
        traceback.print_exc()
        return []


# not currently used
# get results per instances.  useful when you want to get historical results.
def ssm_get_command_invocations_by_ec2Id(boto_session):
    try:
        cmd_list = []
        ec2_resource = boto_session.resource('ec2')
        ec2_list = ec2_resource.instances.all()

        for ec2 in ec2_list:
            # TODO add 'InvokedAfter' or 'MaxResults' to limit output?
            output = boto_session.client('ssm').list_command_invocations(InstanceId=ec2.id)
            for cmd in output['CommandInvocations']:
                if cmd['Status'] == "Success" and \
                   cmd['Comment'] == "fc_diskanalyzer":
                    tmp = CommandInfo(ec2Id=ec2.id, cmdId=cmd['CommandId'])
                    cmd_list.append(tmp)
        return cmd_list
    except:
        e = sys.exc_info()
        print("ERROR failed to get command results %s" %str(e))
        traceback.print_exc()
        return []


# From 'man df': Display  values  are  in  units  of  the  first  available
# SIZE from --block-size,  and the DF_BLOCK_SIZE, BLOCK_SIZE and BLOCKSIZE
# environment variables.  Otherwise, units default to  1024  bytes  (or  512
# if POSIXLY_CORRECT is set).
#
# So we'll just force the default with the -B option when sending the command
def parse_df_output(out):
    df_list = []
    soc = out['StandardOutputContent']
    tmp = soc.split('\n') # split on new line for easier processing
    if len(tmp) < 1: # if for some reason output is empty
        return None
    for i in range(1, len(tmp)-1): #there's a newline at end of output, skip it
        t = tmp[i].split()
        # only want volumes, not tmpfs
        if t[0].startswith("/dev/sd") or t[0].startswith("/dev/xvd"):
            a = {"ec2Id": out['InstanceId'],
                 # the following nightmare converts the output's
                 # time string into a unix timestamp
                 "timestamp": int(time.mktime(datetime.datetime.strptime(
                             out['ExecutionEndDateTime'], FC_TIME_FMT).timetuple())),
                 "dev": t[0],
                 "size": int(t[1])*DF_BLOCK_SIZE, # assumes 1K blocks
                 "used": int(t[2])*DF_BLOCK_SIZE,
                 "free": int(t[3])*DF_BLOCK_SIZE,
                 "used_pct": t[4],
                 "mountpoint": t[5]}
            df_list.append(a)
    return df_list


# we care about fields Caption, DeviceID, FreeSpace, Size
def parse_wmic_output(out):
    wmic_list = []
    soc = out['StandardOutputContent']
    tmp = soc.split('\n')
    if len(tmp) < 1: # if for some reason output is empty
        return None
    for i in range(1, len(tmp)-2): # two newlines at end of output
        t = tmp[i].split()
        size = int(t[3]) # size in bytes
        used = int(t[3])-int(t[2])
        free = int(t[2])
        a = {"ec2Id": out['InstanceId'],
             # the following nightmare converts the output's
             # time string into a unix timestamp
             "timestamp": int(time.mktime(datetime.datetime.strptime(
                         out['ExecutionEndDateTime'], FC_TIME_FMT).timetuple())),
             "dev": t[1],
             "size": size,
             "used": used,
             "free": free,
             "used_pct": "%.0f%%" %(float(used)/float(size)*100),
             "mountpoint": t[0]}
        wmic_list.append(a)
    return wmic_list


# always print in GB to fit in 80-character-wide terminal
# dump json raw, not human-readable.  consumer of can apply transformations
# to json output.
def print_results_tab(df_list, j=False):
    if j == True:
        print(json.dumps(df_list, sort_keys=True, indent=4))
    else:
        print("Ec2ID               Device      Mountpoint Timestamp   Size(GB) Used(GB) Used%")
        for item in df_list:
            size = float(item['size']) / (1024*1024*1024)
            used = float(item['used']) / (1024*1024*1024)
            free = float(item['free']) / (1024*1024*1024)
            ssize = "%.2f" %size
            sused = "%.2f" %used
            sfree = "%.2f" %free
            # some formatting magic to make columns line up
            sdev = "{0}{1:{width}}".format(item['dev'], "", width=11-len(item['dev']))
            smount = "{0}{1:{width}}".format(item['mountpoint'], "", width=10-len(item['mountpoint']))
            ssize = "{0:{width}}{1}".format("", ssize, width=8-len(ssize))
            sused = "{0:{width}}{1}".format("", sused, width=8-len(sused))
            spct = "{0:{width}}{1}".format("", item['used_pct'], width=6-len(item['used_pct']))

            print("%s %s %s %s %s %s %s" \
                  %(item['ec2Id'],
                    sdev,
                    smount,
                    str(item['timestamp']),
                    ssize,
                    sused,
                    spct))


# not currently used
# human readable can be blank for bytes, 'k' for KB, 'm' for MB, 'g' for GB
# dump json raw, not human-readable.  consumer of can apply transformations
# to json output.
def print_results(df_list, human_readable='', j=False):
    if j == True:
        print(json.dumps(df_list, sort_keys=True, indent=4))
    else:
        for item in df_list:
            print("Ec2ID: %s" %item['ec2Id'])
            print("Device: %s" %item['dev'])
            print("Mount Point: %s" %item['mountpoint'])
            print("Timestamp: %s" %str(item['timestamp']))
            print("Used Pct: %s" %item['used_pct'])
            if (human_readable == 'k'):
                size = float(item['size']) / 1024
                used = float(item['used']) / 1024
                free = float(item['free']) / 1024
                print("Size: %.2f K" %size)
                print("Used: %.2f K" %used)
                print("Free: %.2f K" %free)
            elif (human_readable == 'm'):
                size = float(item['size']) / (1024*1024)
                used = float(item['used']) / (1024*1024)
                free = float(item['free']) / (1024*1024)
                print("Size: %.2f M" %size)
                print("Used: %.2f M" %used)
                print("Free: %.2f M" %free)
            elif (human_readable == 'g'):
                size = float(item['size']) / (1024*1024*1024)
                used = float(item['used']) / (1024*1024*1024)
                free = float(item['free']) / (1024*1024*1024)
                print("Size: %.2f G" %size)
                print("Used: %.2f G" %used)
                print("Free: %.2f G" %free)
            else:
                size = item['size']
                used = item['used']
                free = item['free']
                print("Size: %d" %size)
                print("Used: %d" %used)
                print("Free: %d" %free)
            print('')


# human-readable option currently not used, so hide it from usage
def print_usage():
     print("diskanalyzer.py <options>\n"
           "\tOptions are:\n\n"
           "\t--help - Display this help message\n"
           "\t-p --profile <profile name> - AWS profile name (can be used instead of -a and -s options)\n"
           "\t-a --accesskey <access key> - AWS access key\n"
           "\t-s --secretkey <secret key> - AWS secret key\n"
           "\t-r --regions <region1,region2,...> - A list of AWS regions.  If this option is omitted, all regions will be checked.\n"
           #"\t-h --human-readable <'k', 'm', or 'g'> display results in KB, MB, or GB.\n"
           "\t-j --json - Output in JSON format.\n\n"
           "\tOne of the following three parameters are required:\n"
           "\t\t1. Both the -a and -s options.\n"
           "\t\t2. The -p option.\n"
           "\t\t3. A valid " + FC_AWS_ENV + " enviornment variable.\n\n"
           "\tDepending on the number of EBS volumes being analyzed, this tool make take several minutes to run.")


def parse_options(argv):
    parser = argparse.ArgumentParser(prog="diskanalyzer.py",
                     add_help=False) # use print_usage() instead

    parser.add_argument("-p", "--profile", type=str, required=False)
    parser.add_argument("-a", "--access-key", type=str, required=False)
    parser.add_argument("-s", "--secret-key", type=str, required=False)
    parser.add_argument("-r", "--regions", type=str, default="")
    parser.add_argument("-h", "--human_readable", type=str, required=False, default='')
    parser.add_argument("-j", "--json", action="store_true", default=False)

    args = parser.parse_args(argv)
    if (len(args.regions) == 0):
        return args.profile, args.access_key, args.secret_key, [], args.human_readable, args.json
    else:
        return args.profile, args.access_key, args.secret_key, args.regions.split(','), args.human_readable, args.json 


def parse_args(argv):
    # ArgumentParser's built-in way of automatically handling -h and --help
    # leaves much to be desired, so using this hack instead.
    for arg in argv:
        if (arg == '--help'):
            print_usage()
            os._exit(0)

    p, a, s, rList, h, j = parse_options(argv[1:])

    return p, a, s, rList, h, j


if __name__ == "__main__":
    p, a, s, rList, h, j = parse_args(sys.argv)

    # need either -a and -s, -p, or AWS_DEFAULT_PROFILE environment variable
    if not a and not s and not p:
        if (FC_AWS_ENV in os.environ):
            p = os.environ[FC_AWS_ENV]
        else:
            print_usage()
            print("\nError: must provide either -p option or -a and -s options")
            os._exit(1)

    if a and not s and not p:
        print_usage()
        print("\nError: must provide secret access key using -s option")
        os._exit(1)

    if not a and s and not p:
        print_usage()
        print("\nError: must provide access key using -a option")
        os._exit(1)

    if p:
        try:
            home = os.environ["HOME"]
            pFile = open(home + "/.aws/credentials", "r")
            line = pFile.readline()
            p = "["+p+"]"
            while p not in line:
                line = pFile.readline()
                if (line == ""): # end of file
                    print_usage()
                    print("\nError: invalid profile: %s" %p)
                    os._exit(1)

            # get secret/access keys
            a = pFile.readline().strip().split(" ")[2]
            s = pFile.readline().strip().split(" ")[2]

        except:
            print("Error reading credentials for profile %s." %p)
            os._exit(1)

    if (len(rList) == 0):
        rList = aws_regions

    if h != '' and h != 'k' and h != 'm' and h != 'g':
        print("Warning: invalid value for '--human-readable'.  Ignoring.")
        h = ''

    for r in rList:
        try:
            bs = boto3.Session(aws_access_key_id=a,
                               aws_secret_access_key=s,
                               region_name=r)
            ec2_resource = bs.resource('ec2')
            ec2_all = ec2_resource.instances.all()
            cmd_info_list = []
            i = 0
            for ec2 in ec2_all:
                # ec2.platform is empty if Linux.  boto3 docs say that
                # the W in Windows should be upper-case, but it's wrong.
                if ec2.platform == "windows":
                    cmdId = ssm_send_command_individual(bs, ec2.id,
                        "wmic logicaldisk get caption,deviceid,freespace,size", "windows")
                else:
                    df = "df --block-size=%d" %DF_BLOCK_SIZE
                    cmdId = ssm_send_command_individual(bs, ec2.id, df)
                if (cmdId == None): # error
                    continue # skip if SSM Agent not installed
                    #print("ERROR: failed to send command to EC2 %s.  Perhaps SSM Agent is not installed." %ec2.id) # common error
                else:
                    cmd_info = CommandInfo(ec2Id=ec2.id, cmdId=cmdId, platform=ec2.platform)
                    cmd_info_list.append(cmd_info)

            time.sleep(5) # wait for commands to finish executing
            out = []
            for cmd in cmd_info_list:
                output = ssm_get_command_results(bs, cmd)
                if (cmd.platform == "windows"):
                    lst = parse_wmic_output(output)
                else:
                    lst = parse_df_output(output)
                for tmp in lst:
                    out.append(tmp)
            print_results_tab(out, j) # default to sizes in GB

        except:
            e = sys.exc_info()
            print("ERROR: exception region=%s, error=%s" %(r, str(e)))
            traceback.print_exc()
            os._exit(1)
