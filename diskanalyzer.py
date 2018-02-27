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


# small wrapper function to keep ssm_send_command general, but to enforce
def send_df_command(boto_session, ec2idList):
    command = "df --block-size=%s" %(BLOCK_SIZE)
    return ssm_send_command(boto_session, ec2idList, command)


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
    #print(str(output))
    #print("StandardOutputContent:\n%s" %str(output['StandardOutputContent']))
    #print("ssm_get_command_results output = \n%s" %(str(output)))
    return output


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
                    #tmp = CommandInfo(ec2Id=cmd['InstanceId'], cmdId=cmd['CommandInfo'])
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
                 "timestamp": time.mktime(datetime.datetime.strptime(
                             out['ExecutionEndDateTime'], FC_TIME_FMT).timetuple()),
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
             "timestamp": time.mktime(datetime.datetime.strptime(
                         out['ExecutionEndDateTime'], FC_TIME_FMT).timetuple()),
             "dev": t[1],
             "size": size,
             "used": used,
             "free": free,
             "used_pct": "%.0f%%" %(float(used)/float(size)*100),
             "mountpoint": t[0]}
        wmic_list.append(a)
    return wmic_list


# human readable can be blank for bytes, 'k' for KB, 'm' for MB, 'g' for GB
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


def print_usage():
     print("diskanalyzer.py <options>\n"
           "\tOptions are:\n\n"
           "\t--help - Display this help message\n"
           "\t-p --profile <profile name> - AWS profile name (can be used instead of -a and -s options)\n"
           "\t-a --accesskey <access key> - AWS access key\n"
           "\t-s --secretkey <secret key> - AWS secret key\n"
           "\t-r --regions <region1,region2,...> - A list of AWS regions.  If this option is omitted, all regions will be checked.\n"
           "\t-h --human-readable <'k', 'm', or 'g'> display results in KB, MB, or GB.\n"
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

            # get secret access key
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
                # ec2.platform is empty if Linux
                if ec2.platform == "windows":
                    cmdId = ssm_send_command_individual(bs, ec2.id,
                        "wmic logicaldisk get caption,deviceid,freespace,size", "windows")
                else:
                    cmdId = ssm_send_command_individual(bs, ec2.id, "df")
                if (cmdId == None): # error
                    continue # skip if SSM Agent not installed
                    #print("ERROR: failed to send command to EC2 %s.  Perhaps SSM Agent is not installed." %ec2.id)
                else:
                    cmd_info = CommandInfo(ec2Id=ec2.id, cmdId=cmdId, platform=ec2.platform)
                    cmd_info_list.append(cmd_info)

            out = []
            for cmd in cmd_info_list:
                output = ssm_get_command_results(bs, cmd)
                if (cmd.platform == "windows"):
                    lst = parse_wmic_output(output)
                else:
                    lst = parse_df_output(output)
                for tmp in lst:
                    out.append(tmp)
            print_results(out, h, j)

        except:
            e = sys.exc_info()
            print("ERROR: exception region=%s, error=%s" %(r, str(e)))
            traceback.print_exc()
            os._exit(1)
