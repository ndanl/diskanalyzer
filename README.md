Disk Usage Analyzer

Installation:
    1. Install Python 2.7 if not already installed.
    2. Install boto3, botocore, and arrow.  Use "sudo pip install boto3 botocore arrow".

Quick Start:

$ python diskanalyzer.py -a [aws access key] -s [aws secret key]  
$ python diskanalyzer.py -p [profile name]  
$ AWS_DEFAULT_PROFILE=default python diskanalyzer.py

For more information about options:
```
$ python diskanalyzer.py --help

diskanalyzer.py <options>
	Options are:

	--help - Display this help message
	-p --profile <profile name> - AWS profile name (can be used instead of -a and -s options)
	-a --accesskey <access key> - AWS access key
	-s --secretkey <secret key> - AWS secret key
	-r --regions <region1,region2,...> - A list of AWS regions.  If this option is omitted, all regions will be checked.
	-h --human-readable <'k', 'm', or 'g'> display results in KB, MB, or GB.
	-j --json - Output in JSON format.

	One of the following three parameters are required:
		1. Both the -a and -s options.
		2. The -p option.
		3. A valid AWS_DEFAULT_PROFILE enviornment variable.

	Depending on the number of EBS volumes being analyzed, this tool make take several minutes to run.
```
