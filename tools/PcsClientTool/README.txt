Client tool for PCS

Prerequisites
  Install python3 and pip3 first, then install required packages using pip3
    sudo apt install python3
    sudo apt install python3-pip
    pip3 install -r requirements.txt

Usage: ./pcsclient.py [-h] {fetch,collect,cache} ...

positional arguments:
  {fetch,collect,cache}

optional arguments:
  -h, --help       show this help message and exit

1. Fetch platform collateral data from Intel PCS
  ./pcsclient.py fetch [-h] [-u URL] [-i INPUT_FILE] [-o OUTPUT_FILE]

  optional arguments:
          -h, --help            show this help message and exit
          -i INPUT_FILE, --input_file INPUT_FILE
                                The input file name for platform list. When omitted, PCK certificate
                                fetching is skipped; CRLs, TCB infos, and enclave identities are
                                still retrieved.
          -o OUTPUT_FILE, --output_file OUTPUT_FILE
                                The output file name for platform collaterals; default: platform_collaterals.json
          -u URL, --url URL     The URL of the Intel PCS service; default: https://api.trustedservices.intel.com/sgx/certification/v4/
          -p PLATFORM, --platform PLATFORM
                                Specify what kind of platform you want to fetch FMSPCs and tcbinfos for; default: all", choices=['all','client','E3','E5']
          -t {standard,early,all}, --tcb_update_type {standard,early,all}
                                Type of update to TCB info and enclave identities; default: standard
          -c, --crl             Retrieve only the certificate revocation list (CRL). If an input file is provided, this option will be ignored.

2. Collect platform data that was retrieved by PCK ID retrieval tool into one json file. This file can be used as input of "fetch" command.
  ./pcsclient.py collect [-h] [-d DIRECTORY] [-o OUTPUT_FILE]

  optional arguments:
          -h, --help            show this help message and exit
          -d DIRECTORY, --directory DIRECTORY
                                The directory which stores the platform data(*.csv) retrieved by PCK ID retrieval tool; default: ./
          -o OUTPUT_FILE, --output_file OUTPUT_FILE
                                The output json file name; default: platform_list.json

3. Generate local PCK certificate cache files for specific platforms
  ./pcsclient.py cache [-h] [-u URL] [-i INPUT_FILE] [-o OUTPUT_DIR] [-e EXPIRE_HOURS]

  optional arguments:
          -h, --help            show this help message and exit
          -i INPUT_FILE, --input_file INPUT_FILE
                                The input file name for platform list; default: platform_list.json
          -o OUTPUT_DIR, --output_dir OUTPUT_DIR
                                The output directory for cache files; default: ./cache/
          -u URL, --url URL     The URL of the Intel PCS service; default: https://api.trustedservices.intel.com/sgx/certification/v4/
          -e EXPIRE_HOURS, --expire EXPIRE_HOURS
                                How many hours the cache files will be valid for. Default is 2160 hours (90 days) and maximum is 8760.
          -t {standard,early}, --tcb_update_type {standard,early}
                                Type of update to TCB info and enclave identities; default: standard