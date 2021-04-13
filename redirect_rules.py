#!/usr/bin/env python3

#> -----------------------------------------------------------------------------

#   Quick and dirty dynamic redirect.rules generator

#   This is a Python rewrite and expansion of:
#    - https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
#    - https://github.com/violentlydave/mkhtaccess_red/blob/master/mkhtaccess_red

#   Code architecture based on:
#    - https://github.com/0xdade/sephiroth

#> -----------------------------------------------------------------------------

import os
import re
import sys
import time
import shutil
import argparse
import subprocess
from datetime import datetime
from typing import List, Optional

# Import modules
try:
    from core import support
    from core.source import Source
    from core.output.apache import Apache
    from core.output.satellite import Satellite
    from core.type import Block
except (ModuleNotFoundError, ImportError) as e:
    print('[!]\tMissing Python module:')
    print('\t%s' % e)
    sys.exit(1)


__version__ = '1.2.4'

## Exclusion Keywords
# This will allow us to identify explicit exclusions
KEYWORDS = [
    # Static sources
    'static',       # All static sources
    'htaccess',     # Exclude @curi0usJack's .htaccess gist
    'user-agents',
    'hostnames',
    'ips',
    'asn',          # Exclude all ASN sources
    'radb',
    'bgpview',
    'misc',
    # Dynamic sources
    'dynamic',      # All dynamic sources
    'tor',
    'amazon',       # Exclude all Amazon sources
    'aws',
    'google',       # Exclude all Google sources
    'googlecloud',
    'microsoft',    # Exclude all Microsoft sources
    'azure',
    'office365',
    'oracle',       # Exclude all Oracle sources
    'oraclecloud'
]

# URL Regex
regex = re.compile(
    r'^(?:http)s?://'  # http:// or https://
    # domain...
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)


def get_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Dynamically generate redirect.rules file -- v{VERS}".format(VERS=__version__))
    parser.add_argument('-d', '--destination', type=str,
                        help='Destination for redirects (with the protocol, e.g., https://redirect.here/index.php).')
    parser.add_argument(
        '--exclude',
        type=str,
        nargs='+',
        default=[],
        help='Pass in one or more data sources and/or explicit IP/Host/User-Agent\'s to exclude. ' +
        'Run the `--exclude-list` command to list all data source keywords that can be used. ' +
        'Keywords and explicit strings should be space delimited. ' +
        'Example Usage: `--exclude agents radb 35.0.0.0/8`'
    )
    parser.add_argument('--exclude-file',   type=str,
                        help='File containing items/keywords to exclude (line separated).')
    parser.add_argument('--exclude-list',   action='store_true',
                        help='List possible keyword exclusions.')
    # Support for passing in extra source files
    parser.add_argument('--ip-file',        type=str, nargs='+',
                        help='Provide one or more external IP files to use as source data.')
    parser.add_argument('--asn-file',       type=str, nargs='+',
                        help='Provide one or more external ASN files to use as source data.')
    parser.add_argument('--hostname-file',  type=str, nargs='+',
                        help='Provide one or more external Hostname files to use as source data.')
    parser.add_argument('--useragent-file', type=str, nargs='+',
                        help='Provide one or more external User-Agent files to use as source data.')
    parser.add_argument('--output', type=str, default='/tmp/redirect.rules',
                        help='File to write (default /tmp/redirect.rules)')
    parser.add_argument('--user-agent', default='Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:74.0) Gecko/20100101 Firefox/74.0', type=str,
                        help='HTTP user agent')
    parser.add_argument('--timeout', default=10, type=int, help='HTTP timeout')
    parser.add_argument('--apache', action='store_true',
                        help='Set Apache output')
    parser.add_argument('--satellite', action='store_true',
                        help='Set Satellite output.')
    parser.add_argument('--verbose',        action='store_true',
                        help='Enable verbose output.')
    args = parser.parse_args()
    return args


def sanity_checks(args) -> None:
    # Set output type
    if (not args.apache and not args.satellite) or (args.apache and args.satellite):
        print('[!]\tMust select either --apache or --satellite')
        sys.exit(1)

    # Exit the script if not running on a *nix based system
    # *nix required for subprocess commands like `grep` and `sed`
    if os.name != 'posix':
        print('[!]\tPlease run this script on a *nix based system.')
        sys.exit(1)

    # Exit the script if the `whois` tool is not installed to prevent silent failures
    # during ASN collection
    # shutil.which() requires Python3.3+
    if sys.version_info >= (3, 3):
        if not shutil.which('whois'):
            print(
                '[!]\tThe `whois` tool does not appear to be installed on your system.')
            print('\tInstall command: `sudo apt install -y whois`')
            sys.exit(1)

    # Exit the script if we are below Python3.3
    else:
        print('[!]\tPython3.3+ is required to run this script.')
        sys.exit(1)

    # Print the exclusion list and exit
    if args.exclude_list:
        support.print_exclude_list()
        sys.exit()

    # If we made it past the exclude-list, make sure
    # the user provided a destination
    if args.destination:
        # Make sure this is a full URL
        if not (re.match(regex, args.destination)):
            print(
                '[!]\t-d/--destination must include a full URL (e.g., http://example.com/index.html)')
            sys.exit(1)
    else:
        print('[!]\tThe following arguments are required: -d/--destination')
        sys.exit(1)


def print_header() -> None:
    print(f'''
    ----------------------------------
      Redirect Rules Generation Tool
                  v{__version__}
    ----------------------------------
    ''')


def get_exclusions(exclude_file: str) -> List[str]:
    '''
    Parse exclusion file and add to exclude list
    '''
    if not exclude_file or not os.path.exists(exclude_file):
        return []

    with open(args.exclude_file, 'r') as file_:
        return [x.strip() for x in file_.readlines() if x.strip() != '']


if __name__ == '__main__':
    args = get_arguments()
    sanity_checks(args)
    print_header()

    # Start timer
    start = time.perf_counter()

    # Print exclusion count
    # Only show count in case a large list was passed in
    excludes = get_exclusions(args.exclude_file)
    if len(excludes) > 0:
        print('[+]\tExclusion List: %d' % len(excludes))
        print('[*]\tFull exclusion list can be found at the end of the')
        print('   \tredirect.rules file.\n')

    print(args)
    http_headers = {'User-Agent': args.user_agent}

    blocklist = Block()

    #> -----------------------------------------------------------------------------
    # Write @curi0usJack's .htaccess rules: https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
    if 'htaccess' not in excludes:  # Exclude keyword
        source = Source('htaccess', [http_headers, args.timeout, args])
        blocklist |= source.process_data()

    #> -----------------------------------------------------------------------------
    # Add static User-Agent list
    # __static__
    # Exclude keywords
    if all(x not in excludes for x in ['agents', 'user-agents', 'static']):
        source = Source('user-agents', [])
        blocklist |= source.process_data()

    #> -----------------------------------------------------------------------------
    # Add static ips list
    # __static__
    # Exclude keywords
    if all(x not in excludes for x in ['ip', 'ips', 'static']):
        source = Source('ips', [])
        blocklist |= source.process_data()

    #> -----------------------------------------------------------------------------
    # Add static hostnames list
    # __static__
    # Exclude keywords
    if all(x not in excludes for x in ['hosts', 'hostnames', 'static']):
        source = Source('hostnames', [])
        blocklist |= source.process_data()

    #> -----------------------------------------------------------------------------
    # Add Tor exit nodes: https://check.torproject.org/exit-addresses
    # __dynamic__
    if all(x not in excludes for x in ['tor', 'dynamic']):  # Exclude keywords
        source = Source('tor', [http_headers, args.timeout])
        blocklist |= source.process_data()

    #> -----------------------------------------------------------------------------
    # Add AWS IPs: https://ip-ranges.amazonaws.com/ip-ranges.json
    # __dynamic__
    # Exclude keywords
    if all(x not in excludes for x in ['amazon', 'aws', 'dynamic']):
        source = Source('aws', [http_headers, args.timeout])
        blocklist |= source.process_data()

    #> -----------------------------------------------------------------------------
    # Add GoogleCloud IPs: dig txt _cloud-netblocks.googleusercontent.com
    # __dynamic__
    # Exclude keywords
    if all(x not in excludes for x in ['google', 'googlecloud', 'dynamic']):
        source = Source('googlecloud', [])
        blocklist |= source.process_data()

    #> -----------------------------------------------------------------------------
    # Add Microsoft Azure IPs: https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653
    # __dynamic__
    # Exclude keywords
    if all(x not in excludes for x in ['microsoft', 'azure', 'dynamic']):
        source = Source('azure', [http_headers, args.timeout])
        blocklist |= source.process_data()

    #> -----------------------------------------------------------------------------
    # Add Office365 IPs: https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7
    # https://rhinosecuritylabs.com/social-engineering/bypassing-email-security-url-scanning/
    # __dynamic__
    # Note: Not working as of 4/8/2021
    # if all(x not in excludes for x in ['microsoft', 'office365', 'dynamic']):  # Exclude keywords
    #     source = Source(
    #         'office365',
    #         [  # Params object
    #             http_headers,
    #             args.timeout,
    #         ]
    #     )
    #     blocklist |= source.process_data()

    #> -----------------------------------------------------------------------------
    # Add Oracle Cloud IPs: https://docs.cloud.oracle.com/en-us/iaas/tools/public_ip_ranges.json
    # __dynamic__
    # Exclude keywords
    if all(x not in excludes for x in ['orcale', 'oraclecloud', 'dynamic']):
        source = Source('oraclecloud', [http_headers, args.timeout, ])
        blocklist |= source.process_data()

    #> -----------------------------------------------------------------------------
    # Add companies by ASN - via whois.radb.net
    # __static__
    if all(x not in excludes for x in ['asn', 'radb', 'static']):
        source = Source('radb', [args, excludes])
        blocklist |= source.process_data()

    #> -----------------------------------------------------------------------------
    # Add companies by ASN - via BGPView
    # __static__
    if all(x not in excludes for x in ['asn', 'bgpview', 'static']):
        source = Source('bgpview', [http_headers, args.timeout, args])
        blocklist |= source.process_data()

    #> -----------------------------------------------------------------------------
    # Misc sources -- see core/static/misc.txt for more information
    # __static__
    if all(x not in excludes for x in ['misc', 'static']):
        source = Source('misc', [])
        blocklist |= source.process_data()

    #> -----------------------------------------------------------------------------
    # External sources -- IP file(s)
    if args.ip_file:
        for _file in args.ip_file:
            # Make sure the file is valid
            if os.path.isfile(_file):
                source = Source('ip-file', [_file])
                blocklist |= source.process_data()

    #> -----------------------------------------------------------------------------
    # External sources -- Hostname file(s)
    if args.hostname_file:
        for _file in args.hostname_file:
            # Make sure the file is valid
            if os.path.isfile(_file):
                source = Source('hostname-file', [_file])
                blocklist |= source.process_data()

    #> -----------------------------------------------------------------------------
    # External sources -- User-Agents file(s)
    if args.useragent_file:
        for _file in args.useragent_file:
            # Make sure the file is valid
            if os.path.isfile(_file):
                source = Source('useragent-file', [_file])
                blocklist |= source.process_data()

    #> -----------------------------------------------------------------------------
    # External sources -- ASN file(s)
    if args.asn_file:
        for _file in args.asn_file:
            # Make sure the file is valid
            if os.path.isfile(_file):
                source = Source(
                    'asn-file', [_file, excludes, http_headers, args.timeout])
                blocklist |= source.process_data()

    print("\n[+]\tFile/Path redirection and catch-all examples commented at bottom of file.\n")

    output_obj = Apache if args.apache else Satellite
    write_output = output_obj(args.output)
    write_output(args, blocklist)

    elapsed = time.perf_counter() - start
    print(f"\n{__file__} executed in {elapsed:0.2f} seconds.")
