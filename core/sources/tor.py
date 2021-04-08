#!/usr/bin/env python3

import re
import requests
from datetime import datetime

# Disable request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Import parent class
from core.base import Base


class Tor(Base):
    """
    Add Tor exit nodes: https://check.torproject.org/exit-addresses

    :param workingfile: Open file object where rules are written
    :param headers:     HTTP headers
    :param timeout:     HTTP timeout
    :param ip_list:     List of seen IPs
    """

    def __init__(self, workingfile, headers, timeout, ip_list):
        self.workingfile = workingfile
        self.headers     = headers
        self.timeout     = timeout
        self.ip_list     = ip_list

        self.return_data = self._process_source()


    def _get_source(self):
        # Write comments to working file
        print("[*]\tPulling TOR exit node list...")
        self.workingfile.write("\n\n\t# Live copy of current TOR exit nodes: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

        # Fetch the live Tor exit node list
        tor_ips = requests.get(
            'https://check.torproject.org/exit-addresses',
            headers=self.headers,
            timeout=self.timeout,
            verify=False
        )

        # Decode from a bytes object and split into a list of lines
        return tor_ips.content.decode('utf-8').split('\n')


    def _process_source(self):
        try:
            # Get the source data
            tor_ips = self._get_source()
        except:
            return self.ip_list

        def fix_ip(line):
            ip = line.split(' ')[1]
            # Convert /31 and /32 CIDRs to single IP
            ip = re.sub('/3[12]', '', ip)

            # Convert lower-bound CIDRs into /24 by default
            # This is assmuming that if a portion of the net
            # was seen, we want to avoid the full netblock
            ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)
            return ip

        exit_addresses = (l.strip() for l in tor_ips if 'ExitAddress' in l)
        new_ips = [ fix_ip(line) for line in exit_addresses ]
        return [*self.ip_list, *new_ips]
