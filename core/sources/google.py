#!/usr/bin/env python3

import re
import requests
import dns.resolver
from datetime import datetime

# Disable request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Import static data
from core.support import REWRITE

# Import parent class
from core.base import Base


class GoogleCloud(Base):
    """
    Add GoogleCloud IPs: dig txt _cloud-netblocks.googleusercontent.com

    :param workingfile: Open file object where rules are written
    :param ip_list:     List of seen IPs
    """

    def __init__(self, workingfile, ip_list):
        self.workingfile = workingfile
        self.ip_list     = ip_list
        self.resolver    = dns.resolver.Resolver()

        self.return_data = self._process_source()


    def _get_source(self):
        # Write comments to working file
        print("[*]\tPulling Google Cloud IP/network list...")
        self.workingfile.write("\n\n\t# Live copy of GoogleCloud IP space: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

        # Create our own resolver to force a DNS server in case routing
        # defaults cause an issue
        # https://stackoverflow.com/a/5237068
        self.resolver.nameservers = ['8.8.8.8']
        google_netblocks = self.resolver.query('_cloud-netblocks.googleusercontent.com', 'txt')
        # https://stackoverflow.com/a/11706378
        google_netblocks = google_netblocks.response.answer[0][0].strings[0].decode('utf-8')

        return google_netblocks


    def _process_source(self):
        try:
            # Get the source data
            google_netblocks = self._get_source()
        except:
            return self.ip_list


        def fix_ip(ip):
            # Convert /31 and /32 CIDRs to single IP
            ip = re.sub('/3[12]', '', ip)

            # Convert lower-bound CIDRs into /24 by default
            # This is assmuming that if a portion of the net
            # was seen, we want to avoid the full netblock
            ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)
            return ip


        def get_netblock_ip(block):
            if 'ip4' not in block:
                return ''
            ip = block.split(':')[-1]
            ip = fix_ip(ip)
            if ip == '':
                return ''
            return ip

        def flatten(xs):
            return [item for sublist in xs for item in sublist]


        def pull_netblock(netblock):
            # Query each GoogleCloud netblock
            netblock_ips = self.resolver.query(netblock, 'txt')
            netblock_ips = netblock_ips.response.answer[0][0].strings[0].decode('utf-8')
            ips_gen = ( get_netblock_ip(block) for block in netblock_ips.split(' ') )
            return [ l for l in ips_gen if l != '']

        # Get netblocks
        netblocks = (n.split(':')[-1] for n in google_netblocks.split(' ') if 'include' in n)
        # Pull and parse IPs from netblock
        new_ips = flatten([pull_netblock(nb) for nb in netblocks])

        return [*self.ip_list, *new_ips]
