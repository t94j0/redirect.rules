#!/usr/bin/env python3

import os
import re
from datetime import datetime

# Import static data
from core.support import REWRITE

# Import parent class
from core.base import Base


class Misc(Base):
    """
    Misc sources -- see static/misc.txt for reasons

    :param workingfile: Open file object where rules are written
    :param ip_list:     List of seen IPs
    """

    def __init__(self, workingfile, ip_list):
        self.workingfile = workingfile
        self.ip_list     = ip_list

        self.return_data = self._process_source()


    def _get_source(self):
        # Read in static source file from static/ dir
        misc_list = []
        pwd = os.path.dirname(os.path.realpath(__file__))
        with open(pwd + '/../static/misc.txt', 'r') as _file:
            for line in _file.readlines():
                line = line.strip()
                if line != '' and not line.startswith('#'):
                    misc_list.append(line)

        return misc_list


    def _process_source(self):
        try:
            # Get the source data
            misc_list = self._get_source()
        except:
            return self.ip_list

        print("[*]\tAdding Miscellaneous Sources...")

        def fix_ip(ip):
            # Convert /31 and /32 CIDRs to single IP
            ip = re.sub('/3[12]', '', ip)

            # Convert lower-bound CIDRs into /24 by default
            # This is assmuming that if a portion of the net
            # was seen, we want to avoid the full netblock
            ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)
            return ip

        ips_gen = (fix_ip(o.split('-')[0]) for o in misc_list)
        new_ips = [ ip for ip in ips_gen if ip != '' ]
        return [*self.ip_list, *new_ips]
