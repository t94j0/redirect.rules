#!/usr/bin/env python3

import os
import re
from datetime import datetime

# Import static data
from core.support import REWRITE

# Import parent class
from core.base import Base


class IP(Base):
    """
    Class to write static list of IPs that were obtained
    via Malware Kits and other sources located in core/static/ips.txt

    :param workingfile: Open file object where rules are written
    :param ip_list:     List of seen IPs
    """

    def __init__(self, workingfile, ip_list):
        self.workingfile = workingfile
        self.ip_list     = ip_list

        self.return_data = self._process_source()


    def _get_source(self):
        # Read in static source file from static/ dir
        ips = []
        pwd = os.path.dirname(os.path.realpath(__file__))
        with open(pwd + '/../static/ips.txt', 'r') as _file:
            for line in _file.readlines():
                line = line.strip()
                if line != '' and not line.startswith('#'):
                    ips.append(line)

        return ips


    def _process_source(self):
        try:
            # Get the source data
            ips = self._get_source()
        except:
            return self.ip_list

        # Add IPs obtained via Malware Kit's and other sources
        print("[*]\tAdding static IPs obtained via Malware Kit's and other sources...")
        # self.workingfile.write("\n\n\t# IPs obtained via Malware Kit's and other sources: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

        def fix_ip(ip):
            # Convert /31 and /32 CIDRs to single IP
            ip = re.sub('/3[12]', '', ip)

            # Convert lower-bound CIDRs into /24 by default
            # This is assmuming that if a portion of the net
            # was seen, we want to avoid the full netblock
            ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)
            return ip

        new_ips = [ fix_ip(ip) for ip in ips if ip != '' ]
        return [*self.ip_list, *new_ips]
