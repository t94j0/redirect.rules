#!/usr/bin/env python3

import os
import re
from datetime import datetime

# Import parent class
from core.base import Base


class Hostname(Base):
    """
    Class to write static list of Hostnames that were obtained
    via Malware Kits and other sources located in core/static/hostnames.txt

    :param workingfile: Open file object where rules are written
    :param host_list:   List of seen Hosts
    """

    def __init__(self, workingfile, host_list):
        self.workingfile = workingfile
        self.host_list   = host_list

        self.return_data = self._process_source()


    def _get_source(self):
        # Read in static source file from static/ dir
        hostnames = []
        pwd = os.path.dirname(os.path.realpath(__file__))
        with open(pwd + '/../static/hostnames.txt', 'r') as _file:
            for line in _file.readlines():
                line = line.strip()
                if line != '' and not line.startswith('#'):
                    hostnames.append(line)

        return hostnames


    def _process_source(self):
        try:
            # Get the source data
            hostnames = self._get_source()
        except:
            return self.host_list

        # Add IPs obtained via Malware Kit's and other sources
        print("[*]\tAdding static Hostnames obtained via Malware Kit's and other sources...")
        # self.workingfile.write("\n\n\t# Hostnames obtained via Malware Kit's and other sources: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))

        new_hosts = [ h for h in hostnames if h != '' ]
        # self.workingfile.write("\t# Hostname Count: %d\n" % count)

        return [*self.host_list, *new_hosts]
