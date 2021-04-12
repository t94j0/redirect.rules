#!/usr/bin/env python3

from typing import List
import os
import re
from datetime import datetime

# Import static data
from core.support import REWRITE

# Import parent class
from core.base import Base
from core.sources.utils import fix_ip
from core.type import Block


class IP(Base):
    """
    Class to write static list of IPs that were obtained
    via Malware Kits and other sources located in core/static/ips.txt

    :param ip_list:     List of seen IPs
    """

    def __init__(self):
        self.return_data = self._process_source()

    def _get_source(self) -> List[str]:
        # Read in static source file from static/ dir
        ips = []
        pwd = os.path.dirname(os.path.realpath(__file__))
        with open(pwd + '/../static/ips.txt', 'r') as _file:
            for line in _file.readlines():
                line = line.strip()
                if line != '' and not line.startswith('#'):
                    ips.append(line)

        return ips

    def _process_source(self) -> Block:
        try:
            # Get the source data
            ips = self._get_source()
        except:
            return Block()

        # Add IPs obtained via Malware Kit's and other sources
        print("[*]\tAdding static IPs obtained via Malware Kit's and other sources...")
        new_ips = {fix_ip(ip) for ip in ips if ip != ''}
        return Block(ips=new_ips)
