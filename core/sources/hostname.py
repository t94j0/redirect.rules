#!/usr/bin/env python3

from typing import List
import os
import re
from datetime import datetime

# Import parent class
from core.base import Base
from core.type import Block


class Hostname(Base):
    """
    Class to write static list of Hostnames that were obtained
    via Malware Kits and other sources located in core/static/hostnames.txt
    """

    def __init__(self):
        self.return_data = self._process_source()

    def _get_source(self) -> List[str]:
        # Read in static source file from static/ dir
        hostnames = []
        pwd = os.path.dirname(os.path.realpath(__file__))
        with open(pwd + '/../static/hostnames.txt', 'r') as _file:
            for line in _file.readlines():
                line = line.strip()
                if line != '' and not line.startswith('#'):
                    hostnames.append(line)

        return hostnames

    def _process_source(self) -> Block:
        try:
            # Get the source data
            hostnames = self._get_source()
        except:
            return Block()

        # Add IPs obtained via Malware Kit's and other sources
        print(
            "[*]\tAdding static Hostnames obtained via Malware Kit's and other sources...")
        return Block(hosts={h for h in hostnames if h != ''})
