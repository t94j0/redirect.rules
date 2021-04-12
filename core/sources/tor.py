#!/usr/bin/env python3

from core.type import Block
from core.sources.utils import fix_ip
from core.base import Base
import re
import requests
from datetime import datetime

# Disable request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Import parent class


class Tor(Base):
    """
    Add Tor exit nodes: https://check.torproject.org/exit-addresses

    :param headers:     HTTP headers
    :param timeout:     HTTP timeout
    """

    def __init__(self, headers, timeout):
        self.headers = headers
        self.timeout = timeout

        self.return_data = self._process_source()

    def _get_source(self):
        print("[*]\tPulling TOR exit node list...")
        # Fetch the live Tor exit node list
        tor_ips = requests.get(
            'https://check.torproject.org/exit-addresses',
            headers=self.headers,
            timeout=self.timeout,
            verify=False
        )

        # Decode from a bytes object and split into a list of lines
        return tor_ips.content.decode('utf-8').split('\n')

    def _process_source(self) -> Block:
        try:
            # Get the source data
            tor_ips = self._get_source()
        except:
            return Block()

        exit_lines = (l.strip() for l in tor_ips if 'ExitAddress' in l)
        exit_addresses = (l.split(' ')[1] for l in exit_lines)
        return Block(ips={fix_ip(line) for line in exit_addresses})
