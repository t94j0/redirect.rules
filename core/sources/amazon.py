#!/usr/bin/env python3

from core.sources.utils import fix_ip
from core.base import Base
from core.support import REWRITE
from core.type import Block
import re
import requests
from datetime import datetime

# Disable request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class AWS(Base):
    """
    Add AWS IPs: https://ip-ranges.amazonaws.com/ip-ranges.json

    :param headers:     HTTP headers
    :param timeout:     HTTP timeout
    """

    def __init__(self, headers, timeout):
        self.headers = headers
        self.timeout = timeout
        self.return_data = self._process_source()

    def _get_source(self):
        # Write comments to working file
        print("[*]\tPulling AWS IP/Network list...")

        aws_ips = requests.get(
            'https://ip-ranges.amazonaws.com/ip-ranges.json',
            headers=self.headers,
            timeout=self.timeout,
            verify=False
        )

        # Return JSON object
        return aws_ips.json()

    def _process_source(self) -> Block:
        try:
            # Get the source data
            aws_ips = self._get_source()
        except:
            return Block()

        ips_raw = (n['ip_prefix'] for n in aws_ips['prefixes'])
        ips = {fix_ip(ip) for ip in ips_raw if ip != ''}
        return Block(ips=ips)
