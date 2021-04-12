#!/usr/bin/env python3

from core.sources.utils import fix_ip
from core.base import Base
from core.type import Block
from core.support import REWRITE
import re
import requests
from datetime import datetime

# Disable request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Import static data

# Import parent class


class OracleCloud(Base):
    """
    Add Oracle Cloud IPs: https://docs.cloud.oracle.com/en-us/iaas/tools/public_ip_ranges.json

    :param headers:     HTTP headers
    :param timeout:     HTTP timeout
    """

    def __init__(self, headers, timeout):
        self.headers = headers
        self.timeout = timeout

        self.return_data = self._process_source()

    def _get_source(self):
        print("[*]\tPulling Oracle Cloud IP/network list...")
        oracle_networks = requests.get(
            'https://docs.cloud.oracle.com/en-us/iaas/tools/public_ip_ranges.json',
            headers=self.headers,
            timeout=self.timeout,
            verify=False
        )

        # Return JSON object
        return oracle_networks.json()

    def _process_source(self):
        try:
            # Get the source data
            oracle_networks = self._get_source()
        except:
            return Block()

        new_ips: Set[str] = set()
        for region in oracle_networks['regions']:
            for cidr in region['cidrs']:
                ip = fix_ip(cidr['cidr'])
                if ip != '':
                    new_ips.add(ip)

        return Block(ips=new_ips)
