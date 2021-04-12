#!/usr/bin/env python3

from core.type import Block
from core.sources.utils import fix_ip
from core.base import Base
from core.sources.asn import get_ips_bgpview, get_ips_radb
from core.support import REWRITE
from typing import List
import re
import requests
import subprocess
from datetime import datetime

# Disable request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Import static data

# Import parent class


class IPFile(Base):
    """
    Add external IP file(s)

    :param _file:       File to be parsed
    """

    def __init__(self, _file):
        self._file = _file
        self.return_data = self._process_source()

    def _get_source(self) -> List[str]:
        # Read in static source file from static/ dir
        ips = []
        with open(self._file, 'r') as _file:
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
            return Block()

        print("[*]\tParsing external source: %s..." % self._file)
        new_ips = {fix_ip(ip) for ip in ips if ip != ''}
        return Block(ips=new_ips)


class HostnameFile(Base):
    """
    Add external hostname file(s)

    :param _file:       File to be parsed
    """

    def __init__(self, _file):
        self._file = _file

        self.return_data = self._process_source()

    def _get_source(self) -> List[str]:
        # Read in static source file from static/ dir
        hostnames = []
        with open(self._file, 'r') as _file:
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
            return Block()

        print("[*]\tParsing external source: %s..." % self._file)
        new_hosts = {h for h in hostnames if h != ''}
        return Block(hosts=new_hosts)


class UserAgentFile(Base):
    """
    Add external User-Agent file(s)

    :param _file:       File to be parsed
    """

    def __init__(self, _file):
        self._file = _file
        self.return_data = self._process_source()

    def _get_source(self) -> List[str]:
        # Read in static source file from static/ dir
        agents = []
        with open(self._file, 'r') as _file:
            for line in _file.readlines():
                line = line.strip()
                if line != '' and not line.startswith('#'):
                    agents.append(line)

        return agents

    def _process_source(self):
        try:
            # Get the source data
            agents = self._get_source()
        except:
            return Block()

        print("[*]\tParsing external source: %s..." % self._file)
        new_agents = {a for a in agents if a != ''}
        return Block(agents=new_agents)


class ASNFile(Base):
    """
    Add external ASN file(s)
    via whois.radb.net and BGPView

    :param _file:       File to be parsed
    :param headers:       Headers for request
    :param timeout:       HTTP timeout
    """

    def __init__(self, _file, excludes, headers, timeout):
        self._file = _file
        self.headers = headers
        self.timeout = timeout
        self.return_data = self._process_source()

    def _get_source(self) -> List[str]:
        # Read in static source file from static/ dir
        asn_list = []
        with open(self._file, 'r') as _file:
            for line in _file.readlines():
                line = line.strip()
                if line != '' and not line.startswith('#'):
                    asn_list.append(line)

        return asn_list

    def _process_source(self):
        try:
            # Get the source data
            asn_list = self._get_source()
        except:
            return Block()

        asn_list = [x.upper() for x in asn_list]
        ips = get_ips_radb(asn_list, self.excludes) | get_ips_bgpview(
            asn_list, self.excludes, self.headers, self.timeout)
        return Block(ips=ips)
