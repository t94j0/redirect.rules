#!/usr/bin/env python3

import re
import requests
import subprocess
from datetime import datetime

# Disable request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Import static data
from core.support import REWRITE
from core.sources.asn import get_ips_bgpview, get_ips_radb

# Import parent class
from core.base import Base


class IPFile(Base):
    """
    Add external IP file(s)

    :param workingfile: Open file object where rules are written
    :param _file:       File to be parsed
    :param ip_list:     List of seen IPs
    """

    def __init__(self, workingfile, _file, ip_list):
        self.workingfile = workingfile
        self._file       = _file
        self.ip_list     = ip_list

        self.return_data = self._process_source()


    def _get_source(self):
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
            return self.ip_list

        # Write comments to working file
        print("[*]\tParsing external source: %s..." % self._file)

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



class HostnameFile(Base):
    """
    Add external hostname file(s)

    :param workingfile: Open file object where rules are written
    :param _file:       File to be parsed
    :param host_list:   List of seen Hosts
    """

    def __init__(self, workingfile, _file, host_list):
        self.workingfile = workingfile
        self._file       = _file
        self.host_list   = host_list

        self.return_data = self._process_source()


    def _get_source(self):
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
            return self.host_list

        # Write comments to working file
        print("[*]\tParsing external source: %s..." % self._file)
        self.workingfile.write("\n\n\t# External source - %s: %s\n" % (self._file, datetime.now().strftime("%Y%m%d-%H:%M:%S")))

        new_hosts = [ h for h in hostnames if h != '' ]
        return [*self.host_list, *new_hosts]



class UserAgentFile(Base):
    """
    Add external User-Agent file(s)

    :param workingfile: Open file object where rules are written
    :param _file:       File to be parsed
    :param agent_list:  List of seen User-Agents
    """

    def __init__(self, workingfile, _file, agent_list):
        self.workingfile = workingfile
        self._file       = _file
        self.agent_list  = agent_list

        self.return_data = self._process_source()


    def _get_source(self):
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
            return self.agent_list

        # Write comments to working file
        print("[*]\tParsing external source: %s..." % self._file)
        new_agents = [a for a in agents if a != '']
        return [*self.agent_list, *new_agents]


class ASNFile(Base):
    """
    Add external ASN file(s)
    via whois.radb.net and BGPView

    :param workingfile: Open file object where rules are written
    :param _file:       File to be parsed
    :param ip_list:     List of seen IPs
    """

    def __init__(self, workingfile, _file, ip_list):
        self.workingfile = workingfile
        self._file       = _file
        self.ip_list     = ip_list

        self.return_data = self._process_source()


    def _get_source(self):
        # Read in static source file from static/ dir
        asn_list = []
        with open(self._file, 'r') as _file:
            for line in _file.readlines():
                line = line.strip()
                if line != '' and not line.startswith('#'):
                    asn_list.append(line)

        return asn_list


    def _get_data(self, asn):
        asn_data = requests.get(
            'https://api.bgpview.io/asn/%s/prefixes' % asn[1],
            headers=self.headers,
            timeout=self.timeout,
            verify=False
        )

        # Return JSON object
        return asn_data.json()


    def _process_source(self):
        try:
            # Get the source data
            asn_list = self._get_source()
        except:
            return self.ip_list

        asn_list = [x.upper() for x in asn_list]
        new_ips_radb = get_ips_radb(asn_list, self.args.exclude)
        new_ips_bgpview = get_ips_bgpview(asn_list, self.args.exclude, self._get_data)
        return [*self.ip_list, *new_ips_radb, *new_ips_bgpview]
