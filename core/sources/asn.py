#!/usr/bin/env python3

from typing import List
import os
import re
import requests
import subprocess
from datetime import datetime

# Disable request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Import static data
from core.support import REWRITE

# Import parent class
from core.base import Base


def get_ips_radb(asn_list: List[str], exclude: str):
    asn_list = [x.upper() for x in asn_list]

    def fix_ip(ip):
        # Convert /31 and /32 CIDRs to single IP
        ip = re.sub('/3[12]', '', ip)

        # Convert lower-bound CIDRs into /24 by default
        # This is assmuming that if a portion of the net
        # was seen, we want to avoid the full netblock
        ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)
        return ip

    def get_whois(asn):
        # Unfortunately here, it seems we must use subprocess as some
        # whois libraries were acting funky...
        whois_cmd  = 'whois -h whois.radb.net -- -i origin %s | grep "route:" | awk \'{print $2}\'' % (asn)
        whois_data = subprocess.check_output(whois_cmd, shell=True).decode('utf-8')
        return whois_data

    new_ips = []
    for as_ in asn_list:
        if any(x.upper() in as_ for x in exclude):
            continue  # Skip ASN if excluded

        [name, asn] = as_.split('_')

        print(f"[*]\tPulling {asn} -- {name} via RADB...")
        whois_data = get_whois(asn)

        for ip in whois_data.split('\n'):
            ip = fix_ip(ip)
            if ip != '':
                new_ips.append(ip)

    return new_ips

def get_ips_bgpview(asn_list, exclude, get_data):
    asn_list = [x.upper() for x in asn_list]

    def fix_ip(ip):
        # Convert /31 and /32 CIDRs to single IP
        ip = re.sub('/3[12]', '', ip)

        # Convert lower-bound CIDRs into /24 by default
        # This is assmuming that if a portion of the net
        # was seen, we want to avoid the full netblock
        ip = re.sub('\.[0-9]{1,3}/(2[456789]|30)', '.0/24', ip)
        return ip

    new_ips = []
    for as_ in asn_list:
        if any(x.upper() in as_ for x in exclude):
            continue  # Skip ASN if excluded

        [name, asn] = as_.split('_')

        try:
            asn_data = get_data(asn)
        except:
            continue

        # Write comments to working file
        print("[*]\tPulling %s -- %s via BGPView..." % (asn, name))

        try:
            for network in asn_data['data']['ipv4_prefixes']:
                ip = fix_ip(network['prefix'])
                if ip != '':
                    new_ips.append(ip)
        except KeyError:
            pass
    return new_ips

class RADB(Base):
    """
    Add companies by ASN - via whois.radb.net

    :param workingfile: Open file object where rules are written
    :param ip_list:     List of seen IPs
    :param args:        Command line args
    """

    def __init__(self, workingfile, ip_list, args):
        self.workingfile = workingfile
        self.ip_list     = ip_list
        self.args        = args

        self.return_data = self._process_source()


    def _get_source(self):
        # Read in static source file from static/ dir
        asn_list = []
        pwd = os.path.dirname(os.path.realpath(__file__))
        with open(pwd + '/../static/asns.txt', 'r') as _file:
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
            return self.ip_list

        new_ips = get_ips_radb(asn_list, self.args.exclude)
        return [*self.ip_list, *new_ips]



class BGPView(Base):
    """
    Add companies by ASN - via BGPView

    :param workingfile: Open file object where rules are written
    :param headers:     HTTP headers
    :param timeout:     HTTP timeout
    :param ip_list:     List of seen IPs
    :param args:        Command line arguments
    """

    def __init__(self, workingfile, headers, timeout, ip_list, args):
        self.workingfile = workingfile
        self.headers     = headers
        self.timeout     = timeout
        self.ip_list     = ip_list
        self.args        = args

        self.return_data = self._process_source()


    def _get_source(self):
        # Read in static source file from static/ dir
        asn_list = []
        pwd = os.path.dirname(os.path.realpath(__file__))
        with open(pwd + '/../static/asns.txt', 'r') as _file:
            for line in _file.readlines():
                line = line.strip()
                if line != '' and not line.startswith('#'):
                    asn_list.append(line)

        return asn_list


    def _get_data(self, asn):
        asn_data = requests.get(
            'https://api.bgpview.io/asn/%s/prefixes' % asn,
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

        new_ips = get_ips_bgpview(asn_list, self.args.exclude, self._get_data)
        return [*self.ip_list, *new_ips]
