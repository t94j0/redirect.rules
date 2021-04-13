#!/usr/bin/env python3

from multiprocessing import Pool
from core.type import Block
from functools import reduce
from core.sources.utils import fix_ip
from core.base import Base
from core.support import REWRITE
from typing import List, Set
import os
import re
import requests
import subprocess
from datetime import datetime

# Disable request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Import static data

# Import parent class


class RADBProcessor:
    def __init__(self, exclude):
        self.exclude = exclude

    def _get_whois(self, asn):
        # Unfortunately here, it seems we must use subprocess as some
        # whois libraries were acting funky...
        whois_cmd = 'whois -h whois.radb.net -- -i origin %s | grep "route:" | awk \'{print $2}\'' % (
            asn)
        whois_data = subprocess.check_output(
            whois_cmd, shell=True).decode('utf-8')
        return whois_data

    def __call__(self, as_) -> Set[str]:
        new_ips: Set[str] = set()

        if any(x.upper() in as_ for x in self.exclude):
            return set()
        [name, asn] = as_.split('_')

        print(f"[*]\tPulling {asn} -- {name} via RADB...")
        try:
            whois_data = self._get_whois(asn)
            for ip in whois_data.split('\n'):
                ip = fix_ip(ip)
                if ip != '':
                    new_ips.add(ip)
        except:
            pass
        return new_ips


class BGPViewProcessor:
    def __init__(self, exclude, headers, timeout):
        self.exclude = exclude
        self.headers = headers
        self.timeout = timeout

    def _get_bgpview(self, asn):
        return requests.get(
            'https://api.bgpview.io/asn/%s/prefixes' % asn,
            headers=self.headers,
            timeout=self.timeout,
            verify=False
        ).json()

    def __call__(self, as_) -> Set[str]:
        if any(x.upper() in as_ for x in self.exclude):
            return set()
        [name, asn] = as_.split('_')

        print("[*]\tPulling %s -- %s via BGPView..." % (asn, name))
        new_ips: Set[str] = set()
        try:
            asn_data = self._get_bgpview(asn)
            for network in asn_data['data']['ipv4_prefixes']:
                ip = fix_ip(network['prefix'])
                if ip != '':
                    new_ips.add(ip)
        except:
            pass
        return new_ips


def _get_ips_asn(threads: int, asn_list, processor) -> Set[str]:
    asn_list = [x.upper() for x in asn_list]
    with Pool(threads) as p:
        asns = p.map(processor, asn_list)
    return reduce(lambda a, b: a | b, asns)


def get_ips_bgpview(asn_list, threads: int, exclude, headers, timeout) -> Set[str]:
    processor = BGPViewProcessor(exclude, headers, timeout)
    return _get_ips_asn(threads, asn_list, processor)


def get_ips_radb(asn_list, threads: int, exclude) -> Set[str]:
    processor = RADBProcessor(exclude)
    return _get_ips_asn(threads, asn_list, processor)


class RADB(Base):
    """
    Add companies by ASN - via whois.radb.net

    :param args:        Command line args
    :param excludes:    List of exclusions
    """

    def __init__(self, args, excludes):
        self.args = args
        self.excludes = excludes
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

    def _process_source(self) -> Block:
        try:
            # Get the source data
            asn_list = self._get_source()
        except:
            return Block()

        new_ips = get_ips_radb(asn_list, self.args.threads, self.excludes)
        return Block(ips=new_ips)


class BGPView(Base):
    """
    Add companies by ASN - via BGPView

    :param headers:     HTTP headers
    :param timeout:     HTTP timeout
    :param args:        Command line arguments
    """

    def __init__(self, headers, timeout, args):
        self.headers = headers
        self.timeout = timeout
        self.args = args

        self.return_data = self._process_source()

    def _get_source(self) -> List[str]:
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
            return Block()

        new_ips = get_ips_bgpview(
            asn_list, self.args.threads, self.args.exclude, self.headers, self.timeout)
        return Block(ips=new_ips)
