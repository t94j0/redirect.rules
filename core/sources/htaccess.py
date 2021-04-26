#!/usr/bin/env python3

import os
from yaml import load, Loader
from core.type import Block
from core.support import REWRITE
from core.base import Base
from typing import List, Set
import re
import requests
from datetime import datetime

# Disable request warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class HTAccess(Base):
    """
    HTAccess class to pull and write @curi0usJack's .htaccess source file
    https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10
    Current link as of: March 27, 2020

    :param headers:     HTTP headers
    :param timeout:     HTTP timeout
    :param ip_list:     List of seen IPs
    :param agent_list:  List of seen User-Agents
    :param args:        Command line args
    """

    def __init__(self, headers, timeout, args):
        self.headers = headers
        self.timeout = timeout
        self.args = args

        self.return_data = self._process_source()

    def _get_source(self) -> str:
        print("[*]\tPulling @curi0usJack's redirect rules...")

        pwd = os.path.dirname(os.path.realpath(__file__))
        with open(pwd + '/../static/htaccess.yml', 'r') as _file:
            return _file.read()

    def _process_source(self) -> Block:
        try:
            # Get the source data
            htaccess_file = self._get_source()
        except:
            return Block()

        exclude = self.args.exclude

        ips_list: Set[str] = set()
        htaccess = load(htaccess_file, Loader=Loader)
        for name, obj in htaccess['ips'].items():
            names = name.split('_')
            no_add = any(n in exclude for n in names)
            if not no_add:
                ips_list |= set(obj)

        agent_list = set(htaccess['useragents'])

        return Block(ips=ips_list, agents=agent_list)
