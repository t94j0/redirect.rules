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


class Misc(Base):
    """
    Misc sources -- see static/misc.txt for reasons
    """

    def __init__(self):
        self.return_data = self._process_source()

    def _get_source(self) -> List[str]:
        # Read in static source file from static/ dir
        misc_list = []
        pwd = os.path.dirname(os.path.realpath(__file__))
        with open(pwd + '/../static/misc.txt', 'r') as _file:
            for line in _file.readlines():
                line = line.strip()
                if line != '' and not line.startswith('#'):
                    misc_list.append(line)

        return misc_list

    def _process_source(self):
        try:
            # Get the source data
            misc_list = self._get_source()
        except:
            return Block()

        print("[*]\tAdding Miscellaneous Sources...")
        ips_gen = (fix_ip(o.split('-')[0]) for o in misc_list)
        new_ips = {ip for ip in ips_gen if ip != ''}
        return Block(ips=new_ips)
