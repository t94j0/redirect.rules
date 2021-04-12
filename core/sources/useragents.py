#!/usr/bin/env python3

from typing import List
import os
from datetime import datetime

# Import static data
from core.support import REWRITE

# Import parent class
from core.base import Base
from core.type import Block


class UserAgents(Base):
    """
    User-Agents class to write static list of User-Agents from
    core/static/agents.py
    """

    def __init__(self):
        self.return_data = self._process_source()

    def _get_source(self) -> List[str]:
        # Read in static source file from static/ dir
        agents = []
        pwd = os.path.dirname(os.path.realpath(__file__))
        with open(pwd + '/../static/agents.txt', 'r') as _file:
            for line in _file.readlines():
                line = line.strip()
                if line != '' and not line.startswith('#'):
                    agents.append(line)

        return agents

    def _process_source(self) -> Block:
        try:
            # Get the source data
            agents = self._get_source()
        except:
            return Block()

        # Add custom User-Agent list
        print("[*]\tAdding conditions for bad User-Agents...")
        new_agents = {a for a in agents if a != ''}
        return Block(agents=new_agents)
