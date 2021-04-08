#!/usr/bin/env python3

import os
from datetime import datetime

# Import static data
from core.support import REWRITE

# Import parent class
from core.base import Base


class UserAgents(Base):
    """
    User-Agents class to write static list of User-Agents from
    core/static/agents.py

    :param workingfile: Open file object where rules are written
    :param agent_list:  List of seen User-Agents
    """

    def __init__(self, workingfile, agent_list):
        self.workingfile = workingfile
        self.agent_list  = agent_list

        self.return_data = self._process_source()


    def _get_source(self):
        # Read in static source file from static/ dir
        agents = []
        pwd = os.path.dirname(os.path.realpath(__file__))
        with open(pwd + '/../static/agents.txt', 'r') as _file:
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

        # Add custom User-Agent list
        print("[*]\tAdding conditions for bad User-Agents...")
        # self.workingfile.write("\n\n\t# Bad User Agents: %s\n" % datetime.now().strftime("%Y%m%d-%H:%M:%S"))
        # self.workingfile.write("\t# Sources via: %s & %s\n" % ('@curi0usJack/@violentlydave', 'Obtained via Malware Kit'))

        new_agents = [a for a in agents if a != '']

        return [*self.agent_list, *new_agents]
