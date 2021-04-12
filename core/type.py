from typing import NamedTuple, Set


class Block(NamedTuple):
    '''
    Holds the ips, hosts, and user agents for blocklisting. Provides a helper
    function to merge two block lists
    
    Use sets to remove duplicates
    '''

    ips: Set[str] = set()
    hosts: Set[str] = set()
    agents: Set[str] = set()

    def __or__(self, x):
        return Block(
            self.ips | x.ips,
            self.hosts | x.hosts,
            self.agents | x.agents
        )

    def to_list(self):
        return list(self.ips), list(self.hosts), list(self.agents)
