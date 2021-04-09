from typing import List
from yaml import dump

from core.output.output import Output

class Satellite(Output):
    def __init__(self, path: str):
        super(Satellite, self).__init__(path)

    def write_satellite(self, args, ips: List[str], hosts: List[str], agents: List[str]):
        # hosts is not implemented yet
        out = {
            'blacklist_iprange': ips,
            'blacklist_useragents': agents,
            'on_failure': { 'redirect': args.destination }
        }
        self.write(dump(out))
