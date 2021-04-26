from typing import List
from yaml import dump

from core.output.output import Output
from core.type import Block


class Satellite(Output):
    def __init__(self, path: str):
        super(Satellite, self).__init__(path)

    def __call__(self, args, block: Block):
        ips, _, agents = block.to_list()
        # hosts is not implemented yet
        out = {
            'blacklist_iprange': ips,
            'blacklist_useragents': agents,
            'on_failure': {'redirect': args.destination}
        }
        self.write(dump(out))
