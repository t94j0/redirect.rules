from typing import List

from core.output.output import Output
from core.type import Block


class Apache(Output):
    def __init__(self, path: str):
        super(Apache, self).__init__(path)

    def __call__(self, args, block: Block) -> None:
        ips, hosts, agents = block.to_list()
        #> ----------------------------------------------------------------------------
        # Initialize redirect.rules file
        # Add header comments to the redirect.rules file headers
        self.add_comment("\n")
        self.add_comment("\n\n")

        # Add updated/modified comments from @curi0usJack's .htaccess
        self.add_comment(" Note: This currently requires Apache 2.4+\n")
        self.add_comment("\n")
        self.add_comment(" Example Usage:\n")
        self.add_comment(" Save file as /etc/apache2/redirect.rules\n")
        self.add_comment(
            " Within your site's Apache conf file (in /etc/apache2/sites-avaiable/),\n")
        self.add_comment(" put the following statement near the bottom:\n")
        self.add_comment(" \tInclude /etc/apache2/redirect.rules\n")
        self.add_comment("\n\n")

        # Add a note to the user to keep the protocol used when setting the redirect target
        self.add_comment("\n")
        self.add_comment(
            " If modifying the 'REDIR_TARGET' value, please ensure to include the protocol\n")
        self.add_comment(
            " e.g. https://google.com OR http://my.domain/test.txt\n")
        self.add_comment("\n")

        self.write_redirect_header(args.destination)
        self.write_ip_rules(ips, len(hosts) == 0)
        self.write_agent_rules(hosts, len(agents) == 0)
        self.write_host_rules(agents, True)

        #> -----------------------------------------------------------------------------
        # Rule clean up and file finalization

        # Now that we have written the sink-hole rules, let's add some example rules for
        # the user to reference/use for file/path handling and a catch-all redirection

        # Handle redirection of a file/path to its final file/path destination
        self.add_comment(
            " Redirect a file/path to a target backend file/path\n")
        self.add_comment(
            " -> Example: Redirect displayed path to raw path to grab 'example.zip'\n")
        self.add_comment(
            " -> Note: This should come after all IP/Host/User-Agent blacklisting\n\n")
        self.add_comment(
            " RewriteRule\t\t\t\t^/test/files/example.zip(.*)$\t\t/example.zip\t[L,R=302]\n\n")

        # Handle redirection for a file/path to another server
        self.add_comment(
            " Redirect and proxy a file/path to another system's file/path\n")
        self.add_comment(
            " -> Example: Redirect and proxy displayed path to another system via the same path\n")
        self.add_comment(
            " -> Note: You can also specify the URI explicitly as needed\n")
        self.add_comment(
            " -> Note: This should come after all IP/Host/User-Agent blacklisting\n\n")
        self.add_comment(
            " RewriteRule\t\t\t\t^/test/files/example.zip(.*)$\t\thttps://192.168.10.10%{REQUEST_URI}\t[P]\n\n")

        # Create a final, catch-all redirection
        self.add_comment(" Catch-all redirect\n")
        self.add_comment(
            " -> Example: Catch anything other than '/example.zip' and redirect\n")
        self.add_comment(
            " -> Note: This should be the last item in the redirect.rules file as a final catch-all\n\n")
        self.add_comment(
            " RewriteRule\t\t\t\t^((?!\\/example\\.zip).)*$\t\t${REDIR_TARGET}\t[L,R=302]\n")

    def add_comment(self, comment: str) -> None:
        self.write(f'\t#{comment}')

    def write_redirect_header(self, destination: str) -> None:
        self.write(f"\tDefine REDIR_TARGET {destination}\n\n")
        self.write("\tRewriteEngine On\n")
        self.write("\tRewriteOptions Inherit\n\n")

    def write_ip_rules(self, ips: List[str], end=False) -> None:
        if len(ips) == 0:
            return
        if end:
            for ip in ips[:-1]:
                self.write(
                    f'RewriteCond\t\t\t\texpr\t\t\t\t\t"-R \'{ip}\'"\t[OR]\n')
            self.write(
                f'RewriteCond\t\t\t\texpr\t\t\t\t\t"-R \'{ips[-1]}\'"\n')
        else:
            for ip in ips:
                self.write(
                    f'RewriteCond\t\t\t\texpr\t\t\t\t\t"-R \'{ip}\'"\t[OR]\n')

    def write_agent_rules(self, agents: List[str], end=False) -> None:
        if len(agents) == 0:
            return
        if end:
            for agent in agents[:-1]:
                self.write(
                    f'RewriteCond\t\t\t\t%{{HTTP_USER_AGENT}}\t\t\t\t\t{agent}\t[OR]\n')
            self.write(
                f'RewriteCond\t\t\t\t%{{HTTP_USER_AGENT}}\t\t\t\t\t{agents[-1]}\n')
        else:
            for agent in agents:
                self.write(
                    f'RewriteCond\t\t\t\t%{{HTTP_USER_AGENT}}\t\t\t\t\t{agent}\t[OR]\n')

    def write_host_rules(self, hosts: List[str], end=False) -> None:
        if len(hosts) == 0:
            return
        if end:
            for host in hosts[:-1]:
                self.write(
                    f'RewriteCond\t\t\t\t%{{HTTP_HOST}}\t\t\t\t\t{host}\t[OR]\n')
            self.write(
                f'RewriteCond\t\t\t\t%{{HTTP_HOST}}\t\t\t\t\t{hosts[-1]}\n')
        else:
            for host in hosts:
                self.write(
                    f'RewriteCond\t\t\t\t%{{HTTP_HOST}}\t\t\t\t\t{host}\t[OR]\n')

    def write_rewrite_rule(self) -> None:
        self.write(
            'RewriteRule\t\t\t\t^.*$\t\t\t\t\t${REDIR_TARGET}\t[L,R=302]\n')
