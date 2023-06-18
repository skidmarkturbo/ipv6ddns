"""Command line interface for ipv6ddns
"""
import argparse
from ipv6ddns.plugin import PluginManager, PluginType


class Cli:
    """Command line interface entry for ipv6ddns
    """

    def __init__(self) -> None:
        self.args = {}
        self.plugin_manager = PluginManager()
        self.plugin_manager.discover()

    def execute(self, arg_list = None):
        """Execute commands

        Args:
            arg_list (list, optional): List of command line arguments. Defaults to None.
        """

    def execute_ctx(self, ctx):
        """Executes a given context instance. One context instance corresponds
        to all operations needed for DDNS of single host machine

        Args:
            ctx (_type_): the context to execute
        """

    def _parse_args(self):
        """Parse cli arguments
        """

    def _get_root_parser(self):
        """build the root parser and return it
        """
        parser = argparse.ArgumentParser(
            prog=__package__,
            description="DDNS cli for updating IPV6 addresses",
            add_help=False
        )

        #
        # Common Options
        #
        parser.add_argument(
            "-h",
            "--help",
            action='store_true',
            required=False,
            help="Show help and usage"
        )

        parser.add_argument(
            "-y",
            "--assume-yes",
            action='store_true',
            required=False,
            help="Run in non-interactive mode. Don't ask for human input or confirmations."
        )

        #
        # DNS Options
        #
        parser.add_argument(
            "--dns",
            action='store',
            default=PluginManager.PLUGIN_NAME_NOOP,
            help='Name of the DNS plugin to use. Default is no-op plugin,'\
                ' which does not do anything.',
            choices=self.plugin_manager.get_plugin_names(PluginType.DNS)
        )

        parser.add_argument(
            "-d",
            "--domain",
            action='append',
            required=False,
            help="Domain names to update. Use multiple times to add multiple domains."\
                " If no domain names are provided no DNS update is made."
        )

        #
        # Firewall Options
        #
        parser.add_argument(
            "--firewall",
            action='store',
            default=PluginManager.PLUGIN_NAME_NOOP,
            help='Name of the Firewall plugin to use. Default is no-op plugin,'\
                ' which does not do anything.',
            choices=self.plugin_manager.get_plugin_names(PluginType.FIREWALL)
        )

        parser.add_argument(
            "-t",
            "--tcp-port",
            action='append',
            required=False,
            help="TCP ports to open on firewall. Use multiple times to add multiple ports."\
                " If no TCP ports are provided, then none are opened. And ports opened using"\
                " previous runs are removed."
        )

        parser.add_argument(
            "-u",
            "--udp-port",
            action='append',
            required=False,
            help="UDP ports to open on firewall. Use multiple times to add multiple ports."\
                " If no UPD ports are provided, no ports are opened. And ports opened using"\
                " previous runs are removed."
        )

        parser.add_argument(
            "--hostname",
            action='store',
            required=False,
            help="Hostname identifier for the target host. Used for firewall entry identifiers"
        )

        return parser
