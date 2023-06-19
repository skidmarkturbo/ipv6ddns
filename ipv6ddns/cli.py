"""Command line interface for ipv6ddns
"""
import argparse
import logging
import sys
from ipv6ddns.context import ArgparseContextParser
from ipv6ddns.domain import ValidationError
from ipv6ddns.plugin import PluginManager, PluginType


class Cli:
    """Command line interface entry for ipv6ddns
    """

    def __init__(self, cli_args=None) -> None:
        self.cli_args = cli_args
        self.args = {}
        self.plugin_manager = PluginManager()
        self.plugin_manager.discover()

    def execute(self):
        """Execute commands

        Args:
            arg_list (list, optional): List of command line arguments. Defaults to None.
        """
        contexts = self.get_contexts()
        has_errors = False
        for ctx in contexts:
            errors = self.validate_ctx(ctx)
            if errors:
                has_errors = True
                self._print_errors(errors)
                logging.debug(str(ctx))
        if has_errors:
            sys.exit(3)
        sys.exit(0)

    def get_contexts(self):
        """Parse the cli_args and return the DDNS execution contexts. More
        than one context may be returned in future.
        """
        args = self._parse_args()
        ctx_parser = ArgparseContextParser(self.plugin_manager, args)
        return ctx_parser.parse()

    def validate_ctx(self, ctx):
        """Validate the execution context and return the list of ValidationError

        Args:
            ctx (DDNSContext): ddns execution context

        Returns:
            list[ValidationError]: list of validation errors. return empty if context is valid
        """
        errors = []
        if ctx.common.force and ctx.common.dry_run:
            errors.append(ValidationError("main", "Cannot use --dry-run and --force together."))
        errors = errors + ctx.dns.plugin.validate(ctx)
        errors = errors + ctx.firewall.plugin.validate(ctx)
        errors = errors + ctx.ipv6.plugin.validate(ctx)
        return errors

    def _print_errors(self, errors):
        """Print the errors.

        Args:
            errors (list[ValidationError]): list of validation errors
        """
        for error in errors:
            logging.error("[%s] %s", error.plugin_name, error.message)

    def _parse_args(self):
        """Parse cli arguments
        """
        parser = self._get_root_parser()
        args = parser.parse_args(self.cli_args)

        if args.help:
            self._add_group(parser, self.plugin_manager.dns_plugins[args.dns])
            self._add_group(parser, self.plugin_manager.firewall_plugins[args.firewall])
            self._add_group(parser, self.plugin_manager.ipv6_plugins[args.resolver])
            parser.print_help()
            sys.exit(0)

        self._add_group(parser, self.plugin_manager.dns_plugins[args.dns])
        self._add_group(parser, self.plugin_manager.firewall_plugins[args.firewall])
        self._add_group(parser, self.plugin_manager.ipv6_plugins[args.resolver])

        args = parser.parse_args(self.cli_args)

        return args

    def _add_group(self, parser, plugin):
        group = parser.add_argument_group(plugin.get_title(), plugin.get_description())
        plugin.add_args(group)

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

        parser.add_argument(
            "-f",
            "--force",
            action='store_true',
            required=False,
            help="Force update even if nothing has changed."
        )

        parser.add_argument(
            "--dry-run",
            action='store_true',
            required=False,
            help="Analyze the current configuration (DNS and firewall) and only print the changes."\
                " Don't update anything."
        )

        #
        # DNS Options
        #
        parser.add_argument(
            "--dns",
            action='store',
            default=PluginManager.PLUGIN_NAME_NOOP,
            type=str,
            help='Name of the DNS plugin to use. Default is no-op plugin,'\
                ' which does not do anything.',
            choices=self.plugin_manager.get_plugin_names(PluginType.DNS)
        )

        parser.add_argument(
            "-d",
            "--domain",
            action='append',
            type=str,
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
            type=str,
            help='Name of the Firewall plugin to use. Default is no-op plugin,'\
                ' which does not do anything.',
            choices=self.plugin_manager.get_plugin_names(PluginType.FIREWALL)
        )

        parser.add_argument(
            "-t",
            "--tcp-port",
            action='append',
            type=int,
            required=False,
            help="TCP ports to open on firewall. Use multiple times to add multiple ports."\
                " If no TCP ports are provided, then none are opened. And ports opened using"\
                " previous runs are removed."
        )

        parser.add_argument(
            "-u",
            "--udp-port",
            action='append',
            type=int,
            required=False,
            help="UDP ports to open on firewall. Use multiple times to add multiple ports."\
                " If no UPD ports are provided, no ports are opened. And ports opened using"\
                " previous runs are removed."
        )

        parser.add_argument(
            "--host-id",
            action='store',
            type=str,
            required=False,
            help="Host identifier for the target host. Used for firewall entry identifiers."\
                " Defaults to hostname."
        )

        #
        # IPV6 Resolver Options
        #
        parser.add_argument(
            "--resolver",
            action='store',
            default=PluginManager.PLUGIN_NAME_NOOP,
            help='Name of the IP Resolver plugin to use. Default is no-op plugin,'\
                ' which always returns an empty ip address.',
            choices=self.plugin_manager.get_plugin_names(PluginType.IPV6)
        )

        return parser
