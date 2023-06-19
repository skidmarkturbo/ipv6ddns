"""
Classes for execution context
"""
from ipv6ddns.plugin import PluginManager


# pylint: disable=locally-disabled, too-few-public-methods,
class CommonContext:
    """Context common to all operations"""

    def __init__(self) -> None:
        self.assume_yes = False
        self.dry_run = False
        self.args = None
        self.force = False

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return f"CommonContext(assume_yes={self.assume_yes},"\
            f" dry_run={self.dry_run}, args={self.args},"\
            f" force={self.force})"


# pylint: disable=locally-disabled, too-few-public-methods,
class DNSContext:
    """Context specific to DNS operations"""

    def __init__(self) -> None:
        self.plugin = None
        self.fqdns = []

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return f"DNSContext(plugin={self.plugin}, fqdns={self.fqdns})"


# pylint: disable=locally-disabled, too-few-public-methods,
class FirewallContext:
    """Context specific to Firewall operations"""

    def __init__(self) -> None:
        self.plugin = None
        self.tcp_ports = []
        self.udp_ports = []
        self.host_id = None

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return f"FirewallContext(plugin={self.plugin}, tcp_ports={self.tcp_ports})"\
            f", udp_ports={self.udp_ports}, host_id={self.host_id})"


# pylint: disable=locally-disabled, too-few-public-methods,
class ResolverContext:
    """Context specific to IPV6 resolution operations"""

    def __init__(self) -> None:
        self.plugin = None

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return f"ResolverContext(plugin={self.plugin})"


# pylint: disable=locally-disabled, too-few-public-methods
class DDNSContext:
    """Execution context of DDNS oprations. Holds all the configuration
    and arguments (eg. FQDNs, plugins to use, and plugin configuration).
    The DDNS workflow executes over a context.
    """

    def __init__(self) -> None:
        self.ctx_id = "args"
        self.common = CommonContext()
        self.dns = DNSContext()
        self.firewall = FirewallContext()
        self.ipv6 = ResolverContext()

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self) -> str:
        return f"""DDNSContext(
            common={self.common},
            dns={self.dns},
            firewall={self.firewall},
            ipv6={self.ipv6}
        )"""


class ContextParser:
    """Informal noop interface for context parser. Context parsers take
    an input, preferably via the constructor and implement a parse() method
    which returns a list of DDNSContext.
    """

    def __init__(self, plugin_manager: PluginManager) -> None:
        self.plugin_manager = plugin_manager

    def parse(self):
        """parse the input passed in the constructor and return a list of
        execution contexts

        Returns:
            list[DDNSContext]: list of execution contexts
        """
        return []


class ArgparseContextParser(ContextParser):
    """Context parser which parses context from an argparse namespace object"""

    def __init__(self, plugin_manager: PluginManager, args) -> None:
        super().__init__(plugin_manager)
        self.args = args

    def parse(self):
        ctx = DDNSContext()
        ctx.common = self.parse_common_ctx()
        ctx.dns = self.parse_dns_ctx()
        ctx.firewall = self.parse_firewall_ctx()
        ctx.ipv6 = self.parse_resolver_ctx()
        return [ctx]

    def parse_common_ctx(self):
        """Parse CommonContext from namespace"""
        args = self.args
        ctx = CommonContext()
        ctx.assume_yes = args.assume_yes
        ctx.dry_run = args.dry_run
        ctx.force = args.force
        ctx.args = self.args
        return ctx

    def parse_dns_ctx(self):
        """Parse DNSContext from namespace"""
        args = self.args
        ctx = DNSContext()
        ctx.plugin = self.plugin_manager.dns_plugins[args.dns]
        ctx.fqdns = args.domain
        return ctx

    def parse_firewall_ctx(self):
        """Parse FirewallContext from namespace"""
        args = self.args
        ctx = FirewallContext()
        ctx.plugin = self.plugin_manager.firewall_plugins[args.firewall]
        ctx.tcp_ports = args.tcp_port
        ctx.udp_ports = args.udp_port
        ctx.host_id = args.host_id
        return ctx

    def parse_resolver_ctx(self):
        """Parse DNSContext from namespace"""
        args = self.args
        ctx = ResolverContext()
        ctx.plugin = self.plugin_manager.ipv6_plugins[args.resolver]
        return ctx
