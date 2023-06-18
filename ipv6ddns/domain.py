"""
Domain entities for ipv6ddns core.
"""
from enum import Enum


class ZoneRecord:
    """DNS record in a zone."""

    def __init__(self, name: str, ip_addr: str, ttl: int) -> None:
        """Constructor

        Args:
            name (str): fully qualified domain name of the record
            ip_addr (str): ip address of the record
            ttl (int): current TTL in seconds
        """
        self.name = name
        self.ip_addr = ip_addr
        self.ttl = ttl

    def __str__(self) -> str:
        return f"ZoneRecord: name={self.name} | ip={self.ip_addr} | ttl={self.ttl}"

    def __repr__(self) -> str:
        return f"ZoneRecord({repr(self.name)}, {repr(self.ip_addr)}, {repr(self.ttl)})"


class Protocol(Enum):
    """Transport layer protocol"""

    TCP = "tcp"
    UDP = "udp"


class FirewallEntry:
    """Firewall entry in the IPV6 firewall table"""

    def __init__(self, entry_id: str, ip_addr: str, port: int, protocol: Protocol):
        """Constructor

        Args:
            entry_id (str): unique id of the entry in firewall. How this is built is left to
                            to the individual firewall providers.
            ip_addr (str): ipv6 address in the firewall entry
            port (int): the port that is allowed
            protocol (Protocol): protocol being allowed in the firewall entry
        """
        self.entry_id = entry_id
        self.ip_addr = ip_addr
        self.port = port
        self.protocol = protocol

    def __str__(self) -> str:
        return f'Firewall Entry: id={self.entry_id} | ip={self.ip_addr} |'\
                f' port={self.port} | protocol={self.protocol}'

    def __repr__(self) -> str:
        return f"""FirewallEntry(
            {repr(self.entry_id)},
            {repr(self.ip_addr)},
            {repr(self.port)},
            {repr(self.protocol)}
        )"""


# pylint: disable=locally-disabled, too-few-public-methods,
class CommonContext:
    """Context common to all operations
    """

    def __init__(self) -> None:
        self.assume_yes = False
        self.dry_run = False
        self.args = None


# pylint: disable=locally-disabled, too-few-public-methods,
class DNSContext:
    """Context specific to DNS operations
    """

    def __init__(self) -> None:
        self.plugin = None
        self.fqdns = []


# pylint: disable=locally-disabled, too-few-public-methods,
class FirewallContext:
    """Context specific to Firewall operations
    """

    def __init__(self) -> None:
        self.plugin = None
        self.tcp_ports = []
        self.udp_ports = []
        self.host_id = None


# pylint: disable=locally-disabled, too-few-public-methods,
class ResolverContext:
    """Context specific to IPV6 resolution operations
    """

    def __init__(self) -> None:
        self.plugin = None


# pylint: disable=locally-disabled, too-few-public-methods
class DDNSContext:
    """Execution context of DDNS oprations. Holds all the configuration
    and arguments (eg. FQDNs, plugins to use, and plugin configuration).
    The DDNS workflow executes over a context.
    """

    def __init__(self) -> None:
        self.common = CommonContext()
        self.dns = DNSContext()
        self.firewall = FirewallContext()
        self.ipv6 = ResolverContext()
