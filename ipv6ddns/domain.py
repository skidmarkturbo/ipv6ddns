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
class ValidationError:
    """Container struct for validation errors
    """
    def __init__(self, plugin_name: str, message: str) -> None:
        self.plugin_name = plugin_name
        self.message = message
