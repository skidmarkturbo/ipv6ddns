"""
Route53 integration for ipv6ddns
"""
from ipv6ddns.plugin import DNSPlugin


class Route53DNSPlugin(DNSPlugin):
    """DNS plugin for Amazon Route53
    """

    @staticmethod
    def get_name():
        return "route53"

    @staticmethod
    def get_title() -> str:
        return "Amazon Route53 Plugin for ipv6ddns"

    @staticmethod
    def get_description() -> str:
        return """DNS plugin with support for Amazon Route53
        for ipv6ddns.
        """
