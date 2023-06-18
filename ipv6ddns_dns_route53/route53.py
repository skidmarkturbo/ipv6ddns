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
