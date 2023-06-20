"""
DDNS operations and core logic
"""


class DDNSWorkflow:
    """Main workflow that implements the DDNS changes
    """

    def __init__(self, context) -> None:
        self.ctx = context
        self.dns = context.dns.plugin()
        self.firewall = context.firewall.plugin()
        self.ipv6 = context.ipv6.plugin()

    def run(self):
        """Run the workflow
        """
