"""
DDNS operations and core logic
"""
import logging
from ipv6ddns.domain import ZoneRecord, FirewallEntry, Protocol


class DDNSWorkflow:
    """Main workflow that implements the DDNS changes
    """

    def __init__(self, context) -> None:
        self.ctx = context
        self.dns = context.dns.plugin(context.common, context.dns)
        self.firewall = context.firewall.plugin(context.common, context.firewall)
        self.ipv6 = context.ipv6.plugin(context.common, context.ipv6)
        self._current_ip = ""
        self._current_dns_entries = []
        self._current_fw_entries = []
        self._updated_dns_entries = []
        self._updated_fw_entries = []

    def run(self):
        """Run the workflow
        """
        self.build_old_view()
        self.build_new_view()

        dns_diff, fw_diff = self.print_diff()
        if not dns_diff and fw_diff and not self.ctx.common.forced:
            logging.info("No updates to make. Exiting!")
            return 0

        if not self.ctx.common.assume_yes:
            response = input("Continue? [y|N]: ").lower()
            if not response or response[0] == "n":
                logging.info("Aborting.")
                return 4

        self.update()
        return 0

    def build_old_view(self):
        """Build the old view of things. What does the world see currently. This
        fetches the current IPV6 of host, the existing DNS and firewall records. 
        """
        logging.debug("Resolving the current IPV6 address of the host.")
        self._current_ip = self.ipv6.resolve()
        logging.debug("IPV6 of the host is %s", self._current_ip)

        logging.debug("Fetching current DNS entries for %d domains", len(self.ctx.dns.fqdns))
        self._current_dns_entries = self.dns.get_aaaa_records()
        logging.debug("Found %d entries in DNS.", len(self._current_dns_entries))

        logging.debug(
            "Fetching current firewall entries for %d tcp ports, %d udp ports, and host=%s",
            len(self.ctx.firewall.tcp_ports),
            len(self.ctx.firewall.udp_ports),
            self.ctx.firewall.host_id
        )
        self._current_fw_entries = self.firewall.get_entries()
        logging.debug("Found %d firewall entries", len(self._current_fw_entries))

    def build_new_view(self):
        """Build the correct view of DNS entries and firewalls according to the new
        IPV6 address.
        """
        self._updated_dns_entries = [
            ZoneRecord(domain, self._current_ip, 60)
            for domain in self.ctx.dns.fqdns
        ]

        tcp_fw_entries = [
            FirewallEntry("", self._current_ip, port, Protocol.TCP)
            for port in self.ctx.firewall.tcp_ports
        ]

        udp_fw_entries = [
            FirewallEntry("", self._current_ip, port, Protocol.UDP)
            for port in self.ctx.firewall.udp_ports
        ]

        self._updated_fw_entries = tcp_fw_entries + udp_fw_entries

    def print_diff(self):
        """Print the diff between old and new view. Only print the 
        differences: new entries to be created or updated in DNS and 
        firewall
        """
        logging.info("Current IP of the host is %s", self._current_ip)

        dns_diff = self.get_dns_diff(
            self._current_dns_entries,
            self._updated_dns_entries
        )
        for entry in dns_diff:
            old = entry[0]
            new = entry[1]
            if not old:
                logging.info("[dns.add] %s => %s", new.name, new.ip_addr)
            else:
                logging.info("[dns.update] %s => %s [old=%s]", new.name, new.ip_addr, old.ip_addr)

        fw_diff = self.get_fw_diff(
            self._current_fw_entries,
            self._updated_fw_entries
        )
        for entry in fw_diff:
            old = entry[0]
            new = entry[1]
            if not old:
                logging.info("[fw.add] ALLOW %s:%s TO %s", new.protocol, new.port, new.ip_addr)
            else:
                logging.info("[fw.update] ALLOW %s:%s TO %s [old=%s]",
                             new.name, new.port, new.ip_addr, old.ip_addr)

        return (dns_diff, fw_diff)

    def get_dns_diff(self, old, new):
        """Compute and return the diff for DNS records. Returns list of
        tuples containing old and new records for same FQDN.
        """
        diff = []
        for record in new:
            existing = self._find_dns_record(record, old)
            if not existing or existing.ip_addr != record.ip_addr:
                diff.append((existing, record))
        return diff

    def get_fw_diff(self, old, new):
        """Compute and return the diff for firewall records. Returns list of
        tuples containing old and new records for same entry_id.
        """
        diff = []
        for record in new:
            existing = self._find_fw_entry(record, old)
            if not existing or existing.ip_addr != record.ip_addr:
                diff.append((existing, record))
        return diff

    def update(self):
        """Update the DNS and firewall entries
        """
        self.dns.upsert_records(self._updated_dns_entries)
        self.firewall.save_entries(self._updated_fw_entries)

    @staticmethod
    def _find_dns_record(query, records):
        for record in records:
            if record.name == query.name:
                return record
        return None

    @staticmethod
    def _find_fw_entry(query, entries):
        for entry in entries:
            if entry.entry_id == query.entry_id:
                return entry
        return None
