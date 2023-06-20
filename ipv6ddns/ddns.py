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

    def run(self):
        """Run the workflow
        """
        curr_ip = self.ipv6.resolve()
        curr_dns = self.dns.get_aaaa_records()
        curr_fw = self.firewall.get_entries()

        new_dns = self.get_expected_dns_records(curr_ip)
        new_fw = self.get_expected_fw_entries(curr_ip)

        dns_diff = self.get_dns_diff(curr_dns, new_dns)
        fw_diff = self.get_fw_diff(curr_fw, new_fw)

        self.print_diff(curr_ip, dns_diff, fw_diff)

        if not dns_diff and not fw_diff and not self.ctx.common.force:
            logging.info("No updates to make. Exiting!")
            return 0

        if not self.ctx.common.assume_yes:
            response = input("Continue? [y|N]: ").lower()
            if not response or response[0] == "n":
                logging.info("Aborting.")
                return 4

        self.update(new_dns, new_fw)
        return 0

    def get_expected_dns_records(self, curr_ip):
        """return the list of dns records expected in the zone.

        Args:
            curr_ip (str): the current ip address

        Returns:
            list[ZoneRecord]: list of expected zone records
        """
        return [
            ZoneRecord(domain, curr_ip, 60)
            for domain in self.ctx.dns.fqdns
        ]

    def get_expected_fw_entries(self, curr_ip):
        """return the list of firewall entries expected in the firewall

        Args:
            curr_ip (str): current ip address

        Returns:
            list[FirewallEntry]: list of firewall entries
        """
        tcp_fw_entries = [
            FirewallEntry("", curr_ip, port, Protocol.TCP)
            for port in self.ctx.firewall.tcp_ports
        ]

        udp_fw_entries = [
            FirewallEntry("", curr_ip, port, Protocol.UDP)
            for port in self.ctx.firewall.udp_ports
        ]

        return tcp_fw_entries + udp_fw_entries

    @staticmethod
    def print_diff(new_ip, dns_diff, fw_diff):
        """Print the diff between old and new view. Only print the 
        differences: new entries to be created or updated in DNS and 
        firewall
        """
        logging.info("Current IP of the host is %s", new_ip)

        for entry in dns_diff:
            old = entry[0]
            new = entry[1]
            if not old:
                logging.info("[dns.add] %s => %s", new.name, new.ip_addr)
            else:
                logging.info("[dns.update] %s => %s [old=%s]", new.name, new.ip_addr, old.ip_addr)

        for entry in fw_diff:
            old = entry[0]
            new = entry[1]
            if not old:
                logging.info("[fw.add] ALLOW %s:%s TO %s", new.protocol, new.port, new.ip_addr)
            else:
                logging.info("[fw.update] ALLOW %s:%s TO %s [old=%s]",
                             new.protocol, new.port, new.ip_addr, old.ip_addr)

    @staticmethod
    def get_dns_diff(old, new):
        """Compute and return the diff for DNS records. Returns list of
        tuples containing old and new records for same FQDN.
        """
        diff = []
        for record in new:
            existing = DDNSWorkflow._find_dns_record(record, old)
            if not existing or existing.ip_addr != record.ip_addr:
                diff.append((existing, record))
        return diff

    @staticmethod
    def get_fw_diff(old, new):
        """Compute and return the diff for firewall records. Returns list of
        tuples containing old and new records for same entry_id.
        """
        diff = []
        for record in new:
            existing = DDNSWorkflow._find_fw_entry(record, old)
            if not existing or existing.ip_addr != record.ip_addr:
                diff.append((existing, record))
        return diff

    def update(self, dns_records, fw_entries):
        """Update the DNS and firewall entries
        """
        self.dns.upsert_records(dns_records)
        self.firewall.save_entries(fw_entries)

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
