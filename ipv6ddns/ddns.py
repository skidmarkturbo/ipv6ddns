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
        curr_ip, curr_dns, curr_fw = self.build_old_view()
        new_dns, new_fw = self.build_new_view(curr_ip)

        dns_diff, fw_diff = self.print_diff(
            curr_ip,
            (curr_dns, new_dns),
            (curr_fw, new_fw)
        )
        if not dns_diff and fw_diff and not self.ctx.common.forced:
            logging.info("No updates to make. Exiting!")
            return 0

        if not self.ctx.common.assume_yes:
            response = input("Continue? [y|N]: ").lower()
            if not response or response[0] == "n":
                logging.info("Aborting.")
                return 4

        self.update(new_dns, new_fw)
        return 0

    def build_old_view(self):
        """Build the old view of things. What does the world see currently. This
        fetches the current IPV6 of host, the existing DNS and firewall records. 
        """
        logging.debug("Resolving the current IPV6 address of the host.")
        curr_ip = self.ipv6.resolve()
        logging.debug("IPV6 of the host is %s", curr_ip)

        logging.debug("Fetching current DNS entries for %d domains", len(self.ctx.dns.fqdns))
        curr_dns = self.dns.get_aaaa_records()
        logging.debug("Found %d entries in DNS.", len(curr_dns))

        logging.debug(
            "Fetching current firewall entries for %d tcp ports, %d udp ports, and host=%s",
            len(self.ctx.firewall.tcp_ports),
            len(self.ctx.firewall.udp_ports),
            self.ctx.firewall.host_id
        )
        curr_fw = self.firewall.get_entries()
        logging.debug("Found %d firewall entries", len(curr_fw))

        return (curr_ip, curr_dns, curr_fw)

    def build_new_view(self, curr_ip):
        """Build the correct view of DNS entries and firewalls according to the new
        IPV6 address.
        """
        new_dns = [
            ZoneRecord(domain, curr_ip, 60)
            for domain in self.ctx.dns.fqdns
        ]

        tcp_fw_entries = [
            FirewallEntry("", curr_ip, port, Protocol.TCP)
            for port in self.ctx.firewall.tcp_ports
        ]

        udp_fw_entries = [
            FirewallEntry("", curr_ip, port, Protocol.UDP)
            for port in self.ctx.firewall.udp_ports
        ]

        new_fw = tcp_fw_entries + udp_fw_entries

        return (new_dns, new_fw)

    def print_diff(self, new_ip, dns_diff, fw_diff):
        """Print the diff between old and new view. Only print the 
        differences: new entries to be created or updated in DNS and 
        firewall
        """
        logging.info("Current IP of the host is %s", new_ip)

        dns_diff = self.get_dns_diff(dns_diff[0], dns_diff[1])
        for entry in dns_diff:
            old = entry[0]
            new = entry[1]
            if not old:
                logging.info("[dns.add] %s => %s", new.name, new.ip_addr)
            else:
                logging.info("[dns.update] %s => %s [old=%s]", new.name, new.ip_addr, old.ip_addr)

        fw_diff = self.get_fw_diff(fw_diff[0], fw_diff[1])
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
