"""
Plugins for test cases
"""
from ipv6ddns import plugin
from ipv6ddns.domain import FirewallEntry, ZoneRecord


class InMemoryDNSPlugin(plugin.DNSPlugin):
    """DNS plugin which stores the records in memory. The current
    records can be updated using the set_records method.
    """

    @staticmethod
    def get_name() -> str:
        return "in-memory"

    def __init__(self, common_ctx, plugin_ctx) -> None:
        super().__init__(common_ctx, plugin_ctx)
        self.records = {}

    def get_aaaa_records(self):
        ctx = self.ctx_plugin
        records = []
        for fqdn in ctx.fqdns:
            if fqdn in self.records:
                record = self.records[fqdn]
                records.append(ZoneRecord(fqdn, record['ip'], record['ttl']))
        return records

    def upsert_records(self, records) -> None:
        for record in records:
            self.records[record.name] = {
                'ip': record.ip_addr,
                'ttl': record.ttl
            }

    def set_records(self, new_records):
        """Update the current records in the DNS zone

        Args:
            new_records (list[ZoneRecord]): desired records
        """
        self.records = {}
        for record in new_records:
            self.records[record.name] = {
                'ip': record.ip_addr,
                'ttl': record.ttl
            }


class InMemoryFirewallPlugin(plugin.FirewallPlugin):
    """Firewall plugin which stores the entries in memory. The current
    entries can be updated using the set_entries method.
    """

    @staticmethod
    def get_name() -> str:
        return "in-memory"

    def __init__(self, common_ctx, plugin_ctx) -> None:
        super().__init__(common_ctx, plugin_ctx)
        self.entries = {}

    def get_entries(self):
        entries = []
        for entry_id, value in self.entries.items():
            entries.append(FirewallEntry(
                entry_id,
                value['ip'],
                value['port'],
                value['protocol']
            ))
        return entries

    def save_entries(self, entries) -> None:
        for entry in entries:
            self.entries[entry.entry_id] = {
                'ip': entry.ip_addr,
                'port': entry.port,
                'protocol': entry.protocol
            }

    def set_entries(self, entries):
        """Set the entries in firewall to desired entries

        Args:
            entries (list[FirewallEntry]): list of entries
        """
        self.entries = {}
        for entry in entries:
            self.entries[entry.entry_id] = {
                'ip': entry.ip_addr,
                'port': entry.port,
                'protocol': entry.protocol
            }
