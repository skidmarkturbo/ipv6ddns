"""
Plugin structure for the ipv6ddns core. 
"""
from enum import Enum
import sys
import logging


if sys.version_info < (3, 10):
    # pylint: disable=locally-disabled, unused-import
    from importlib_metadata import entry_points
else:
    # pylint: disable=locally-disabled, unused-import
    from importlib.metadata import entry_points


class PluginType(Enum):
    """Type of providers that can be provided by the plugin. ipv6ddns only
    allows providers of type dns and firewall.
    """

    DNS      = "ipv6ddns.plugin.dns"
    """Provider provides DNS capabilities. The provider should allow getting
    existing DNS records and updating them.
    """

    FIREWALL = "ipv6ddns.plugin.firewall"
    """Provider provides firewall integration. The provider is capable of 
    fetching the current firewall entries and updating them when the host
    ip changes.
    """

    UNKNOWN = "unknown"
    """Unknown provider. Internal use only.
    """


class Plugin:
    """Informal interface for all providers. All providers by a plugin will 
    extend from this class.
    """

    @staticmethod
    def get_name() -> str:
        """Return the name of this provider. This should be unique across
        all plugins of the system

        Returns:
            str: unique name of the provider
        """
        return ""

    @staticmethod
    def get_type() -> PluginType:
        """Type of this provider

        Returns:
            _ProviderType: provider type
        """
        return PluginType.UNKNOWN


class DNSPlugin(Plugin):
    """Informal interface for DNS plugin. Should be exported in 'ipv6ddns.plugin.dns'
    entry point.
    """

    # pylint: disable=locally-disabled, unused-argument
    def get_aaaa_records(self, fqdns):
        """Get AAAA records from DNS server for given list of fully-qualified-domain-names.
        In case the record does not exist, the list return should not contain the record.

        Args:
            fqdns (list[str]): list of fqdns for which the records are desired

        Returns:
            list[ZoneRecord]: list of existing records in the dns server
        """
        return []

    # pylint: disable=locally-disabled, unused-argument
    def upsert_records(self, records) -> None:
        """Create or update the AAAA records in the DNS server.

        Args:
            records (list[ZoneRecord]): list of records to update
        """

    @staticmethod
    def get_type() -> PluginType:
        return PluginType.DNS


class FirewallPlugin(Plugin):
    """Informal interface for Firewall Provider. Should be exposed in
    'ipv6ddns.plugin.firewall' entry point.
    """

    # pylint: disable=locally-disabled, unused-argument
    def get_entries(self):
        """Get list of firewall entries in the firewall.

        Returns:
            list[FirewallEntry]: list of existing firewall entries
        """
        return []

    def save_entries(self, entries) -> None:
        """Update the entries in firewall

        Args:
            entries (list[FirewallEntry]): list of entries to update
        """

    @staticmethod
    def get_type() -> PluginType:
        return PluginType.FIREWALL


# pylint: disable=locally-disabled, too-few-public-methods
class IPluginLookup:
    """Informal interface for plugin lookup logic
    """

    # pylint: disable=locally-disabled, unused-argument
    def lookup(self, ep_name: str):
        """Lookup plugins, load them and return the list of loaded plugin
        
        Args:
            ep_name: str: Name of the entry point to load plugins from

        Returns:
            list[_Plugin]: list of loaded plugins
        """
        return []


class ImportLibPluginLookup(IPluginLookup):
    """Plugin lookup using importlib entry points
    """

    def lookup(self, ep_name: str):
        eps = entry_points(group=ep_name)
        return [ep.load() for ep in eps]


class StaticPluginLookup(IPluginLookup):
    """Plugin lookup that returns static list of plugins. The static list
    can be configured at the time of creating the instance or by modifying
    the `plugins` field of the object.
    """

    def __init__(self,
                 dns_plugins = None, # type: ignore
                 firewall_plugins = None) -> None:
        self.dns_plugins = dns_plugins if dns_plugins else []
        self.firewall_plugins = firewall_plugins if firewall_plugins else []

    def lookup(self, ep_name: str):
        if ep_name == PluginType.DNS.value:
            return self.dns_plugins # type: ignore
        if ep_name == PluginType.FIREWALL.value:
            return self.firewall_plugins # type: ignore
        return []


class PluginManager:
    """Plugin manager for the ipv6ddns core. This is responsible for
    discovering and loading the available plugins and utility functions
    around plugin management.
    """

    def __init__(self, lookup: IPluginLookup = ImportLibPluginLookup()) -> None:
        self.lookup = lookup
        self.plugins = []
        self.dns_plugins = {}
        self.firewall_plugins = {}

    def discover(self):
        """Discover available plugins and load them
        """
        self.discover_and_load(
            PluginType.DNS,
            self.dns_plugins # type: ignore
        )
        self.discover_and_load(
            PluginType.FIREWALL,
            self.firewall_plugins  # type: ignore
        )

    def discover_and_load(self, plugin_type: PluginType, target):
        """Discover and load plugins from given entry point name and store
        it in the given target dictionalry

        Args:
            ep_name (str): name of the entry point
            target (dict[str, _Plugin]): target dictionary of plugin name to plugin class
        """
        plugins = self.lookup.lookup(plugin_type.value)
        for plugin in plugins:
            if not self.validate(plugin, plugin_type, target):
                logging.debug("Skipping invalid plugin '%s'.", plugin)
                continue

            target[plugin.get_name()] = plugin
            self.plugins.append(plugin)

    def validate(self, plugin: Plugin, plugin_type: PluginType, target) -> bool:
        """Validate the plugin. Check if plugin name is correct and does not
        collide with existing or already loaded plugins.

        Args:
            plugin (_Plugin): Plugin to be loaded
            plugin_type(PluginType): Type of plugin to validate
            target (dict[str, _Plugin]): the target plugin namespace (dns/firewall) where
                                         the plugin will be added

        Returns:
            bool: returns True if plugin can be added, False otherwise
        """
        name = plugin.get_name()
        if not name:
            logging.debug("Invalid plugin name: '%s'", name)
            return False

        if plugin.get_type() != plugin_type:
            logging.debug("Plugin type did not match for plugin '%s'", name)
            return False

        if name in target:
            logging.debug('Plugin with name "%s" already registered', name)
            return False

        return True