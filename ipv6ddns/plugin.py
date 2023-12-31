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

    IPV6 = "ipv6ddns.plugin.ipv6"
    """Provider provides IPV6 resolution. The provider is capable of 
    determining the correct IPV6 address of the target host.
    """

    UNKNOWN = "unknown"
    """Unknown provider. Internal use only.
    """


class Plugin:
    """Informal interface for all providers. All providers by a plugin will 
    extend from this class. All plugin classes should implement an __init__
    method that takes the CommonContext and Plugin specific context as parameters.
    """

    PLUGIN_NAME_NOOP = "noop"

    def __init__(self, common_ctx, plugin_ctx) -> None:
        self.ctx_common = common_ctx
        self.ctx_plugin = plugin_ctx

    @staticmethod
    def get_name() -> str:
        """Return the name of this provider. This should be unique across
        all plugins of the system

        Returns:
            str: unique name of the provider
        """
        return Plugin.PLUGIN_NAME_NOOP

    @staticmethod
    def get_title() -> str:
        """Return the descriptive name of this provider. Used in help section
        and to inform user when things go wrong.

        Returns:
            str: unique name of the provider
        """
        return ""

    @staticmethod
    def get_description() -> str:
        """Return the long description for this provider. Used in help section.

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

    # pylint: disable=locally-disabled, unused-argument
    @staticmethod
    def add_args(argparse_group, prefix):
        """Add arguments specific to this plugin to the passed argparse group.
        The `argparse_group` is created using `ArgumentParser.add_argument_group()`.
        All arguments must specify a long arg format and should be prefixed with
        the given `prefix`.

        Args:
            argparse_group: argparse group
        """

    # pylint: disable=locally-disabled, unused-argument
    @staticmethod
    def validate(context):
        """Validates the context and returns a list of ValidationError
        """
        return []


class DNSPlugin(Plugin):
    """Informal interface for DNS plugin. Should be exported in 'ipv6ddns.plugin.dns'
    entry point.
    """

    # pylint: disable=locally-disabled, unused-argument
    def get_aaaa_records(self):
        """Get existing AAAA records from DNS server for given list of 
        fully-qualified-domain-names. The desired FQDNs can be retrieved from 
        the `fqdns` attribute of the `plugin_ctx` passed to the `__init__` 
        method. In case the record does not exist, the list return should not 
        contain the record.

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
    def get_title() -> str:
        return "NOOP DNS Plugin"

    @staticmethod
    def get_description() -> str:
        return "DNS plugin for ipv6ddns which does nothing. Call to get_aaaa_records"\
            " will always return empty list, and call to upsert_records() will do "\
            " nothing"

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
    def get_title() -> str:
        return "NOOP Firewall Plugin"

    @staticmethod
    def get_description() -> str:
        return "Firewall plugin for ipv6ddns which does nothing. Call to get_entries"\
            " will always return empty list, and call to save_entries() will do "\
            " nothing"

    @staticmethod
    def get_type() -> PluginType:
        return PluginType.FIREWALL


class IPResolverPlugin(Plugin):
    """Informal interface for IPV6 Resolver. Should be exposed in
    'ipv6ddns.plugin.ipv6' entry point.
    """

    # pylint: disable=locally-disabled, unused-argument
    def resolve(self):
        """Get the current IPV6 address of the target host.

        Returns:
           str: resolved IPV6 address
        """
        return ""

    @staticmethod
    def get_title() -> str:
        return "NOOP DNS Plugin"

    @staticmethod
    def get_description() -> str:
        return "IPV6 resolver plugin for ipv6ddns which does nothing. Call to"\
            " resolve will always return empty string."

    @staticmethod
    def get_type() -> PluginType:
        return PluginType.IPV6


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
                 dns_plugins = None,
                 firewall_plugins = None,
                 ipv6_plugins = None) -> None:
        self.dns_plugins = dns_plugins if dns_plugins else []
        self.firewall_plugins = firewall_plugins if firewall_plugins else []
        self.ipv6_plugins = ipv6_plugins if ipv6_plugins else []

    def lookup(self, ep_name: str):
        if ep_name == PluginType.DNS.value:
            return self.dns_plugins
        if ep_name == PluginType.FIREWALL.value:
            return self.firewall_plugins
        if ep_name == PluginType.IPV6.value:
            return self.ipv6_plugins
        return []


class PluginManager:
    """Plugin manager for the ipv6ddns core. This is responsible for
    discovering and loading the available plugins and utility functions
    around plugin management.
    """

    PLUGIN_NAME_NOOP = Plugin.PLUGIN_NAME_NOOP

    def __init__(self, lookup: IPluginLookup = ImportLibPluginLookup()) -> None:
        self.lookup = lookup
        self.plugins = []
        self.dns_plugins = {}
        self.firewall_plugins = {}
        self.ipv6_plugins = {}

    def discover(self):
        """Discover available plugins and load them
        """
        self.discover_and_load(PluginType.DNS)
        self.discover_and_load(PluginType.FIREWALL)
        self.discover_and_load(PluginType.IPV6)

    def discover_and_load(self, plugin_type: PluginType):
        """Discover and load plugins from given entry point name and store
        it in the given target dictionalry

        Args:
            ep_name (str): name of the entry point
            target (dict[str, _Plugin]): target dictionary of plugin name to plugin class
        """
        plugins = self.lookup.lookup(plugin_type.value)
        for plugin in plugins:
            self.register(plugin)

    def register(self, plugin):
        """Manually register a plugin.

        Args:
            plugin (Plugin): plugin to register.
        """
        target = {}
        if plugin.get_type() == PluginType.DNS:
            target = self.dns_plugins
        elif plugin.get_type() == PluginType.FIREWALL:
            target = self.firewall_plugins
        elif plugin.get_type() == PluginType.IPV6:
            target = self.ipv6_plugins
        else:
            logging.error("Skipping unknown plugin '%s", plugin)
            return

        if not self.validate(plugin, target):
            logging.error("Skipping invalid plugin '%s'.", plugin)
            return

        target[plugin.get_name()] = plugin
        self.plugins.append(plugin)

    def validate(self, plugin: Plugin, target) -> bool:
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

        if name in target:
            logging.debug('Plugin with name "%s" already registered', name)
            return False

        return True

    def get_plugin_names(self, plugin_type):
        """Get the names of loaded plugins

        Args:
            plugin_type (PluginType): type of plugins required

        Returns:
            list: List of plugin names available
        """
        if plugin_type == PluginType.DNS:
            return self.dns_plugins.keys()
        if plugin_type == PluginType.FIREWALL:
            return self.firewall_plugins.keys()
        if plugin_type == PluginType.IPV6:
            return self.ipv6_plugins.keys()
        return []
