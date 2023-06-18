"""
Tests for PluginManager
"""
from ipv6ddns.plugin import (
    PluginManager,
    DNSPlugin,
    StaticPluginLookup,
    Plugin,
    PluginType,
    FirewallPlugin,
    IPResolverPlugin,
)


def test_inbuilt_plugins_are_loaded_correctly():
    """test in-built plugins are loaded correctly"""
    plugin_manager = PluginManager()
    plugin_manager.discover()
    print(plugin_manager.plugins)
    assert len(plugin_manager.plugins) == 3
    assert plugin_manager.firewall_plugins == {
        PluginManager.PLUGIN_NAME_NOOP: FirewallPlugin
    }
    assert plugin_manager.dns_plugins == {PluginManager.PLUGIN_NAME_NOOP: DNSPlugin}
    assert plugin_manager.ipv6_plugins == {
        PluginManager.PLUGIN_NAME_NOOP: IPResolverPlugin
    }


class PluginWithName(DNSPlugin):
    """Sample plugin with name"""

    @staticmethod
    def get_name() -> str:
        return "awesome"


class FirewallPluginWithName(FirewallPlugin):
    """Sample plugin with name"""

    @staticmethod
    def get_name() -> str:
        return "awesome"


class IPResolverPluginWithName(IPResolverPlugin):
    """Sample plugin with name"""

    @staticmethod
    def get_name() -> str:
        return "awesome"


class PluginWithNoName(DNSPlugin):
    """Sample plugin with empty name"""

    @staticmethod
    def get_name() -> str:
        return ""


class PluginWithDuplicateName(DNSPlugin):
    """Sample plugin with duplicate name"""

    @staticmethod
    def get_name() -> str:
        return "awesome"


class UnknownPlugin(Plugin):
    """Sample plugin that directly inherits from Plugin class.
    This should not be done.
    """

    @staticmethod
    def get_name():
        return "hello"


def test_plugin_with_name_is_loaded():
    """Tests that plugin with a valid name is loaded"""
    plugin_lookup = StaticPluginLookup([PluginWithName], [FirewallPluginWithName], [IPResolverPluginWithName])
    plugin_manager = PluginManager(plugin_lookup)
    plugin_manager.discover()
    assert len(plugin_manager.plugins) == 3
    assert plugin_manager.firewall_plugins == {
        "awesome": FirewallPluginWithName,
    }
    assert plugin_manager.dns_plugins == {
        "awesome": PluginWithName,
    }
    assert plugin_manager.ipv6_plugins == {
        'awesome': IPResolverPluginWithName
    }


def test_plugin_with_no_name_is_not_loaded():
    """Tests that plugin with a empty name is not loaded"""
    plugin_lookup = StaticPluginLookup([PluginWithNoName])
    plugin_manager = PluginManager(plugin_lookup)
    plugin_manager.discover()
    assert len(plugin_manager.plugins) == 0
    assert not plugin_manager.firewall_plugins
    assert not plugin_manager.dns_plugins
    assert not plugin_manager.ipv6_plugins


def test_plugin_with_duplicate_name_is_not_loaded():
    """Tests that plugin with a duplicate name is not loaded"""
    plugin_lookup = StaticPluginLookup([PluginWithName, PluginWithDuplicateName])
    plugin_manager = PluginManager(plugin_lookup)
    plugin_manager.discover()
    assert len(plugin_manager.plugins) == 1
    assert not plugin_manager.firewall_plugins
    assert plugin_manager.dns_plugins == {
        "awesome": PluginWithName,
    }
    assert not plugin_manager.ipv6_plugins


def test_plugin_with_incorrect_type_is_not_loaded():
    """Tests that plugin with invalid type is not loaded"""
    plugin_lookup = StaticPluginLookup([PluginWithName], [PluginWithDuplicateName])
    plugin_manager = PluginManager(plugin_lookup)
    plugin_manager.discover()
    assert len(plugin_manager.plugins) == 1
    assert not plugin_manager.firewall_plugins
    assert plugin_manager.dns_plugins == {
        "awesome": PluginWithName,
    }
    assert not plugin_manager.ipv6_plugins


def test_unknown_plugin_is_not_loaded():
    """Tests that plugin with invalid type is not loaded"""
    plugin_lookup = StaticPluginLookup([UnknownPlugin], [UnknownPlugin])  # type: ignore
    plugin_manager = PluginManager(plugin_lookup)
    plugin_manager.discover()
    assert len(plugin_manager.plugins) == 0
    assert not plugin_manager.firewall_plugins
    assert not plugin_manager.dns_plugins
    assert not plugin_manager.ipv6_plugins


def test_static_plugin_lookup_returns_correct_plugins():
    """Tests that static plugin lookup is working correctly"""
    plugin_lookup = StaticPluginLookup(
        [PluginWithName], [PluginWithDuplicateName], [IPResolverPluginWithName]
    )
    assert plugin_lookup.lookup(PluginType.DNS.value) == [PluginWithName]
    assert plugin_lookup.lookup(PluginType.FIREWALL.value) == [PluginWithDuplicateName]
    assert plugin_lookup.lookup(PluginType.IPV6.value) == [IPResolverPluginWithName]
    assert not plugin_lookup.lookup(PluginType.UNKNOWN.value)
