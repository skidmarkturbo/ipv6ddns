"""
Tests for execution context classes
"""
import argparse
from ipv6ddns.context import ArgparseContextParser
from ipv6ddns import plugin


def test_common_ctx_is_parsed_correctly():
    """Tests that common context is parsed
    correctly
    """
    plugin_manager = plugin.PluginManager()
    namespace = argparse.Namespace()
    namespace.dry_run = True
    namespace.force = True
    namespace.assume_yes = True

    parser = ArgparseContextParser(plugin_manager, namespace)
    ctx = parser.parse_common_ctx()

    assert ctx.dry_run
    assert ctx.force
    assert ctx.assume_yes
    assert ctx.args == namespace


def test_dns_ctx_is_parsed_correctly():
    """Tests that common context is parsed
    correctly
    """
    plugin_manager = plugin.PluginManager()
    namespace = argparse.Namespace()
    namespace.dns = plugin.PluginManager.PLUGIN_NAME_NOOP
    namespace.domain = ["example.com"]

    parser = ArgparseContextParser(plugin_manager, namespace)
    ctx = parser.parse_dns_ctx()

    assert ctx.plugin == plugin.DNSPlugin
    assert ctx.fqdns == namespace.domain


def test_firewall_ctx_is_parsed_correctly():
    """Tests that common context is parsed
    correctly
    """
    plugin_manager = plugin.PluginManager()
    namespace = argparse.Namespace()
    namespace.firewall = plugin.PluginManager.PLUGIN_NAME_NOOP
    namespace.tcp_port = [80, 443]
    namespace.udp_port = [4848, 1191]
    namespace.host_id = "nginx-proxy"

    parser = ArgparseContextParser(plugin_manager, namespace)
    ctx = parser.parse_firewall_ctx()

    assert ctx.plugin == plugin.FirewallPlugin
    assert ctx.tcp_ports == namespace.tcp_port
    assert ctx.udp_ports == namespace.udp_port
    assert ctx.host_id == namespace.host_id


def test_resolver_ctx_is_parsed_correctly():
    """Tests that common context is parsed
    correctly
    """
    plugin_manager = plugin.PluginManager()
    namespace = argparse.Namespace()
    namespace.resolver = plugin.PluginManager.PLUGIN_NAME_NOOP

    parser = ArgparseContextParser(plugin_manager, namespace)
    ctx = parser.parse_resolver_ctx()

    assert ctx.plugin == plugin.IPResolverPlugin
