"""
Tests for ddns workflow
"""
import pytest
from ipv6ddns.cli import Cli
from ipv6ddns.context import ArgparseContextParser
from ipv6ddns.ddns import DDNSWorkflow
from ipv6ddns.domain import ZoneRecord, FirewallEntry, Protocol
from ipv6ddns.plugin import PluginManager


@pytest.fixture()
def plugin_manager():
    """Plugin manager fixture for this test
    """
    plugins = PluginManager()
    plugins.discover()
    yield plugins


# pylint: disable=locally-disabled, redefined-outer-name
@pytest.fixture()
def empty_context(plugin_manager):
    """Empty DDNS execution context
    """
    args = []
    cli = Cli(args)
    parsed = cli.parse_args()
    ctx_parser = ArgparseContextParser(plugin_manager, parsed)
    ctx = ctx_parser.parse()
    yield ctx[0]


# pylint: disable=locally-disabled, redefined-outer-name
@pytest.fixture()
def full_context(plugin_manager):
    """DDNS context with 2 domains and 3 firewall ports and asking
    for non-interactive mode using --assume-yes
    """
    args = [
        "--domain", "example.com",
        "--domain", "site.example.com",
        "--tcp-port", "80",
        "--tcp-port", "443",
        "--udp-port", "1191",
        "--assume-yes"
    ]
    cli = Cli(args)
    parsed = cli.parse_args()
    ctx_parser = ArgparseContextParser(plugin_manager, parsed)
    ctx = ctx_parser.parse()
    yield ctx[0]


# pylint: disable=locally-disabled, redefined-outer-name
@pytest.fixture()
def input_context(plugin_manager):
    """DDNS context with 2 domains and 3 firewall ports and asking
    for user input before applying changes.
    """
    args = [
        "--domain", "example.com",
        "--domain", "site.example.com",
        "--tcp-port", "80",
        "--tcp-port", "443",
        "--udp-port", "1191"
    ]
    cli = Cli(args)
    parsed = cli.parse_args()
    ctx_parser = ArgparseContextParser(plugin_manager, parsed)
    ctx = ctx_parser.parse()
    yield ctx[0]


def test_get_fw_diff_no_old_records():
    """Test get_fw_diff when old entries is empty
    """
    old = []
    new = [
        FirewallEntry(
            "fw:1", 
            "0001:db8:3333:4444:5555:6666:7777:8888",
            80,
            Protocol.TCP
        )
    ]

    fw_diff = DDNSWorkflow.get_fw_diff(old, new)

    assert len(fw_diff) == 1
    assert not fw_diff[0][0]
    assert fw_diff[0][1] == new[0]


def test_get_fw_diff_update_records():
    """Test get_fw_diff when records need to be updated
    """
    old = [
        FirewallEntry(
            "fw:1", 
            "0001:db8:3333:4444:5555:6666:7777:8889",
            80,
            Protocol.TCP
        )
    ]
    new = [
        FirewallEntry(
            "fw:1", 
            "0001:db8:3333:4444:5555:6666:7777:8888",
            80,
            Protocol.TCP
        )
    ]

    fw_diff = DDNSWorkflow.get_fw_diff(old, new)

    assert len(fw_diff) == 1
    assert fw_diff[0][0] == old[0]
    assert fw_diff[0][1] == new[0]


def test_get_fw_diff_no_changes():
    """Test get_fw_diff when no changes are required
    """
    old = [
        FirewallEntry(
            "fw:1", 
            "0001:db8:3333:4444:5555:6666:7777:8888",
            80,
            Protocol.TCP
        )
    ]
    new = [
        FirewallEntry(
            "fw:1", 
            "0001:db8:3333:4444:5555:6666:7777:8888",
            80,
            Protocol.TCP
        )
    ]

    fw_diff = DDNSWorkflow.get_fw_diff(old, new)

    assert not fw_diff


def test_get_dns_diff_no_old_records():
    """Test get_dns_diff when old entries is empty
    """
    old = []
    new = [
        ZoneRecord(
            "example.com",
            "0001:db8:3333:4444:5555:6666:7777:8888",
            60
        )
    ]

    diff = DDNSWorkflow.get_dns_diff(old, new)

    assert len(diff) == 1
    assert not diff[0][0]
    assert diff[0][1] == new[0]


def test_get_dns_diff_update_records():
    """Test get_dns_diff when records need to be updated
    """
    old = [
        ZoneRecord(
            "example.com",
            "0001:db8:3333:4444:5555:6666:7777:8889",
            60
        )
    ]
    new = [
        ZoneRecord(
            "example.com",
            "0001:db8:3333:4444:5555:6666:7777:8888",
            60
        )
    ]

    diff = DDNSWorkflow.get_dns_diff(old, new)

    assert len(diff) == 1
    assert diff[0][0] == old[0]
    assert diff[0][1] == new[0]


def test_get_dns_diff_no_update():
    """Test get_dns_diff when there are no changes
    """
    old = [
        ZoneRecord(
            "example.com",
            "0001:db8:3333:4444:5555:6666:7777:8888",
            60
        )
    ]
    new = [
        ZoneRecord(
            "example.com",
            "0001:db8:3333:4444:5555:6666:7777:8888",
            60
        )
    ]

    diff = DDNSWorkflow.get_dns_diff(old, new)

    assert not diff


def test_print_diff():
    """Test print_diff
    """
    dns_diff = [
        (
            ZoneRecord(
                "example.com",
                "0001:db8:3333:4444:5555:6666:7777:8889",
                60
            ),
            ZoneRecord(
                "example.com",
                "0001:db8:3333:4444:5555:6666:7777:8888",
                60
            )
        ),
        (
            None,
            ZoneRecord(
                "site.example.com",
                "0001:db8:3333:4444:5555:6666:7777:8888",
                60
            )
        )
    ]

    fw_diff = [
        (
            FirewallEntry(
                "fw:1", 
                "0001:db8:3333:4444:5555:6666:7777:8889",
                80,
                Protocol.TCP
            ),
            FirewallEntry(
                "fw:1", 
                "0001:db8:3333:4444:5555:6666:7777:8888",
                80,
                Protocol.TCP
            )
        ),
        (
            None,
            FirewallEntry(
                "fw:1", 
                "0001:db8:3333:4444:5555:6666:7777:8888",
                443,
                Protocol.TCP
            )
        )
    ]

    DDNSWorkflow.print_diff(
        "0001:db8:3333:4444:5555:6666:7777:8888",
        dns_diff,
        fw_diff
    )


# pylint: disable=locally-disabled, redefined-outer-name
def test_expected_fw_entries_empty(empty_context):
    """Test that expected firewall entries are created
    correctly
    """
    ip_addr = "0001:db8:3333:4444:5555:6666:7777:8888"
    workflow = DDNSWorkflow(empty_context)
    entries = workflow.get_expected_fw_entries(ip_addr)

    assert not entries


# pylint: disable=locally-disabled, redefined-outer-name
def test_expected_fw_entries(full_context):
    """Test that expected firewall entries are created
    correctly
    """
    ip_addr = "0001:db8:3333:4444:5555:6666:7777:8888"
    workflow = DDNSWorkflow(full_context)
    entries = workflow.get_expected_fw_entries(ip_addr)

    assert len(entries) == 3

    assert entries[0].ip_addr == ip_addr
    assert entries[0].protocol == Protocol.TCP
    assert entries[0].port == 80

    assert entries[1].ip_addr == ip_addr
    assert entries[1].protocol == Protocol.TCP
    assert entries[1].port == 443

    assert entries[2].ip_addr == ip_addr
    assert entries[2].protocol == Protocol.UDP
    assert entries[2].port == 1191


# pylint: disable=locally-disabled, redefined-outer-name
def test_expected_dns_entries_empty(empty_context):
    """Test that expected firewall entries are created
    correctly
    """
    ip_addr = "0001:db8:3333:4444:5555:6666:7777:8888"
    workflow = DDNSWorkflow(empty_context)
    records = workflow.get_expected_dns_records(ip_addr)

    assert not records


# pylint: disable=locally-disabled, redefined-outer-name
def test_expected_dns_entries(full_context):
    """Test that expected firewall entries are created
    correctly
    """
    ip_addr = "0001:db8:3333:4444:5555:6666:7777:8888"
    workflow = DDNSWorkflow(full_context)
    records = workflow.get_expected_dns_records(ip_addr)

    assert len(records) == 2

    assert records[0].ip_addr == ip_addr
    assert records[0].name == "example.com"
    assert records[0].ttl == 60

    assert records[1].ip_addr == ip_addr
    assert records[1].name == "site.example.com"
    assert records[1].ttl == 60


# pylint: disable=locally-disabled, redefined-outer-name
def test_ddns_works_correctly(full_context):
    """Test that expected firewall entries are created
    correctly
    """
    workflow = DDNSWorkflow(full_context)
    result = workflow.run()
    assert result == 0


# pylint: disable=locally-disabled, redefined-outer-name
def test_ddns_works_correctly_with_no(input_context, monkeypatch):
    """Test that expected firewall entries are created
    correctly
    """
    monkeypatch.setattr('builtins.input', lambda _: "n")
    workflow = DDNSWorkflow(input_context)
    result = workflow.run()
    assert result == 4

    monkeypatch.setattr('builtins.input', lambda _: "no")
    workflow = DDNSWorkflow(input_context)
    result = workflow.run()
    assert result == 4


# pylint: disable=locally-disabled, redefined-outer-name
def test_ddns_works_correctly_with_yes(input_context, monkeypatch):
    """Test that expected firewall entries are created
    correctly
    """
    monkeypatch.setattr('builtins.input', lambda _: "y")
    workflow = DDNSWorkflow(input_context)
    result = workflow.run()
    assert result == 0

    monkeypatch.setattr('builtins.input', lambda _: "yes")
    workflow = DDNSWorkflow(input_context)
    result = workflow.run()
    assert result == 0


# pylint: disable=locally-disabled, redefined-outer-name
def test_ddns_works_correctly_empty(empty_context):
    """Test that expected firewall entries are created
    correctly
    """
    workflow = DDNSWorkflow(empty_context)
    result = workflow.run()
    assert result == 0
