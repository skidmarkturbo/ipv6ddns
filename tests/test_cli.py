"""
Tests for CLI
"""
import pytest
from ipv6ddns.cli import Cli


def test_cli_help():
    """Tests calling help doesn't crash
    """
    cli = Cli(cli_args=["--help"])

    with pytest.raises(SystemExit) as sys_exit:
        cli.execute()
    assert sys_exit.type == SystemExit
    assert sys_exit.value.code == 0

    cli = Cli(cli_args=["-h"])

    with pytest.raises(SystemExit) as sys_exit:
        cli.execute()
    assert sys_exit.type == SystemExit
    assert sys_exit.value.code == 0


def test_cli_returns_zero_code():
    """Tests when cli exits code 0
    """
    args = [
        "--domain", "example.com",
        "--domain", "site.example.com",
        "--tcp-port", "80",
        "--tcp-port", "443",
        "--udp-port", "1191",
        "--assume-yes"
    ]
    cli = Cli(cli_args=args)

    with pytest.raises(SystemExit) as sys_exit:
        cli.execute()
    assert sys_exit.type == SystemExit
    assert sys_exit.value.code == 0


def test_cli_returns_non_zero_code(monkeypatch):
    """Tests when cli exits code 0
    """
    monkeypatch.setattr('builtins.input', lambda _: "n")
    
    args = [
        "--domain", "example.com",
        "--domain", "site.example.com",
        "--tcp-port", "80",
        "--tcp-port", "443",
        "--udp-port", "1191"
    ]
    cli = Cli(cli_args=args)

    with pytest.raises(SystemExit) as sys_exit:
        cli.execute()
    assert sys_exit.type == SystemExit
    assert sys_exit.value.code == 4

def test_dry_run_and_force_together():
    """Test that using --dry-run and --force together
    raises error
    """
    cli = Cli(cli_args=["--dry-run", "--force"])

    with pytest.raises(SystemExit) as sys_exit:
        cli.execute()
    assert sys_exit.type == SystemExit
    assert sys_exit.value.code == 3

    cli = Cli(cli_args=["--dry-run", "-f"])

    with pytest.raises(SystemExit) as sys_exit:
        cli.execute()
    assert sys_exit.type == SystemExit
    assert sys_exit.value.code == 3
