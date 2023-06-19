"""
Test the main method
"""
import pytest
from ipv6ddns.main import main


def test_main():
    """Test the main method
    """
    with pytest.raises(SystemExit) as sys_exit:
        main(["--dry-run"])

    assert sys_exit.type == SystemExit
    assert sys_exit.value.code == 0
