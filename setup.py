"""
setuptools script for ipv6ddns
"""

import os
from setuptools import setup


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    """Utility function to read a file. Used for long_description.

    Args:
        fname (str): name of the file to read from the project root.

    Returns:
        str: text contents of the file
    """
    return open(os.path.join(os.path.dirname(__file__), fname), encoding="utf-8").read()


# pylint: disable=locally-disabled, duplicate-code
setup(
    name = "ipv6ddns",
    version = "0.0.1",
    author = "skidmarkturbo",
    author_email = "skidmarkturbo@pm.me",
    description = ("CLI for managing DDNS and firewall for IPV6 hosts."),
    license = "MIT",
    keywords = "ipv6 cli ddns firewall",
    url = "https://github.com/skidmarkturbo/ipv6ddns",
    packages=['ipv6ddns'],
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 1 - Planning",
        "Topic :: Utilities",
        "License :: OSI Approved :: MIT License",
        "Environment :: Console",
    ],
    entry_points = {
        'console_scripts': ['ipv6ddns=ipv6ddns.main:main'],
        'ipv6ddns.plugin.dns': ['noop=ipv6ddns.plugin:DNSPlugin'],
        'ipv6ddns.plugin.firewall': ['noop=ipv6ddns.plugin:FirewallPlugin'],
        'ipv6ddns.plugin.ipv6': ['noop=ipv6ddns.plugin:IPResolverPlugin'],
    },
    install_requires = [],
)
