"""
setuptools script for ipv6ddns-dns-route53
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
    name = "ipv6ddns-dns-route53",
    version = "0.0.1",
    author = "skidmarkturbo",
    author_email = "skidmarkturbo@pm.me",
    description = ("DNS integration with Amazon Route53 for ipv6ddns."),
    license = "MIT",
    keywords = "ipv6ddns dns route53",
    url = "https://github.com/skidmarkturbo/ipv6ddns",
    packages=['ipv6ddns_dns_route53.route53'],
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 1 - Planning",
        "Topic :: Utilities",
        "License :: OSI Approved :: MIT License",
        "Environment :: Console",
    ],
    entry_points = {
        'ipv6ddns.plugin.dns': ['route53=ipv6ddns_dns_route53.route53:Route53DNSPlugin'],
    },
    install_requires = [],
)
