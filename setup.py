"""
 Copyright (c) 2023 skidmarkturbo

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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
    },
    install_requires = [],
)
