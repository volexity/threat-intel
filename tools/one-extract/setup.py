#! /usr/bin/env python3
# flake8: noqa

from setuptools import setup, find_packages
from onenoteextractor._version import __version__

main_ns = {}

setup(
    name             = "onenoteextractor",
    packages         = find_packages(),
    description      = "Simple extractor for OneNote files.",
    author           = "Volexity Threat Intelligence",
    author_email     = "threatintel@volexity.com",
    python_requires  = ">=3.6.8",
    entry_points     = {"console_scripts": ["one-extract = onenoteextractor.cli:run"]},
    include_package_data= True,
    install_requires = [],
    version=__version__
)
