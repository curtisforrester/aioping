#!/usr/bin/env python
# coding: utf-8

"""
    distutils setup
    ~~~~~~~~~~~~~~~

    :homepage: https://github.com/M-o-a-T/aioping/
    :copyleft: 1989-2016 by the python-ping team, see AUTHORS for more details.
    :license: GNU GPL v2, see LICENSE for more details.
"""

import os
import sys
from setuptools import setup
import pkg_version_mgr as pv
import aioping.version as version

PACKAGE_ROOT = os.path.dirname(os.path.abspath(__file__))


# convert creole to ReSt on-the-fly, see also:
# https://github.com/jedie/python-creole/wiki/Use-In-Setup
# TODO: Migrate from using `get_long_description` since it's deprecated
try:
    # noinspection PyPackageRequirements
    from creole.setup_utils import get_long_description
except ImportError:
    if "register" in sys.argv or "sdist" in sys.argv or "--long-description" in sys.argv:
        etype, evalue, etb = sys.exc_info()
        evalue = etype("%s - Please install python-creole >= v0.8 -  e.g.: pip install python-creole" % evalue)
        raise etype(evalue).with_traceback(etb)
    long_description = None
else:
    long_description = get_long_description(PACKAGE_ROOT)


def get_authors():
    with open(os.path.join(PACKAGE_ROOT, 'AUTHORS')) as fp:
        lines = [line.strip().lstrip('* ') for line in fp if "* " in line]
        lines = [line.split('--', 1) for line in lines if '--' in line]

    return sorted(lines)


ver_mgr = pv.PkgVersionMgr(major=0, minor=6, micro=0, suffix='dev', suffix_num=1)


setup(
    version=ver_mgr.version(target_module=version),
    long_description=long_description,
    author=get_authors(),
    author_email="matthias@urlichs.de",
    maintainer="Curtis Forrester",
    maintainer_email="crforresterspam@pm.me",
    zip_safe=False,
    install_requires=['pkg-version-mgr', 'python-creole'],
)
