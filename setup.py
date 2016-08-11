#
# Copyright (c) 2015 EMC Corporation
# All Rights Reserved
#
# This software contains the intellectual property of EMC Corporation
# or is licensed to EMC Corporation from third parties.  Use of this
# software and the intellectual property contained therein is expressly
# limited to the terms and conditions of the License Agreement under which
# it is provided by or on behalf of EMC.
#

""" Python distutils setup for siolib distribution """

import textwrap
from glob import glob
from setuptools import setup

distribution_name = "siolib"
main_module_name = 'siolib'
main_module = __import__(main_module_name)
version = main_module.__version__

main_module_doc = main_module.__doc__.decode('utf-8')
short_description, long_description = (
    textwrap.dedent(desc).strip()
    for desc in main_module_doc.split('\n\n', 1)
    )

setup(
    name=distribution_name,
    version=version,
    description=short_description,
    license=main_module.__license__,
    author=main_module.__author__,
    author_email=main_module.__author_email__,
    long_description=long_description,
    packages=['siolib'],
    include_package_data=True,
    test_suite="tests.unit.suite",
    classifiers=[
        # Reference: http://pypi.python.org/pypi?%3Aaction=list_classifiers
        "Development Status :: 4 - Beta",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",],
    install_requires=[
        'oslo.config>=3.7.0',
        'requests>=2.8.1,!=2.9.0',
        'urllib3>=1.8.3',
        'enum34',
    ],
    scripts=glob("tests/functional/*"),
)
