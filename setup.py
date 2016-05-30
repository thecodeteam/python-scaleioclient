# Copyright (c) 2015 - 2016 EMC Corporation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

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
        "Development Status :: 2 - Pre-Alpha",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License"],
    install_requires=[
        'requests',
        'urllib3',
        'enum34',
    ],
    scripts=glob("tests/functional/*"),
)
