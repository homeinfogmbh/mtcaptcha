#! /usr/bin/env python3
"""Installation script."""

from setuptools import setup

setup(
    name='mtcaptcha',
    use_scm_version={
        "local_scheme": "node-and-timestamp"
    },
    setup_requires=['setuptools_scm'],
    author='HOMEINFO - Digitale Informationssysteme GmbH',
    author_email='<info@homeinfo.de>',
    maintainer='Richard Neumann',
    maintainer_email='<r.neumann@homeinfo.de>',
    install_requires=['pycryptodome'],
    py_modules=['mtcaptcha'],
    license='GPLv3',
    description='A library for validating MTCaptcha.'
)
