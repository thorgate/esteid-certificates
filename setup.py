#!/usr/bin/env python
# -*- coding: utf-8 -*-

import esteid_certificates

from setuptools import setup

version = esteid_certificates.__version__

readme = open('README.md').read()

setup(
    name='esteid-certificates',
    version=version,
    description="Certificates for Estonian e-identity services",
    long_description=readme,
    long_description_content_type='text/markdown',
    author='Thorgate',
    author_email='info@thorgate.eu',
    url='https://github.com/thorgate/esteid-certificates',
    packages=[
        'esteid_certificates',
        'esteid_certificates.constants',
    ],
    include_package_data=True,
    install_requires=[],
    license="ISC",
    keywords='esteid asice xades smartid smart-id mobiilid mobileid mobile-id idcard',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
)
