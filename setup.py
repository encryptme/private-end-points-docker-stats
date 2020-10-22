#!/usr/bin/env python

from distutils.core import setup


setup(
    name='encryptme_stats',
    version='0.10.0',
    description='Encrypt.me Statistics gatherer',
    author='Encrypt.me',
    author_email='hello@encrypt.me',
    packages=['encryptme_stats'],
    python_requires='>3.6',
    entry_points={
        'console_scripts': [
            'encryptme-stats = encryptme_stats:main',
        ]},
    install_requires=[
        'netifaces==0.10.6',
        'psutil==5.6.6',
        'uptime==3.0.1',
        'proc==0.14',
        'docker==2.5.1',
        'schedule==0.6.0',
        'requests==2.22.0',
        'parse==1.14.0',
        'vici==5.8.4',
    ],
)
