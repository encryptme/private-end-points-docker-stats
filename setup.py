#!/usr/bin/env python

from distutils.core import setup

setup(name='encryptme_stats',
      version='0.9.15',
      description='Encrypt.me Statistics gatherer',
      author='Roy Hooper',
      author_email='rhooper@toybox.ca',
      packages=['encryptme_stats'],
      entry_points={
              'console_scripts': [
                  'encryptme-stats = encryptme_stats:main',
              ]},
      install_requires=[
          'netifaces==0.10.6',
          'psutil==5.4.0',
          'uptime==3.0.1',
          'proc==0.14',
          'docker==2.5.1',
          'schedule==0.4.3',
          'requests==2.18.4',
          'parse==1.14.0',
      ],
     )
