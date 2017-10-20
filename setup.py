#!/usr/bin/env python

from distutils.core import setup

setup(name='encryptme_stats',
      version='0.9',
      description='Encrypt.me Statistics gatherer',
      author='Roy Hooper',
      author_email='rhooper@toybox.ca',
      packages=['encryptme_stats'],
      entry_points={
              'console_scripts': [
                  'encryptme-stats = encryptme_stats:main',
              ]}
     )