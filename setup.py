#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

packages = [
    'cpkfile',
]

requirements = [
    'click',
    'jsonpickle'
]

setup(name='cpk-editor',
      version='0.1',
      install_requires=requirements,
      packages=packages,
      python_requires='>=3',
)
