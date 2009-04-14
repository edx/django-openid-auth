#!/usr/bin/env python
# django-openid-auth -  OpenID integration for django.contrib.auth
#
# Copyright (C) 2009 Canonical Ltd.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
"""setup.py"""

from distutils.core import setup

setup(name = 'django-openid-auth',
    version = '0.1',
    description = 'OpenID integration for django.contrib.auth',
    long_description = """A library that can be used to add OpenID support to
    Django applications. The library integrates with Django's built in
    authentication system, so most applications require minimal changes to
    support OpenID llogin. The library also includes the following features:
    * Basic user details are transferred from the OpenID server via the simple
      Registration extension.
    * can be configured to use a fixed OpenID server URL, for use in SSO.
    * supports the launchpad.net teams extension to get team membership info.
    """,
    url = 'https://launchpad.net/django-openid-auth',
    packages = ['django_openid_auth',
                'django_openid_auth/management',
                'django_openid_auth/management/commands',
                'django_openid_auth/templates',
                'django_openid_auth/templates/openid',
                'django_openid_auth/tests',
                ],
    classifiers = ['Development Status :: 4 - Beta',
                   'Environment :: Web Environment',
                   'Framework :: Django',
                   'Intended Audience :: Developers',
                   'License :: OSI Approved :: BSD License',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python',
                   'Topic :: Utilities'])
