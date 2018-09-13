# django-openid-auth -  OpenID integration for django.contrib.auth
#
# Copyright (C) 2007 Simon Willison
# Copyright (C) 2008-2013 Canonical Ltd.
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

from __future__ import unicode_literals

import base64
import time

from openid.association import Association as OIDAssociation
from openid.store.interface import OpenIDStore
from openid.store.nonce import SKEW

from django_openid_auth import PY3
from django_openid_auth.models import Association, Nonce


class DjangoOpenIDStore(OpenIDStore):

    def __init__(self):
        super(DjangoOpenIDStore, self).__init__()
        self.max_nonce_age = 6 * 60 * 60  # Six hours

    def storeAssociation(self, server_url, association):
        try:
            assoc = Association.objects.get(
                server_url=server_url, handle=association.handle)
            if isinstance(assoc.secret, str) and PY3:
                try:
                    assoc.secret = assoc.secret.split("b'")[1].split("'")[0]
                except Exception:
                    pass
                assoc.secret = bytes(assoc.secret, 'utf-8')
        except Association.DoesNotExist:
            if isinstance(association.secret, str) and PY3:
                association.secret = association.secret.split("b'")[1].split("'")[0]
                association.secret = bytes(association.secret, 'utf-8')
            assoc = Association(
                server_url=server_url,
                handle=association.handle,
                secret=base64.encodestring(association.secret),
                issued=association.issued,
                lifetime=association.lifetime,
                assoc_type=association.assoc_type)
        else:
            if isinstance(assoc.secret, str) and PY3:
                try:
                    assoc.secret = assoc.secret.split("b'")[1].split("'")[0]
                except Exception:
                    pass
                assoc.secret = bytes(assoc.secret, 'utf-8')
            assoc.secret = base64.encodestring(association.secret)
            assoc.issued = association.issued
            assoc.lifetime = association.lifetime
            assoc.assoc_type = association.assoc_type
        if isinstance(assoc.secret, bytes) and PY3:
            assoc.secret = bytes(assoc.secret.decode('utf-8').rstrip(), 'utf-8')
        assoc.save()

    def getAssociation(self, server_url, handle=None):
        assocs = []
        if handle is not None:
            assocs = Association.objects.filter(
                server_url=server_url, handle=handle)
        else:
            assocs = Association.objects.filter(server_url=server_url)
        associations = []
        expired = []
        for assoc in assocs:
            if isinstance(assoc.secret, str) and PY3:
                try:
                    assoc.secret = assoc.secret.split("b'")[1].split("'")[0]
                except Exception:
                    pass
                assoc.secret = bytes(assoc.secret, 'utf-8')
            if isinstance(assoc.secret, bytes) and PY3:
                assoc.secret = bytes(assoc.secret.decode('utf-8').rstrip(), 'utf-8')
            if PY3:
                decoded = base64.decodebytes(assoc.secret)
            else:
                decoded = base64.decodestring(assoc.secret)
            association = OIDAssociation(
                assoc.handle,
                decoded,
                assoc.issued, assoc.lifetime, assoc.assoc_type
            )
            if PY3:
                expires_in = association.expiresIn
            else:
                expires_in = association.getExpiresIn()
            if expires_in == 0:
                expired.append(assoc)
            else:
                associations.append((association.issued, association))
        for assoc in expired:
            assoc.delete()
        if not associations:
            return None
        associations.sort()
        return associations[-1][1]

    def removeAssociation(self, server_url, handle):
        assocs = list(Association.objects.filter(
            server_url=server_url, handle=handle))
        assocs_exist = len(assocs) > 0
        for assoc in assocs:
            assoc.delete()
        return assocs_exist

    def useNonce(self, server_url, timestamp, salt):
        if abs(timestamp - time.time()) > SKEW:
            return False

        try:
            ononce = Nonce.objects.get(
                server_url__exact=server_url,
                timestamp__exact=timestamp,
                salt__exact=salt)
        except Nonce.DoesNotExist:
            ononce = Nonce(
                server_url=server_url,
                timestamp=timestamp,
                salt=salt)
            ononce.save()
            return True

        return False

    def cleanupNonces(self, _now=None):
        if _now is None:
            _now = int(time.time())
        expired = Nonce.objects.filter(timestamp__lt=_now - SKEW)
        count = expired.count()
        if count:
            expired.delete()
        return count

    def cleanupAssociations(self):
        now = int(time.time())
        expired = Association.objects.extra(
            where=['issued + lifetime < %d' % now])
        count = expired.count()
        if count:
            expired.delete()
        return count
