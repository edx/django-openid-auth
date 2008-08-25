import time
import unittest

from django.test import TestCase
from openid.association import Association as OIDAssociation
from openid.store.nonce import SKEW

from django_openid_auth.models import Association, Nonce
from django_openid_auth.store import DjangoOpenIDStore


class OpenIDStoreTests(TestCase):

    def setUp(self):
        self.store = DjangoOpenIDStore()

    def test_storeAssociation(self):
        assoc = OIDAssociation('handle', 'secret', 42, 600, 'HMAC-SHA1')
        self.store.storeAssociation('server-url', assoc)

        dbassoc = Association.objects.get(
            server_url='server-url', handle='handle')
        self.assertEquals(dbassoc.server_url, 'server-url')
        self.assertEquals(dbassoc.handle, 'handle')
        self.assertEquals(dbassoc.secret, 'secret'.encode('base-64'))
        self.assertEquals(dbassoc.issued, 42)
        self.assertEquals(dbassoc.lifetime, 600)
        self.assertEquals(dbassoc.assoc_type, 'HMAC-SHA1')

    def test_getAssociation(self):
        timestamp = int(time.time())
        self.store.storeAssociation(
            'server-url', OIDAssociation('handle', 'secret', timestamp, 600,
                                         'HMAC-SHA1'))
        assoc = self.store.getAssociation('server-url', 'handle')
        self.assertTrue(isinstance(assoc, OIDAssociation))

        self.assertEquals(assoc.handle, 'handle')
        self.assertEquals(assoc.secret, 'secret')
        self.assertEquals(assoc.issued, timestamp)
        self.assertEquals(assoc.lifetime, 600)
        self.assertEquals(assoc.assoc_type, 'HMAC-SHA1')

    def test_getAssociation_unknown(self):
        assoc = self.store.getAssociation('server-url', 'unknown')
        self.assertEquals(assoc, None)

    def test_getAssociation_expired(self):
        lifetime = 600
        timestamp = int(time.time()) - 2 * lifetime
        self.store.storeAssociation(
            'server-url', OIDAssociation('handle', 'secret', timestamp,
                                         lifetime, 'HMAC-SHA1'))

        # The association is not returned, and is removed from the database.
        assoc = self.store.getAssociation('server-url', 'handle')
        self.assertEquals(assoc, None)
        self.assertRaises(Association.DoesNotExist, Association.objects.get,
                          server_url='server-url', handle='handle')

    def test_getAssociation_no_handle(self):
        timestamp = int(time.time())

        self.store.storeAssociation(
            'server-url', OIDAssociation('handle1', 'secret', timestamp + 1,
                                         600, 'HMAC-SHA1'))
        self.store.storeAssociation(
            'server-url', OIDAssociation('handle2', 'secret', timestamp,
                                         600, 'HMAC-SHA1'))

        # The newest handle is returned.
        assoc = self.store.getAssociation('server-url', None)
        self.assertNotEquals(assoc, None)
        self.assertEquals(assoc.handle, 'handle1')
        self.assertEquals(assoc.issued, timestamp + 1)

    def test_removeAssociation(self):
        self.assertEquals(
            self.store.removeAssociation('server-url', 'unknown'), False)

        timestamp = int(time.time())
        self.store.storeAssociation(
            'server-url', OIDAssociation('handle', 'secret', timestamp, 600,
                                         'HMAC-SHA1'))
        self.assertEquals(
            self.store.removeAssociation('server-url', 'handle'), True)
        self.assertEquals(
            self.store.getAssociation('server-url', 'handle'), None)

    def test_useNonce(self):
        timestamp = time.time()
        # The nonce can only be used once.
        self.assertEqual(
            self.store.useNonce('server-url', timestamp, 'salt'), True)
        self.assertEqual(
            self.store.useNonce('server-url', timestamp, 'salt'), False)
        self.assertEqual(
            self.store.useNonce('server-url', timestamp, 'salt'), False)

    def test_useNonce_expired(self):
        timestamp = time.time() - 2 * SKEW
        self.assertEqual(
            self.store.useNonce('server-url', timestamp, 'salt'), False)

    def test_useNonce_future(self):
        timestamp = time.time() + 2 * SKEW
        self.assertEqual(
            self.store.useNonce('server-url', timestamp, 'salt'), False)

    def test_cleanupNonces(self):
        timestamp = time.time()
        self.assertEqual(
            self.store.useNonce('server1', timestamp, 'salt1'), True)
        self.assertEqual(
            self.store.useNonce('server2', timestamp, 'salt2'), True)
        self.assertEqual(
            self.store.useNonce('server3', timestamp, 'salt3'), True)
        self.assertEqual(Nonce.objects.count(), 3)

        self.assertEqual(
            self.store.cleanupNonces(_now=timestamp + 2 * SKEW), 3)
        self.assertEqual(Nonce.objects.count(), 0)

        # The nonces have now been cleared:
        self.assertEqual(
            self.store.useNonce('server1', timestamp, 'salt1'), True)
        self.assertEqual(
            self.store.cleanupNonces(_now=timestamp + 2 * SKEW), 1)
        self.assertEqual(
            self.store.cleanupNonces(_now=timestamp + 2 * SKEW), 0)

    def test_cleanupAssociations(self):
        timestamp = int(time.time()) - 100
        self.store.storeAssociation(
            'server-url', OIDAssociation('handle1', 'secret', timestamp,
                                         50, 'HMAC-SHA1'))
        self.store.storeAssociation(
            'server-url', OIDAssociation('handle2', 'secret', timestamp,
                                         200, 'HMAC-SHA1'))

        self.assertEquals(self.store.cleanupAssociations(), 1)

        # The second (non-expired) association is left behind.
        self.assertNotEqual(self.store.getAssociation('server-url', 'handle2'),
                            None)


def suite():
    return unittest.TestLoader().loadTestsFromName(__name__)
