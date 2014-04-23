from unittest import skipIf, TestLoader

from django import VERSION
from django.conf import settings
from django.test import TestCase


class SessionSerializerTest(TestCase):
    """Django 1.6 changed the default session serializer to use JSON
    instead of pickle for security reasons[0]. Unfortunately the
    openid module on which we rely stores objects which are not JSON
    serializable[1], so until this is fixed upstream (or we decide to
    create a wrapper serializer) we are recommending Django 1.6 users
    to fallback to the PickleSerializer.

    [0] https://bit.ly/1myzetd
    [1] https://github.com/openid/python-openid/issues/17
    """
    @skipIf(VERSION >= (1, 6, 0), "Old versions used the pickle serializer.")
    def test_not_using_json_session_serializer(self):
        # We use getattr because this setting did not exist in Django
        # 1.4 (pickle serialization was hard coded)
        serializer = getattr(settings, 'SESSION_SERIALIZER', '')
        self.assertNotEqual(
            serializer, 'django.contrib.sessions.serializers.JSONSerializer')

    @skipIf(VERSION < (1, 6, 0), "Newer versions use JSON by default.")
    def test_using_json_session_serializer(self):
        serializer = getattr(settings, 'SESSION_SERIALIZER', '')
        self.assertEqual(
            serializer, 'django.contrib.sessions.serializers.JSONSerializer')


def suite():
    return TestLoader().loadTestsFromName(__name__)
