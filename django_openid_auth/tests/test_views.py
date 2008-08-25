import cgi
import re
import time
import unittest

from django.conf import settings
from django.contrib.auth.models import User
from django.test import TestCase
from openid.fetchers import (
    HTTPFetcher, HTTPFetchingError, HTTPResponse, setDefaultFetcher)
from openid.oidutil import importElementTree
from openid.server.server import BROWSER_REQUEST_MODES, Server
from openid.store.memstore import MemoryStore

from django_openid_auth.models import UserOpenID


ET = importElementTree()


class StubOpenIDProvider(HTTPFetcher):

    def __init__(self, base_url):
        self.store = MemoryStore()
        self.identity_url = base_url + 'identity'
        self.endpoint_url = base_url + 'endpoint'
        self.server = Server(self.store, self.endpoint_url)
        self.last_request = None

    def fetch(self, url, body=None, headers=None):
        if url == self.identity_url:
            # Serve an XRDS document directly, which is the 
            return HTTPResponse(
                url, 200, {'content-type': 'application/xrds+xml'}, """\
<?xml version="1.0"?>
<xrds:XRDS
    xmlns="xri://$xrd*($v*2.0)"
    xmlns:xrds="xri://$xrds">
  <XRD>
    <Service priority="0">
      <Type>http://specs.openid.net/auth/2.0/signon</Type>
      <URI>%s</URI>
      <LocalID>%s</LocalID>
    </Service>
  </XRD>
</xrds:XRDS>
""" % (self.endpoint_url, self.identity_url))
        elif url.startswith(self.endpoint_url):
            # Gather query parameters
            query = {}
            if '?' in url:
                query.update(cgi.parse_qsl(url.split('?', 1)[1]))
            if body is not None:
                query.update(cgi.parse_qsl(body))
            self.last_request = self.server.decodeRequest(query)

            # The browser based requests should not be handled through
            # the fetcher interface.
            assert self.last_request.mode not in BROWSER_REQUEST_MODES

            response = self.server.handleRequest(self.last_request)
            webresponse = self.server.encodeResponse(response)
            return HTTPResponse(url,  webresponse.code, webresponse.headers,
                                webresponse.body)
        else:
            raise HTTPFetchingError('unknown URL %s' % url)

    def parseFormPost(self, content):
        """Parse an HTML form post to create an OpenID request."""
        # Hack to make the javascript XML compliant ...
        content = content.replace('i < elements.length',
                                  'i &lt; elements.length')
        tree = ET.XML(content)
        form = tree.find('.//form')
        assert form is not None, 'No form in document'
        assert form.get('action') == self.endpoint_url, (
            'Form posts to %s instead of %s' % (form.get('action'),
                                                self.endpoint_url))
        query = {}
        for input in form.findall('input'):
            if input.get('type') != 'hidden':
                continue
            query[input.get('name').encode('UTF-8')] = \
                input.get('value').encode('UTF-8')
        self.last_request = self.server.decodeRequest(query)
        return self.last_request


class RelyingPartyTests(TestCase):
    urls = 'django_openid_auth.tests.urls'

    def setUp(self):
        super(RelyingPartyTests, self).setUp()
        self.provider = StubOpenIDProvider('http://example.com/')
        setDefaultFetcher(self.provider, wrap_exceptions=False)

        self.old_create_users = getattr(settings, 'OPENID_CREATE_USERS', False)
        self.old_update_details = getattr(settings, 'OPENID_UPDATE_DETAILS_FROM_SREG', False)
        self.old_sso_server_url = getattr(settings, 'OPENID_SSO_SERVER_URL')
        settings.OPENID_CREATE_USERS = False
        settings.OPENID_UPDATE_DETAILS_FROM_SREG = False
        settings.OPENID_SSO_SERVER_URL = None

    def tearDown(self):
        settings.OPENID_CREATE_USERS = self.old_create_users
        settings.OPENID_UPDATE_DETAILS_FROM_SREG = self.old_update_details
        settings.OPENID_SSO_SERVER_URL = self.old_sso_server_url

        setDefaultFetcher(None)
        super(RelyingPartyTests, self).tearDown()

    def complete(self, openid_response):
        """Complete an OpenID authentication request."""
        webresponse = self.provider.server.encodeResponse(openid_response)
        self.assertEquals(webresponse.code, 302)
        redirect_to = webresponse.headers['location']
        self.assertTrue(redirect_to.startswith(
                'http://testserver/openid/complete'))
        return self.client.get('/openid/complete',
            dict(cgi.parse_qsl(redirect_to.split('?', 1)[1])))

    def test_login_sso(self):
        settings.OPENID_SSO_SERVER_URL = 'http://example.com/identity'
        user = User.objects.create_user('someuser', 'someone@example.com')
        useropenid = UserOpenID(
            user=user,
            claimed_id='http://example.com/identity',
            display_id='http://example.com/identity')
        useropenid.save()

        response = self.client.get('/openid/login', {'next': '/getuser'})
        self.assertEquals(response.status_code, 200)
        self.assertContains(response, 'OpenID transaction in progress')

        openid_request = self.provider.parseFormPost(response.content)
        self.assertEquals(openid_request.mode, 'checkid_setup')
        self.assertTrue(openid_request.return_to.startswith(
                'http://testserver/openid/complete'))

        # Complete the request.  The user is redirected to the next URL.
        openid_response = openid_request.answer(True)
        response = self.complete(openid_response)
        self.assertRedirects(response, 'http://testserver/getuser')

        # And they are now logged in:
        response = self.client.get('/getuser')
        self.assertEquals(response.content, 'someuser')


def suite():
    return unittest.TestLoader().loadTestsFromName(__name__)
