= Django OpenID Authentication Support =

This package provides integration between Django's authentication
system and OpenID authentication.  It also includes support for using
a fixed OpenID server endpoint, which can be useful when implementing
single signon systems.


== Basic Installation ==

 1. Add 'django_auth_openid' to INSTALLED_APPS for your application.
    At a minimum, you'll need the following in there:

        INSTALLED_APPS = (
            'django.contrib.auth',
            'django.contrib.contenttypes',
            'django.contrib.sessions',
            'django_openid_auth',
        )

 2. Add 'django_auth_openid.auth.OpenIDBackend' to
    AUTHENTICATION_BACKENDS.  This should be in addition to the
    default ModelBackend:

        AUTHENTICATION_BACKENDS = (
            'django_openid_auth.auth.OpenIDBackend',
            'django.contrib.auth.backends.ModelBackend',
        )

 3. To create users automatically when a new OpenID is used, add the
    following to the settings:

        OPENID_CREATE_USERS = True

 4. To have user details updated from OpenID Simple Registration data
    each time they log in, add the following:

        OPENID_UPDATE_DETAILS_FROM_SREG = True

 5. Hook up the login URLs to your application's urlconf with
    something like:

        urlpatterns = patterns('',
            ...
            (r'^openid/', include('django_openid_auth.urls')),
            ...
        )

 6. Configure the LOGIN_URL and LOGIN_REDIRECT_URL appropriately for
    your site:

        LOGIN_URL = '/openid/login'
        LOGIN_REDIRECT_URL = '/'

    This will allow pages that use the standard @login_required
    decorator to use the OpenID login page.

 7. Rerun "python manage.py syncdb" to add the UserOpenID table to
    your database.


== Configuring Single Sign-On ==

If you only want to accept identities from a single OpenID server and
that server implemnts OpenID 2.0 identifier select mode, add the
following setting to your app:

    OPENID_SSO_SERVER_URL = 'server-endpoint-url'

With this setting enabled, the user will not be prompted to enter
their identity URL, and instead an OpenID authentication request will
be started with the given server URL.

As an example, to use Launchpad accounts for SSO, you'd use:

     OPENID_SSO_SERVER_URL = 'https://login.launchpad.net/'
