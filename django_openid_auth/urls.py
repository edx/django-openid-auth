from django.conf.urls.defaults import *

urlpatterns = patterns('django_openid_auth.views',
    (r'^login$', 'login_begin'),
    (r'^complete$', 'login_complete'),
    url(r'^logo$', 'logo', name='openid-logo'),
)
