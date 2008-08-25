from django.conf.urls.defaults import *


urlpatterns = patterns('',
    (r'^openid/', include('django_openid_auth.urls')),
)
