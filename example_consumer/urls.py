from django.conf.urls.defaults import *
from django.contrib import admin

import views


admin.autodiscover()

urlpatterns = patterns('',
    (r'^$', views.index),
    (r'^openid/', include('django_openid_auth.urls')),
    (r'^logout$', 'django.contrib.auth.views.logout'),
    (r'^private/$', views.require_authentication),

    (r'^admin/(.*)', admin.site.root),
)
