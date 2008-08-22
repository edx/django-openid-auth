from django.conf.urls.defaults import *
import views

urlpatterns = patterns('',
    (r'^$', views.index),
    (r'^openid/', include('django_openid_auth.urls')),
    (r'^logout$', 'django.contrib.auth.views.logout'),
    (r'^private/$', views.require_authentication),
)
