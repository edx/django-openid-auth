from django.conf.urls.defaults import *
import views

urlpatterns = patterns('',
    (r'^$', views.index),
    (r'^openid/login$', 'django_openid_auth.views.login_begin'),
    (r'^openid/login/complete$', 'django_openid_auth.views.login_complete'),
    (r'^openid/logout$', 'django.contrib.auth.views.logout'),
    (r'^private/$', views.require_authentication),
)
