from django.conf.urls.defaults import *
import views

urlpatterns = patterns('',
    (r'^$', views.index),
    (r'^openid/login$', 'django_openidconsumer.views.login_begin'),
    (r'^openid/login/complete$', 'django_openidconsumer.views.login_complete'),
    (r'^openid/logout$', 'django.contrib.auth.views.logout'),
    (r'^next-works/$', views.next_works),
)
