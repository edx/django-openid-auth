from django.conf.urls.defaults import patterns

urlpatterns = patterns('django_openid_auth.views',
    (r'^login$', 'login_begin'),
    (r'^complete$', 'login_complete'),
)
