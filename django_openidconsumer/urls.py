from django.conf.urls.defaults import patterns

urlpatterns = patterns('django_openidconsumer.views',
    (r'^login$', 'login_begin'),
    (r'^complete$', 'login_complete'),
)
