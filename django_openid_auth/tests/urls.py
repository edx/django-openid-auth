from django.http import HttpResponse
from django.conf.urls.defaults import *


def get_user(request):
    return HttpResponse(request.user.username)

urlpatterns = patterns('',
    (r'^getuser', get_user),
    (r'^openid/', include('django_openid_auth.urls')),
)
