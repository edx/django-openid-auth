from django.http import HttpResponse

from django.utils.html import escape

def index(request):
    s = ['<p>']
    if request.user.is_authenticated():
        s.append('You are signed in as <strong>%s</strong> (%s)' % (
                escape(request.user.username),
                escape(request.user.get_full_name())))
        s.append(' | <a href="/openid/logout">Sign out</a>')
    else:
        s.append('<a href="/openid/login">Sign in with OpenID</a>')

    s.append('</p>')
    return HttpResponse('\n'.join(s))

def next_works(request):
    return HttpResponse('?next= bit works. <a href="/">Home</a>')
