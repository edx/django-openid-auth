from django.http import HttpResponse, HttpResponseRedirect, get_host
from django.shortcuts import render_to_response as render
from django.template import RequestContext
from django.conf import settings
from django.utils.http import urlquote_plus, urlquote

import md5, re, time, urllib
from openid.consumer.consumer import Consumer, \
    SUCCESS, CANCEL, FAILURE, SETUP_NEEDED
from openid.consumer.discover import DiscoveryFailure
from openid.yadis import xri


from util import OpenID, DjangoOpenIDStore, from_openid_response

from forms import OpenidSigninForm

from django.utils.html import escape

def get_url_host(request):
    if request.is_secure():
        protocol = 'https'
    else:
        protocol = 'http'
    host = escape(get_host(request))
    return '%s://%s' % (protocol, host)

def get_full_url(request):
    if request.is_secure():
        protocol = 'https'
    else:
        protocol = 'http'
    host = escape(request.META['HTTP_HOST'])
    return get_url_host(request) + request.get_full_path()

next_url_re = re.compile('^/[-\w/]+$')

def is_valid_next_url(next):
    # When we allow this:
    #   /openid/?next=/welcome/
    # For security reasons we want to restrict the next= bit to being a local 
    # path, not a complete URL.
    return bool(next_url_re.match(next))

def begin(request, sreg=None, extension_args=None, redirect_to=None, 
        on_failure=None):
    
    on_failure = on_failure or default_on_failure
    extension_args = extension_args or {}
    
    next = ''
    if request.GET.get('next'):
        next = urllib.urlencode({
            'next': request.GET['next']
        })
        
  
    form_signin = OpenidSigninForm(initial={'next':next})
    if request.POST:
        form_signin = OpenidSigninForm(request.POST)
        if form_signin.is_valid():
            consumer = Consumer(request.session, DjangoOpenIDStore())
            try:
                auth_request = consumer.begin(form_signin.cleaned_data['openid_url'])
            except DiscoveryFailure:
                return on_failure(request, "The OpenID was invalid")

            if sreg:
                extension_args['sreg.optional'] = sreg
            
            trust_root = getattr(
                    settings, 'OPENID_TRUST_ROOT', get_url_host(request) + '/'
                )
        
            redirect_to = redirect_to or getattr(
                settings, 'OPENID_REDIRECT_TO',
                # If not explicitly set, assume current URL with complete/ appended
                get_full_url(request).split('?')[0] + 'complete/'
            )

            # TODO: add redirect_to in form 
            if not redirect_to.startswith('http://'):
                redirect_to =  get_url_host(request) + redirect_to


            if 'next' in form_signin.cleaned_data and next != "":
                if '?' in redirect_to:
                    join = '&'
                else:
                    join = '?'
                redirect_to += join + urllib.urlencode({
                    'next': form_signin.cleaned_data['next']
                })
    
            # Add extension args (for things like simple registration)
            for name, value in extension_args.items():
                namespace, key = name.split('.', 1)
                auth_request.addExtensionArg(namespace, key, value)
    
            redirect_url = auth_request.redirectURL(trust_root, redirect_to)
            return HttpResponseRedirect(redirect_url)

    return render('openid_signin.html', {
            'form': form_signin,
            'action': request.path,
            'logo': request.path + 'logo/',
            'openids': request.session.get('openids', []),
        })
    
def complete(request, on_success=None, on_failure=None):
    on_success = on_success or default_on_success
    on_failure = on_failure or default_on_failure
    

    redirect_to = getattr(
        settings, 'OPENID_REDIRECT_TO',
        get_full_url(request).split('?')[0]
        )

    consumer = Consumer(request.session, DjangoOpenIDStore())
    openid_response = consumer.complete(dict(request.GET.items()), redirect_to)

    if openid_response.status == SUCCESS:
        return on_success(request, openid_response.identity_url, openid_response)
    elif openid_response.status == CANCEL:
        return on_failure(request, 'The request was cancelled')
    elif openid_response.status == FAILURE:
        return on_failure(request, openid_response.message)
    elif openid_response.status == SETUP_NEEDED:
        return on_failure(request, 'Setup needed')
    else:
        assert False, "Bad openid status: %s" % openid_response.status

def default_on_success(request, identity_url, openid_response):
    if 'openids' not in request.session.keys():
        request.session['openids'] = []
    
    # Eliminate any duplicates
    request.session['openids'] = [
        o for o in request.session['openids'] if o.openid != identity_url
    ]
    request.session['openids'].append(from_openid_response(openid_response))
    
    next = request.GET.get('next', '').strip()
    if not next or not is_valid_next_url(next):
        next = getattr(settings, 'OPENID_REDIRECT_NEXT', '/')
    
    return HttpResponseRedirect(next)

def default_on_failure(request, message):
    return render('openid_failure.html', {
        'message': message
    })

def signout(request):
    request.session['openids'] = []
    next = request.GET.get('next', '/')
    if not is_valid_next_url(next):
        next = '/'
    return HttpResponseRedirect(next)

def logo(request):
    return HttpResponse(
        OPENID_LOGO_BASE_64.decode('base64'), mimetype='image/gif'
    )

# Logo from http://openid.net/login-bg.gif
# Embedded here for convenience; you should serve this as a static file
OPENID_LOGO_BASE_64 = """
R0lGODlhEAAQAMQAAO3t7eHh4srKyvz8/P5pDP9rENLS0v/28P/17tXV1dHEvPDw8M3Nzfn5+d3d
3f5jA97Syvnv6MfLzcfHx/1mCPx4Kc/S1Pf189C+tP+xgv/k1N3OxfHy9NLV1/39/f///yH5BAAA
AAAALAAAAAAQABAAAAVq4CeOZGme6KhlSDoexdO6H0IUR+otwUYRkMDCUwIYJhLFTyGZJACAwQcg
EAQ4kVuEE2AIGAOPQQAQwXCfS8KQGAwMjIYIUSi03B7iJ+AcnmclHg4TAh0QDzIpCw4WGBUZeikD
Fzk0lpcjIQA7
"""
