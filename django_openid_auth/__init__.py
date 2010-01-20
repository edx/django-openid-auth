# django-openid-auth -  OpenID integration for django.contrib.auth
#
# Copyright (C) 2007 Simon Willison
# Copyright (C) 2008-2009 Canonical Ltd.
# Copyright (c) 2010 Dave Walker
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

""" Support for allowing openid authentication for /admin (django.contrib.admin) """

from django.conf import settings

try:
    if getattr(settings, 'OPENID_USE_AS_ADMIN_LOGIN', False):
        from django.http import HttpResponseRedirect
        from django.contrib.admin import sites
        from django_openid_auth import views

        def _openid_login(self, request, error_message='', extra_context=None):
            if request.user.is_authenticated():
                if not request.user.is_staff:
                    return views.render_failure(request, "User %s does not have admin access." 
                        % request.user.username)
                return views.render_failure(request, "Unknown Error: %s" % error_message)
            else:
                # Redirect to openid login path,
                return HttpResponseRedirect(settings.LOGIN_URL+"?next="+request.get_full_path())
            
        # Overide the standard admin login form. 
        sites.AdminSite.display_login_form = _openid_login

except:
    # An error occured overiding, silently fall back to upstream login form.
    pass


