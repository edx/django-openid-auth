from django import forms
from django.utils.translation import ugettext as _
from django.conf import settings

from openid.yadis import xri


class OpenIDLoginForm(forms.Form):
    openid_url = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={'class': 'required openid'}))

    def clean_openid_url(self):
        if 'openid_url' in self.cleaned_data:
            openid_url = self.cleaned_data['openid_url']
            if xri.identifierScheme(openid_url) == 'XRI' and getattr(
                settings, 'OPENID_DISALLOW_INAMES', False
                ):
                raise forms.ValidationError(_('i-names are not supported'))
            return self.cleaned_data['openid_url']


