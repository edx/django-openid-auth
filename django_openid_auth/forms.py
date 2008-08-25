from django import forms
from django.utils.translation import ugettext as _
from django.conf import settings

from openid.yadis import xri


class OpenIDLoginForm(forms.Form):
    openid_identifier = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={'class': 'required openid'}))

    def clean_openid_identifier(self):
        if 'openid_identifier' in self.cleaned_data:
            openid_identifier = self.cleaned_data['openid_identifier']
            if xri.identifierScheme(openid_identifier) == 'XRI' and getattr(
                settings, 'OPENID_DISALLOW_INAMES', False
                ):
                raise forms.ValidationError(_('i-names are not supported'))
            return self.cleaned_data['openid_identifier']


