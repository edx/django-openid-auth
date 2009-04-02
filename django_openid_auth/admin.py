from django.contrib import admin
from django_openid_auth.models import Nonce, Association, UserOpenID


class NonceAdmin(admin.ModelAdmin):
    list_display = ('server_url', 'timestamp')

admin.site.register(Nonce, NonceAdmin)

class AssociationAdmin(admin.ModelAdmin):
    list_display = ('server_url', 'assoc_type')
    list_filter = ('assoc_type',)

admin.site.register(Association, AssociationAdmin)

class UserOpenIDAdmin(admin.ModelAdmin):
    list_display = ('user', 'claimed_id', 'display_id')
    search_fields = ('user',)

admin.site.register(UserOpenID, UserOpenIDAdmin)
