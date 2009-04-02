from django.contrib import admin
from django_openid_auth.models import Nonce, Association, UserOpenID
from django_openid_auth.store import DjangoOpenIDStore


class NonceAdmin(admin.ModelAdmin):
    list_display = ('server_url', 'timestamp')
    actions = ['cleanup_nonces']

    def cleanup_nonces(self, request, queryset):
        store = DjangoOpenIDStore()
        count = store.cleanupNonces()
        self.message_user(request, "%d expired nonces removed" % count)
    cleanup_nonces.short_description = "Clean up expired nonces"

admin.site.register(Nonce, NonceAdmin)


class AssociationAdmin(admin.ModelAdmin):
    list_display = ('server_url', 'assoc_type')
    list_filter = ('assoc_type',)
    search_fields = ('server_url',)
    actions = ['cleanup_associations']

    def cleanup_associations(self, request, queryset):
        store = DjangoOpenIDStore()
        count = store.cleanupAssociations()
        self.message_user(request, "%d expired associations removed" % count)
    cleanup_associations.short_description = "Clean up expired associations"

admin.site.register(Association, AssociationAdmin)


class UserOpenIDAdmin(admin.ModelAdmin):
    list_display = ('user', 'claimed_id')
    search_fields = ('claimed_id',)

admin.site.register(UserOpenID, UserOpenIDAdmin)
