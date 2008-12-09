from django.core.management.base import NoArgsCommand

from django_openid_auth.store import DjangoOpenIDStore


class Command(NoArgsCommand):
    help = 'Clean up stale OpenID associations and nonces'

    def handle_noargs(self, **options):
        store = DjangoOpenIDStore()
        store.cleanup()
