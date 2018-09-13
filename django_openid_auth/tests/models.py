from django.conf import settings
from django.contrib.auth.models import Group
from django.db import models


class UserGroup(models.Model):

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.deletion.CASCADE)
    group = models.ForeignKey(
        Group,
        on_delete=models.deletion.CASCADE)
