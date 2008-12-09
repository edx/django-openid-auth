"""Glue between OpenID and django.contrib.auth."""

__metaclass__ = type

from django.conf import settings
from django.contrib.auth.models import User, Group
from openid.consumer.consumer import SUCCESS
from openid.extensions import sreg

from django_openid_auth import teams
from django_openid_auth.models import UserOpenID


class IdentityAlreadyClaimed(Exception):
    pass


class OpenIDBackend:
    """A django.contrib.auth backend that authenticates the user based on
    an OpenID response."""

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def authenticate(self, **kwargs):
        """Authenticate the user based on an OpenID response."""
        # Require that the OpenID response be passed in as a keyword
        # argument, to make sure we don't match the username/password
        # calling conventions of authenticate.

        openid_response = kwargs.get('openid_response')
        if openid_response is None:
            return None

        if openid_response.status != SUCCESS:
            return None

        user = None
        try:
            user_openid = UserOpenID.objects.get(
                claimed_id__exact=openid_response.identity_url)
        except UserOpenID.DoesNotExist:
            if getattr(settings, 'OPENID_CREATE_USERS', False):
                user = self.create_user_from_openid(openid_response)
        else:
            user = user_openid.user

        if user is None:
            return None

        if getattr(settings, 'OPENID_UPDATE_DETAILS_FROM_SREG', False):
            sreg_response = sreg.SRegResponse.fromSuccessResponse(
                openid_response)
            if sreg_response:
                self.update_user_details_from_sreg(user, sreg_response)

        if getattr(settings, 'OPENID_UPDATE_GROUPS_FROM_LAUNCHPAD_TEAMS', False):
            teams_response = teams.TeamsResponse.fromSuccessResponse(
                openid_response)
            if teams_response:
                self.update_groups_from_teams(user, teams_response)

        return user

    def create_user_from_openid(self, openid_response):
        sreg_response = sreg.SRegResponse.fromSuccessResponse(openid_response)
        if sreg_response:
            nickname = sreg_response.get('nickname', 'openiduser')
            email = sreg_response.get('email', '')
        else:
            nickname = 'openiduser'
            email = ''

        # Pick a username for the user based on their nickname,
        # checking for conflicts.
        i = 1
        while True:
            username = nickname
            if i > 1:
                username += str(i)
            try:
                User.objects.get(username__exact=username)
            except User.DoesNotExist:
                break
            i += 1

        user = User.objects.create_user(username, email, password=None)

        if sreg_response:
            self.update_user_details_from_sreg(user, sreg_response)

        self.associate_openid(user, openid_response)
        return user

    def associate_openid(self, user, openid_response):
        """Associate an OpenID with a user account."""
        # Check to see if this OpenID has already been claimed.
        try:
            user_openid = UserOpenID.objects.get(
                claimed_id__exact=openid_response.identity_url)
        except UserOpenID.DoesNotExist:
            user_openid = UserOpenID(
                user=user,
                claimed_id=openid_response.identity_url,
                display_id=openid_response.endpoint.getDisplayIdentifier())
            user_openid.save()
        else:
            if user_openid.user != user:
                raise IdentityAlreadyClaimed(
                    "The identity %s has already been claimed"
                    % openid_response.identity_url)

        return user_openid

    def update_user_details_from_sreg(self, user, sreg_response):
        fullname = sreg_response.get('fullname')
        if fullname:
            # Do our best here ...
            if ' ' in fullname:
                user.first_name, user.last_name = fullname.rsplit(None, 1)
            else:
                user.first_name = u''
                user.last_name = fullname

        email = sreg_response.get('email')
        if email:
            user.email = email
        user.save()

    def update_groups_from_teams(self, user, teams_response):
        teams_mapping = getattr(settings, 'OPENID_LAUNCHPAD_TEAMS_MAPPING', {})
        resp_groups = set(Group.objects.get(name=teams_mapping[i])
                          for i in teams_response.is_member)
        user_groups = set(
            i for i in user.groups.filter(name__in=teams_mapping.values()))

        # the groups the user is in that aren't reported by openid
        # should be removed
        for group in user_groups - resp_groups:
            user.groups.remove(group)
        # and viceversa
        for group in resp_groups - user_groups:
            user.groups.add(group)
        user.save()
