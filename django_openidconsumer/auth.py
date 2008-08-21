"""Glue between OpenID and django.contrib.auth."""

from django.conf import settings
from django.contrib.auth.models import User
from openid.extensions import sreg

from models import UserOpenID


class IdentityAlreadyClaimed(Exception):
    pass


def get_user(openid_response):
    try:
        user_openid = UserOpenID.objects.get(
            claimed_id__exact=openid_response.identity_url)
    except UserOpenID.DoesNotExist:
        return None
    return user_openid.user


def find_unused_username(preferred_username):
    """Return an unused username, based on preferred_username."""
    i = 0
    while True:
        username = preferred_username
        if i > 0:
            username += str(i)
        try:
            User.objects.get(username__exact=username)
        except User.DoesNotExist:
            return username
        i += 1


def fill_user_details_from_sreg(user, sreg_response):
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


def create_user(openid_response):
    """Create a new user from an OpenID response."""
    sreg_response = sreg.SRegResponse.fromSuccessResponse(openid_response)
    if sreg_response:
        nickname = sreg_response.get('nickname', 'openiduser')
        email = sreg_response.get('email', '')
    else:
        nickname = 'openiduser'
        email = ''

    username = find_unused_username(nickname)
    user = User.objects.create_user(username, email)

    if sreg_response:
        fill_user_details_from_sreg(user, sreg_response)

    add_openid(user, openid_response)
    return user


def add_openid(user, openid_response):
    existing_user = get_user(openid_response)
    if existing_user is not None:
        if  existing_user != user:
            raise IdentityAlreadyClaimed(
                "The identity %s has already been claimed"
                % openid_response.identity_url)
        return

    user_openid = UserOpenID(
        user=user,
        claimed_id=openid_response.identity_url,
        display_id=openid_response.endpoint.getDisplayIdentifier())
    user_openid.save()


def openid_authenticate(openid_response):
    user = get_user(openid_response)
    if user is not None:
        if getattr(settings, 'OPENID_UPDATE_DETAILS_FROM_SREG', False):
            sreg_response = sreg.SRegResponse.fromSuccessResponse(
                openid_response)
            if sreg_response:
                fill_user_details_from_sreg(user, sreg_response)
    else:
        if getattr(settings, 'OPENID_CREATE_USERS', False):
            user = create_user(openid_response)

    # As we aren't using authenticate() here, we need to annotate the
    # user with the backend used.  We don't currently have one though,
    # so fake it.
    if user is not None:
        user.backend = 'django.contrib.auth.backends.ModelBackend'
    return user
