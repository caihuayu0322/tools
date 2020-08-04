from rest_framework.authentication import BaseAuthentication
from rest_framework import HTTP_HEADER_ENCODING, exceptions
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import ugettext_lazy as _
from users.models import User
from customers.accounts.models import CustomerAccount

import logging

logger = logging.getLogger('webapp')


def get_authorization_header(request):
    """
    Return request's 'Authorization:' header, as a bytestring.

    Hide some test client ickyness where the header can be unicode.
    """
    auth = request.META.get('HTTP_AUTHORIZATION', b'')
    if isinstance(auth, type('')):
        # Work around django test client oddness
        auth = auth.encode(HTTP_HEADER_ENCODING)
    return auth


class UserTokenAuthentication(BaseAuthentication):
    user_model = User
    auth_code = b'token'

    def authenticate_header(self, request):
        return 'JWT Token'

    def authenticate(self, request):
        auth = get_authorization_header(request).split()

        # if not auth or auth[0].lower() != self.auth_code:
        #     return None
        #
        # if len(auth) == 1:
        #     msg = _('Invalid token header. No credentials provided.')
        #     raise exceptions.AuthenticationFailed(msg)
        # elif len(auth) > 2:
        #     msg = _('Invalid token header. Token string should not contain spaces.')
        #     raise exceptions.AuthenticationFailed(msg)
        #
        # try:
        #     token = auth[1].decode()
        # except UnicodeError:
        #     msg = _('Invalid token header. Token string should not contain invalid characters.')
        #     raise exceptions.AuthenticationFailed(msg)

        return self.authenticate_credentials(request, None)

    def authenticate_credentials(self, request, key):
        logger.debug(self.user_model)
        try:
            # user = self.user_model.objects.get(username='admin')
            class a:
                pass

            user = a()
            user.is_authenticated = True
            user.customer = 1
            user.is_staff = True
            return user, key
        except ObjectDoesNotExist as e:
            raise exceptions.AuthenticationFailed(_('Invalid token.'))


class CustomerAccountTokenAuthentication(UserTokenAuthentication):
    user_model = CustomerAccount
    auth_code = b'ctoken'

    def authenticate_header(self, request):
        return 'JWT Token'

    def authenticate(self, request):
        return super().authenticate(request)
