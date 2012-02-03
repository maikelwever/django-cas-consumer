# -*- coding: utf-8 -*-
"""cas_consumer.backends -- authentication backend for CAS v1.0
"""
import logging
logger = logging.getLogger('cas.consumer')

import urllib
from urlparse import urljoin

from django.conf import settings

from django.contrib.auth.models import User, UNUSABLE_PASSWORD

from . import signals


__all__ = ['CASBackend']


class CASBackend(object):
    """CAS authentication backend"""
    service = getattr(settings, 'CAS_SERVICE', None)
    cas_base = getattr(settings, 'CAS_BASE', '')
    cas_login = cas_base + getattr(settings, 'CAS_LOGIN_URL', '/cas/login/')
    cas_validate = cas_base + getattr(settings, 'CAS_VALIDATE_URL', '/cas/validate/')
    cas_logout = cas_base + getattr(settings, 'CAS_LOGOUT_URL', '/cas/logout/')
    cas_next_default = getattr(settings, 'CAS_NEXT_DEFAULT', None)

    extra_validation_params = getattr(settings, 'CAS_EXTRA_VALIDATION_PARAMS', {})
    encode_params = getattr(settings, 'CAS_URLENCODE_PARAMS', True)

    def authenticate(self, ticket, service):
        """Verifies CAS ticket and gets or creates User object"""
        logger.info('Authenticating against CAS: service = %s ; ticket = %s', service, ticket)
        usernames = self._verify_cas1(ticket, service)
        if not usernames:
            return None
        users = list(User.objects.filter(username__in=usernames))
        logger.info('Authentication turned up %s users: %s', len(users), users)
        if users:
            user = users[0]
            logger.info('Picking primary user: %s', user)
        else:
            logger.info('Creating new user for %s', usernames[0])
            user = User(username=usernames[0])
            user.set_unusable_password()
            user.save()

        if len(users) > 1:
            logger.info('Sending merge signal for other users: %s', users[1:])
            signals.on_cas_merge_users.send(sender=self, primary=user, others=users[1:])

        logger.info('Authenticated user: %s' % user)
        signals.on_cas_authentication.send(sender=self, user=user)
        return user

    def get_user(self, user_id):
        """Retrieve the user's entry in the User model if it exists"""
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def _verify_cas1(self, ticket, service):
        """Verifies CAS 1.0 authentication ticket.

        Returns validated username(s) on success and None on failure.
        """
        params = dict(self.extra_validation_params)
        params.update({getattr(settings, 'CAS_TICKET_LABEL', 'ticket'): ticket,
                       getattr(settings, 'CAS_SERVICE_LABEL', 'service'): service})
        url = self.cas_validate + '?'
        if self.encode_params:
            url += urllib.urlencode(params)
        else:
            raw_params = ['%s=%s' % (key, value) for key, value in params.items()]
            url += '&'.join(raw_params)
        logger.info('Validating at %s', url)

        page = urllib.urlopen(url)
        try:
            verified = page.readline().strip()
            logger.info('Result: %s', verified)
            if verified == 'yes':
                usernames = [u.strip() for u in page.readlines() if u.strip()]
                logger.info('Verified %s usernames: %s' % (len(usernames), usernames))
                return usernames
        except Exception:
            logger.exception('Validation encountered an error:')
        finally:
            page.close()

        return []
