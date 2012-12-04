# -*- coding: utf-8 -*-
"""cas_consumer.backends -- authentication backend for CAS v1.0
"""
import logging
logger = logging.getLogger('cas.consumer')

import urllib2
import urllib
import gzip

try:
    from xml.etree import ElementTree
except ImportError:
    from elementtree import ElementTree

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from django.conf import settings

from django.contrib.auth.models import User

from . import signals


__all__ = ['CASBackend']


class _CASValidation(object):
    """Base class for CAS validation, non-protocol-specific.
    """
    protocol = None
    service = getattr(settings, 'CAS_SERVICE', None)
    cas_base = getattr(settings, 'CAS_BASE', '')
    cas_login = cas_base + getattr(settings, 'CAS_LOGIN_URL', '/cas/login/')
    cas_logout = cas_base + getattr(settings, 'CAS_LOGOUT_URL', '/cas/logout/')
    cas_next_default = getattr(settings, 'CAS_NEXT_DEFAULT', None)

    extra_validation_params = getattr(settings, 'CAS_EXTRA_VALIDATION_PARAMS', {})
    encode_params = getattr(settings, 'CAS_URLENCODE_PARAMS', True)

    def __init__(self, ticket, service):
        self.ticket = ticket
        self.service = service
        params = dict(self.extra_validation_params)
        params.update({getattr(settings, 'CAS_TICKET_LABEL', 'ticket'): ticket,
                       getattr(settings, 'CAS_SERVICE_LABEL', 'service'): service})
        url = self.cas_validate + '?'
        if self.encode_params:
            url += urllib.urlencode(params)
        else:
            raw_params = ['%s=%s' % (key, value) for key, value in params.items()]
            url += '&'.join(raw_params)

        page = None
        try:
            request = urllib2.Request(url)
            request.add_header('Accept-encoding', 'gzip')
            page = urllib2.urlopen(request)
            buf = StringIO(page.read())

            if page.info().get('Content-Encoding') == 'gzip':
                buf = gzip.GzipFile(fileobj=buf)
        except Exception:
            logger.exception('Validation encountered an error:')
            raise
        finally:
            if page is not None:
                page.close()

        self.url = url
        self.request = request
        self._buf = buf

    def __bool__(self):
        return self.success

    def __str__(self):
        return "<CAS %s via %s / %s: %s>" % (self.protocol, self.url, self.ticket, self.success)

    @property
    def _not_implemented(self):
        raise NotImplementedError()

    success = _not_implemented
    username = _not_implemented
    identifiers = _not_implemented
    attributes = _not_implemented


class CAS1Validation(_CASValidation):
    """CAS 1.0 validation
    """
    protocol = 1.0
    cas_validate = _CASValidation.cas_base + getattr(settings, 'CAS1_VALIDATE_URL', getattr(settings, 'CAS_VALIDATE_URL', 'validate/'))

    @property
    def success(self):
        if not hasattr(self, '_success'):
            self._buf.seek(0)
            self._success = self._buf.readline().strip() == 'yes'
            logger.info('Result: %s', self._success)
        return self._success

    @property
    def username(self):
        if not hasattr(self, '_username'):
            if self.success:
                self._username = self._buf.readline().strip()
            else:
                self._username = None
        return self._username

    @property
    def identifiers(self):
        if not hasattr(self, '_identifiers'):
            if self.success:
                self._identifiers = [self.username]
                self._identifiers.extend(u.strip() for u in self._buf.readlines() if u.strip())
            else:
                self._identifiers = []
        return self._identifiers

    @property
    def attributes(self):
        return {}


class CAS2Validation(_CASValidation):
    """CAS 2.0 validation
    """
    protocol = 2.0
    cas_validate = _CASValidation.cas_base + getattr(settings, 'CAS2_VALIDATE_URL', 'serviceValidate/')

    CAS_URI = 'http://www.yale.edu/tp/cas'
    CAS = '{%s}' % CAS_URI

    @property
    def tree(self):
        if not hasattr(self, '_tree'):
            self._buf.seek(0)
            self._tree = ElementTree.fromstring(self._buf.read())
        return self._tree

    @property
    def success(self):
        if not hasattr(self, '_success'):
            self._success = (self.tree.find(self.CAS + 'authenticationSuccess') is not None)
        return self._success

    @property
    def username(self):
        if not hasattr(self, '_username'):
            if self.success:
                self._username = self.tree.find('{CAS}authenticationSuccess/{CAS}user'.format(CAS=self.CAS)).text
            else:
                self._username = None
        return self._username

    @property
    def identifiers(self):
        if not hasattr(self, '_identifiers'):
            if self.success:
                self._identifiers = [self.username]
                identifiers = self.tree.findall('{CAS}authenticationSuccess/{CAS}attributes/{CAS}identifier'.format(CAS=self.CAS))
                if identifiers:
                    for el in identifiers:
                        self._identifiers.append(el.text)
            else:
                self._identifiers = []
        return self._identifiers

    @property
    def attributes(self):
        if not hasattr(self, '_attributes'):
            self._attributes = {}
            if self.success:
                xml_attributes = self.tree.find('{CAS}authenticationSuccess/{CAS}attributes'.format(CAS=self.CAS))
                if xml_attributes is not None:
                    for el in xml_attributes:
                        self._attributes[el.tag.replace(self.CAS, '')] = el.text
        return self._attributes


class CASBackend(object):
    """CAS authentication backend
    """
    protocol = getattr(settings, 'CAS_VALIDATION_PROTOCOL', 2)
    set_email = getattr(settings, 'CAS_SET_EMAIL_FROM_ATTRIBUTE', True)
    set_username = getattr(settings, 'CAS_SET_USERNAME_FROM_PRIMARY', False)

    def authenticate(self, ticket, service):
        """Verifies CAS ticket and gets or creates User object"""
        if self.protocol == 1:
            valid = CAS1Validation(ticket, service)
        elif self.protocol == 2:
            valid = CAS2Validation(ticket, service)
        else:
            valid = None
        logger.info('Authenticating against CAS %s: service = %s ; ticket = %s; identifiers %s\n%s', self.protocol, service, ticket, valid.identifiers, valid)
        if not valid or not valid.identifiers:
            return None
        # Select any users that match valid identifiers. Specify an ordering for consistent results.
        users = list(User.objects.filter(username__in=valid.identifiers, is_active=True).order_by('id'))
        logger.info('Authentication turned up %s users: %s', len(users), users)
        if users:
            user = None
            primary = valid.username
            for potential in users:
                # Try and pick a user that matches the primary identifier.
                if potential.username == primary:
                    user = potential
                    break
            if user is None:
                # Otherwise, pick the first in the result set.
                user = users[0]
            logger.info('Picking primary user: %s', user)

        else:
            logger.info('Creating new user for %s', valid.username)
            user = User(username=valid.username)
            user.set_unusable_password()
            if self.set_email and 'email' in valid.attributes:
                user.email = valid.attributes['email']
            user.save()

        if len(users) > 1:
            others = [u for u in users if u.username != user.username]
            logger.info('Sending merge signal for other users: %s', others)
            try:
                result = signals.on_cas_merge_users.send(sender=self, primary=user,
                                                         others=others)
            except Exception:
                logger.exception('Merge signal failed!')
            else:
                logger.info('Sent merge signal. Result: %s', result)

        if users:
            changed = False
            if (self.set_email
                and 'email' in valid.attributes
                and valid.attributes['email'] != user.email
                ):
                user.email = valid.attributes['email']
                changed = True

            if (self.set_username
                and user.username != primary
                ):
                user.username = primary
                changed = True

            if changed:
                user.save()

        logger.info('Authenticated user: %s' % user)

        signals.on_cas_authentication.send(sender=self, user=user, attributes=valid.attributes)
        return user

    def get_user(self, user_id):
        """Retrieve the user's entry in the User model if it exists"""
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
