# -*- coding: utf-8 -*-
"""steps/auth_steps.py -- authentication steps for testing the CAS consumer
"""
import urllib
from StringIO import StringIO

from behave import given, when, then

import mock


@given(u'an existing user')
def step(context):
    from django.contrib.auth.models import User
    context.user = User.objects.create(username='foo')
    context.users = [context.user]


@given(u'two existing users')
def step(context):
    from django.contrib.auth.models import User
    context.user = User.objects.create(username='foo')
    context.other_user = User.objects.create(username='bar')
    context.users = [context.user, context.other_user]


@given(u'no existing user')
def step(context):
    context.user = None
    context.users = []


@given(u'one user will be validated')
def step(context):
    context.verification_fo = StringIO('yes\nfoo\n')


@given(u'two users will be validated')
def step(context):
    context.verification_fo = StringIO('yes\nfoo\nbar\n')



@given(u'a validation ticket')
def step(context):
    context.ticket = 'bar'


@given(u'I am listening for CAS-related signals')
def step(context):
    from cas_consumer import signals
    context.merge_receiver = mock.Mock()
    context.merge_receiver_f = lambda *args, **kwargs: context.merge_receiver(*args, **kwargs)
    signals.on_cas_merge_users.connect(context.merge_receiver_f)

    context.auth_receiver = mock.Mock()
    context.auth_receiver_f = lambda *args, **kwargs: context.auth_receiver(*args, **kwargs)
    signals.on_cas_authentication.connect(context.auth_receiver_f)


@when(u'I authenticate against the CAS client backend')
def step(context):
    from cas_consumer import backends

    backend = context.backend = backends.CASBackend()
    with mock.patch.object(urllib, 'urlopen', new=mock.Mock(return_value = context.verification_fo)):
        context.authenticated_user = backend.authenticate(ticket='bar', service='http://example.com/service/')
        urllib.urlopen.assert_called_once_with('validate/?ticket=bar&service=http%3A%2F%2Fexample.com%2Fservice%2F')


@then(u'I receive the authenticated user')
def step(context):
    assert context.authenticated_user.id
    if context.user is not None:
        assert context.authenticated_user.id in [u.id for u in context.users], context.authenticated_user


@then(u'a user was created')
def step(context):
    from django.contrib.auth.models import User
    assert User.objects.all().count() == 1
    

@then(u'I receive the authentication signal')
def step(context):
    from cas_consumer import signals
    context.auth_receiver.assert_called_once_with(
        sender = context.backend,
        signal = signals.on_cas_authentication,
        user = context.authenticated_user,
        )


@then(u'I receive the merge signal')
def step(context):
    from cas_consumer import signals
    context.merge_receiver.assert_called_once_with(
        sender = context.backend,
        signal = signals.on_cas_merge_users,
        primary = context.authenticated_user,
        others = [u for u in context.users if u.id != context.authenticated_user.id],
        )
