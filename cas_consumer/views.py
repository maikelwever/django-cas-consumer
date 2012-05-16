# -*- coding: utf-8 -*-
"""cas_consumer.views -- authentication views for the CAS consumer.
"""
import urlparse
from django.http import HttpResponseForbidden, HttpResponseRedirect
from django.contrib.auth import authenticate
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.conf import settings
try:
    from django.contrib import messages
except ImportError:
    messages = None

__all__ = ['login', 'logout']

service = settings.CAS_SERVICE
cas_base = settings.CAS_BASE
cas_login = cas_base + settings.CAS_LOGIN_URL
cas_validate = cas_base + settings.CAS_VALIDATE_URL
cas_logout = cas_base + settings.CAS_LOGOUT_URL
cas_next_default = settings.CAS_NEXT_DEFAULT
cas_redirect_on_logout = settings.CAS_REDIRECT_ON_LOGOUT


def login(request, redirect_field_name=REDIRECT_FIELD_NAME):
    """ Fairly standard login view.

        1. Checks request.GET for a service ticket.
        2. If there is NOT a ticket, redirects to the CAS provider's login page.
        3. Otherwise, attempt to authenticate with the backend using the ticket.
        4. If the backend is able to validate the ticket, then the user is logged in and redirected to *CAS_NEXT_DEFAULT*.
        5. Otherwise, the process fails and displays an error message.

    """
    ticket = request.GET.get(settings.CAS_TICKET_LABEL, None)
    redirect_to = request.REQUEST.get(redirect_field_name,
                                      request.session.pop('login_redirect_to', ''))
    
    if ticket is None:
        # Need to obtain a service validation ticket from the CAS provider.
        request.session['login_redirect_to'] = redirect_to
        params = settings.CAS_EXTRA_LOGIN_PARAMS
        params.update({settings.CAS_SERVICE_LABEL: service})
        url = cas_login + '?'
        raw_params = ['%s=%s' % (key, value) for key, value in params.items()]
        url += '&'.join(raw_params)
        return HttpResponseRedirect(url)

    user = authenticate(service=service, ticket=ticket)
    if user is not None:
        netloc = urlparse.urlparse(redirect_to)[1]

        # Use default setting if redirect_to is empty
        if not redirect_to:
            redirect_to = settings.LOGIN_REDIRECT_URL

        # Heavier security check -- don't allow redirection to a different
        # host.
        elif netloc and netloc != request.get_host():
            redirect_to = settings.LOGIN_REDIRECT_URL
        
        # Okay, security checks complete. Log the user in.
        auth_login(request, user)
        name = user.first_name or user.username
        if messages is not None:
            messages.success(request, "Login succeeded. Welcome, %s." % name)
        return HttpResponseRedirect(redirect_to)
    else:
        return HttpResponseForbidden("Error authenticating with CAS")


def logout(request, next_page=cas_redirect_on_logout):
    """ Logs the current user out. If *CAS_COMPLETELY_LOGOUT* is true, redirect to the provider's logout page,
        which will redirect to ``next_page``.

    """
    auth_logout(request)
    if settings.CAS_COMPLETELY_LOGOUT:
        return HttpResponseRedirect('%s?url=%s' % (cas_logout, next_page))
    return HttpResponseRedirect(cas_redirect_on_logout)
