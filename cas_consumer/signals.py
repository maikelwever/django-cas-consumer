# -*- coding: utf-8 -*-
"""cas_consumer.signals -- signal definitions for the CAS client.
"""
import django.dispatch


# Sent when multiple users match the CAS verification response. The
# primary user will be used for authentication. The others may be
# merged into the primary as appropriate for the application.
on_cas_merge_users = django.dispatch.Signal(providing_args=["primary", "others"])


# Sent when a user has been successfully authenticated by CAS.
on_cas_authentication = django.dispatch.Signal(providing_args=['user'])
