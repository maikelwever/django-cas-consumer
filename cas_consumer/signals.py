# -*- coding: utf-8 -*-
"""cas_consumer.signals -- signal definitions for the CAS client.
"""
from django import dispatch


# Sent when multiple users match the CAS verification response. The
# primary user will be used for authentication. The others may be
# merged into the primary as appropriate for the application.
on_cas_merge_users = dispatch.Signal(providing_args=["primary", "others"])


# Sent when a user has been successfully authenticated by CAS.
on_cas_authentication = dispatch.Signal(providing_args=['user'])
