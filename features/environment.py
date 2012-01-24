# -*- coding: utf-8 -*-
"""features/environment.py -- environment settings for behavior testing the CAS client.
"""
import tempfile


def before_all(context):
    from django.conf import settings, global_settings
    settings.configure(
        DATABASES = {
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': ':memory:',
                }
            },
        INSTALLED_APPS = (
            'django.contrib.contenttypes',
            'django.contrib.auth',
            'django.contrib.sessions',
            'django.contrib.messages',
            'cas_provider',
            )
        )

    from django.core import management
    cmd = management.load_command_class('django.core', 'syncdb')
    cmd.handle_noargs(database='default', noinput=True, all=True, verbosity=1)

    from django.test.simple import DjangoTestSuiteRunner
    context.runner = DjangoTestSuiteRunner()


def before_scenario(context, scenario):
    # Set up the scenario test environment
    context.runner.setup_test_environment()
    context.old_db_config = context.runner.setup_databases()


def after_scenario(context, scenario):
    # Tear down the scenario test environment.
    context.runner.teardown_databases(context.old_db_config)
    context.runner.teardown_test_environment()
