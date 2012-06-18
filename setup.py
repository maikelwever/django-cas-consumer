
from setuptools import setup, find_packages
 
setup(
    name='django-cas-consumer',
    version='0.3.3',
    description='A "consumer" for a modified version of the the Central Authentication Service protocol (http://jasig.org/cas)',
    author='David Eyk & Derek Wickwire (original by Chris Williams)',
    author_email='deyk@crossway.org',
    packages=find_packages(),
    zip_safe=False,
    install_requires=['setuptools'],
)
