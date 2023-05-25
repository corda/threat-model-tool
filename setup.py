# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='r3threatmodeling',
    version='0.1.0',
    description='r3threatmodeling tool for structuring and reporting',
    long_description=readme,
    author='David Cervigni, James Brown ',
    author_email='david.cervigni@r3.com',
    url='https://github.com/corda/threat-model-tool',
    license=license,
    # package_data={'': ['*.mako']},
    include_package_data=True,
    package_dir = {"": "src"},
    packages=['r3threatmodeling', 'r3threatmodeling.template'] #find_packages(include=['*'], exclude=('tests', 'docs'))##f
)

