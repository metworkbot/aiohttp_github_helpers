from setuptools import setup
from setuptools import find_packages

with open('requirements.txt') as reqs:
    install_requires = [
        line for line in reqs.read().split('\n')
        if (line and not line.startswith('--')) and (";" not in line)]

DESCRIPTION = "some github api helpers for use with aiohttp"

setup(
    name='aiohttp_github_helpers',
    packages=find_packages(),
    license='BSD',
    version='0.0.1',
    description=DESCRIPTION,
    install_requires=install_requires
)
