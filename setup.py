from glob import glob
from setuptools import find_packages, setup

setup(
    name='jupyterhub-chameleon',
    version='1.7.0',
    description='Chameleon extensions for JupyterHub',
    url='https://github.com/chameleoncloud/jupyterhub-chameleon',
    author='Jason Anderson',
    author_email='jasonanderson@uchicago.edu',
    license='MIT',
    packages=find_packages(),
    install_requires=[
        'dockerspawner',
        'jupyterhub',
        'jupyterhub-keystoneauthenticator',
        'keystoneauth1',
        'oauthenticator',
        'python-keystoneclient',
        'tornado',
        'traitlets',
    ],
    entry_points={
        'jupyterhub.authenticators': [
            'chameleon = jupyterhub_chameleon.authenticator.keycloak:ChameleonKeycloakAuthenticator',
        ],
        'jupyterhub.spawners': [
            'chameleon = jupyterhub_chameleon.spawner:ChameleonSpawner',
        ],
    },
    data_files=[
        ('etc/jupyterhub/templates', glob('templates/*.html')),
    ],
)
