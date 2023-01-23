from glob import glob
from setuptools import find_packages, setup

setup(
    name="jupyterhub-chameleon",
    version="2.0.16",
    description="Chameleon extensions for JupyterHub",
    url="https://github.com/chameleoncloud/jupyterhub-chameleon",
    author="Jason Anderson",
    author_email="jasonanderson@uchicago.edu",
    license="MIT",
    packages=find_packages(),
    install_requires=[
        "dockerspawner",
        "jupyterhub",
        "keystoneauth1",
        "oauthenticator",
        "python-keystoneclient",
        "tornado",
        "traitlets",
    ],
    entry_points={
        "jupyterhub.authenticators": [
            "chameleon = jupyterhub_chameleon.authenticator.keycloak:ChameleonKeycloakAuthenticator",
            "openstack_oauth = jupyterhub_chameleon.authenticator.openstack_oauth:OpenstackOAuthenticator",
        ],
        "jupyterhub.spawners": [
            "chameleon = jupyterhub_chameleon.spawner:ChameleonSpawner",
        ],
    },
    data_files=[
        (
            "share/jupyterhub_chameleon/templates",
            glob("share/jupyterhub_chameleon/templates/*.html"),
        ),
    ],
)
