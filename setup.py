from setuptools import find_packages, setup

setup(
    name='jupyterhub-chameleon',
    version='0.2.0',
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
        'oauthenticator',
        'tornado',
        'traitlets',
    ],
    entry_points={
        'jupyterhub.authenticators': [
            'chameleon = jupyterhub_chameleon.authenticator.branching:ChameleonAuthenticator',
        ],
        'jupyterhub.spawners': [
            'chameleon = jupyterhub_chameleon.spawner:ChameleonSpawner',
        ],
    },
)
