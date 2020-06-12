from setuptools import setup

setup(
    name='jupyterhub-chameleon',
    version='0.0.1',
    description='Chameleon extensions for JupyterHub',
    url='https://github.com/chameleoncloud/jupyterhub-chameleon',
    author='Jason Anderson',
    author_email='jasonanderson@uchicago.edu',
    license='MIT',
    packages=['jupyterhub_chameleon'],
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
            'chameleon = jupyterhub_chameleon:ChameleonAuthenticator',
        ],
        'jupyterhub.spawners': [
            'chameleon = jupyterhub_chameleon:ChameleonSpawner',
        ],
    },
)
