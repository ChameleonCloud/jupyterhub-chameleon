import os
import sys

from .handler import AccessTokenHandler, UserRedirectExperimentHandler

origin = '*'
server_idle_timeout = 60 * 60 * 24
server_max_age = 60 * 60 * 24 * 7
kernel_idle_timeout = 60 * 60 * 2
debug = os.getenv('DEBUG', '').strip().lower() in ['1', 'true', 'yes']


def install_extension(config):
    c = config

    # Set log levels
    log_level = 'DEBUG' if debug else 'INFO'
    c.Application.log_level = c.JupyterHub.log_level = log_level

    # The experiment import functionality requires named servers
    c.JupyterHub.allow_named_servers = True
    # c.JupyterHub.default_server_name = 'workbench'
    # Enable restarting of Hub without affecting singleuser servers
    c.JupyterHub.cleanup_servers = False
    c.JupyterHub.cleanup_proxy = False
    # Keystone tokens only last 7 days; limit sessions to this amount of time too.
    c.JupyterHub.cookie_max_age_days = 7

    c.JupyterHub.extra_handlers = [
        (r'/import', UserRedirectExperimentHandler),
        (r'/api/tokens', AccessTokenHandler),
    ]

    _configure_authenticator(c)
    _configure_services(c)
    _configure_spawner(c)
    _configure_zenodo(c)


def _configure_authenticator(c):
    c.JupyterHub.authenticator_class = 'chameleon'


def _configure_services(c):
    c.JupyterHub.services = [
        {
            'name': 'cull-idle',
            'admin': True,
            'command': [
                sys.executable,
                '-m', 'jupyterhub_chameleon.service.cull_idle_servers',
                '--timeout={}'.format(server_idle_timeout),
                '--max_age={}'.format(server_max_age),
                '--cull_every={}'.format(60 * 15),
            ],
        },
    ]


def _configure_spawner(c):
    c.JupyterHub.spawner_class = 'chameleon'
    c.ChameleonSpawner.debug = debug
    c.ChameleonSpawner.mem_limit = '2G'
    c.ChameleonSpawner.http_timeout = 600
    # This directory will be symlinked to the `ChameleonSpawner.work_dir`
    c.ChameleonSpawner.notebook_dir = '~/work'
    c.ChameleonSpawner.args.extend([
        f'--NotebookApp.allow_origin={origin}',
        f'--NotebookApp.shutdown_no_activity_timeout={server_idle_timeout}',
        f'--MappingKernelManager.cull_idle_timeout={kernel_idle_timeout}',
        f'--MappingKernelManager.cull_interval={kernel_idle_timeout}',
    ])


def _configure_zenodo(c):
    access_token = os.getenv('ZENODO_DEFAULT_ACCESS_TOKEN')
    upload_url = os.getenv('CHAMELEON_SHARING_PORTAL_UPLOAD_URL', '')
    update_url = os.getenv('CHAMELEON_SHARING_PORTAL_UPDATE_URL', '')

    # Pass extra configuration for Zenodo extension
    c.ChameleonSpawner.args.extend([
        f'--ZenodoConfig.access_token={access_token}',
        f'--ZenodoConfig.upload_redirect_url={upload_url}',
        f'--ZenodoConfig.update_redirect_url={update_url}',
        f'--ZenodoConfig.dev={debug}',
        '--ZenodoConfig.community=chameleon',
        '--ZenodoConfig.database_location=~/work/.zenodo',
    ])


__all__ = ['install_extension']
