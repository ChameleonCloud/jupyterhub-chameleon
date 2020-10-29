import os
import sys

from .handler import AccessTokenHandler
from .handler import ArtifactPublishPrepareUploadHandler
from .handler import ForcePasswordLoginHandler
from .handler import UserRedirectExperimentHandler

origin = '*'
# Terminate servers after 3 days of idleness
server_idle_timeout = 60 * 60 * 24 * 3
# Terminate kernells after 1 day of idleness
kernel_idle_timeout = 60 * 60 * 24
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
    # Keycloak SSO sessions only last 1 day; the Jupyter session length needs
    # to match to avoid ...
    c.JupyterHub.cookie_max_age_days = 1

    c.JupyterHub.extra_handlers = [
        (r'/import', UserRedirectExperimentHandler),
        (r'/api/tokens', AccessTokenHandler),
        (r'/api/share/prepare_upload', ArtifactPublishPrepareUploadHandler),
        (r'/auth/force-password-login', ForcePasswordLoginHandler),
    ]

    _configure_authenticator(c)
    _configure_services(c)
    _configure_spawner(c)


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
    if debug:
        c.ChameleonSpawner.remove = False


__all__ = ['install_extension']
