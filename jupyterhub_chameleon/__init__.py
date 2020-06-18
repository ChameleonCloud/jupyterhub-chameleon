import sys

from .handler import UserRedirectExperimentHandler

origin = '*'
server_idle_timeout = 60 * 60 * 24
server_max_age = 60 * 60 * 24 * 7
kernel_idle_timeout = 60 * 60 * 2


def install_extension(config):
    c = config
    # The experiment import functionality requires named servers
    c.JupyterHub.allow_named_servers = True
    # c.JupyterHub.default_server_name = 'workbench'
    c.JupyterHub.authenticator_class = 'chameleon'
    c.JupyterHub.spawner_class = 'chameleon'
    c.JupyterHub.extra_handlers = [
        (r'/import', UserRedirectExperimentHandler),
    ]
    # Keystone tokens only last 7 days; limit sessions to this amount of time too.
    c.JupyterHub.cookie_max_age_days = 7
    # Enable restarting of Hub without affecting singleuser servers
    c.JupyterHub.cleanup_servers = False
    c.JupyterHub.cleanup_proxy = False
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
        {
            'name': 'oauth-refresh',
            'url': 'http://127.0.0.1:8880',
            'command': [
                sys.executable,
                '-m', 'jupyterhub_chameleon.service.oauth_refresh',
            ]
        }
    ]
    # Spawner-specific overrides
    c.ChameleonSpawner.mem_limit = '2G'
    c.ChameleonSpawner.http_timeout = 600
    # This directory will be symlinked to the `ChameleonSpawner.work_dir`
    c.ChameleonSpawner.notebook_dir = '~/work'
    c.ChameleonSpawner.args = [
        f'--NotebookApp.allow_origin={origin}',
        f'--NotebookApp.shutdown_no_activity_timeout={server_idle_timeout}',
        f'--MappingKernelManager.cull_idle_timeout={kernel_idle_timeout}',
        f'--MappingKernelManager.cull_interval={kernel_idle_timeout}',
    ]


__all__ = ['install_extension']
