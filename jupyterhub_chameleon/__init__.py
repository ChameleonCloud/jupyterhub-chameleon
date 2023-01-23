import os
import sys

from .handler import AccessTokenHandler
from .handler import UserRedirectExperimentHandler
from .handler import TroviMetricHandler

origin = "*"
# Terminate servers after 3 days of idleness
server_idle_timeout = 60 * 60 * 24 * 3
# Terminate kernels after 1 day of idleness
kernel_idle_timeout = 60 * 60 * 24
debug = os.getenv("DEBUG", "").strip().lower() in ["1", "true", "yes"]


def install_extension(config):
    c = config

    # Set log levels
    log_level = "DEBUG" if debug else "INFO"
    c.Application.log_level = c.JupyterHub.log_level = log_level

    # The experiment import functionality requires named servers
    c.JupyterHub.allow_named_servers = True
    # c.JupyterHub.default_server_name = 'workbench'
    # Enable restarting of Hub without affecting singleuser servers
    c.JupyterHub.cleanup_servers = False
    c.JupyterHub.cleanup_proxy = False
    # Keycloak SSO sessions only last 30 days; the Jupyter session length needs
    # to match to avoid allowing to be logged in tof roo long.
    c.JupyterHub.cookie_max_age_days = 30

    c.JupyterHub.extra_handlers = [
        (r"/import", UserRedirectExperimentHandler),
        (r"/api/tokens", AccessTokenHandler),
        (r"/api/trovi_metrics", TroviMetricHandler),
    ]

    c.JupyterHub.template_paths = [
        os.path.join(_data_files_path(), "templates"),
    ]

    _configure_authenticator(c)
    _configure_services(c)
    _configure_spawner(c)


def _configure_authenticator(c):
    c.JupyterHub.authenticator_class = "openstack_oauth"


def _configure_services(c):
    c.JupyterHub.services = [
        {
            "name": "cull-idle",
            "admin": True,
            "command": [
                sys.executable,
                "-m",
                "jupyterhub_chameleon.service.cull_idle_servers",
                "--timeout={}".format(server_idle_timeout),
                "--cull_every={}".format(60 * 15),
            ],
        },
    ]


def _configure_spawner(c):
    c.JupyterHub.spawner_class = "chameleon"
    c.ChameleonSpawner.debug = debug
    c.ChameleonSpawner.mem_limit = "2G"
    c.ChameleonSpawner.http_timeout = 600
    # This directory will be symlinked to the `ChameleonSpawner.work_dir`
    c.ChameleonSpawner.notebook_dir = "~/work"
    c.ChameleonSpawner.args.extend(
        [
            f"--ServerApp.allow_origin={origin}",
            f"--ServerApp.shutdown_no_activity_timeout={server_idle_timeout}",
            f"--MappingKernelManager.cull_idle_timeout={kernel_idle_timeout}",
            f"--MappingKernelManager.cull_interval={kernel_idle_timeout}",
        ]
    )
    if debug:
        c.ChameleonSpawner.remove = False


def _data_files_path():
    path = os.path.abspath(os.path.dirname(__file__))
    while path != "/":
        data_files_path = os.path.join(path, "share", "jupyterhub_chameleon")
        if os.path.exists(data_files_path):
            return data_files_path
        path, _ = os.path.split(path)


__all__ = ["install_extension"]
