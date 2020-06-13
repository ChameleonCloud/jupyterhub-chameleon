from .handler import UserRedirectExperimentHandler


def install_extension(config):
    # The experiment import functionality requires named servers
    config.JupyterHub.allow_named_servers = True
    config.JupyterHub.default_server_name = 'workbench'
    config.JupyterHub.authenticator_class = 'chameleon'
    config.JupyterHub.spawner_class = 'chameleon'
    config.JupyterHub.extra_handlers = [
        (r'/import', UserRedirectExperimentHandler),
    ]


__all__ = ['install_extension']
