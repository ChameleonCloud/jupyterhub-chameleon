from .handler import UserRedirectExperimentHandler


def install_extension(config):
    # The experiment import functionality requires named servers
    config.JupyterHub.allow_named_servers = True
    config.JupyterHub.extra_handlers = [
        (r'/import', UserRedirectExperimentHandler),
    ]
    config.JupyterHub.authenticator_class = 'chameleon'
    config.JupyterHub.spawner_class = 'chameleon'


__all__ = ['install_extension']
