import os
from urllib.parse import parse_qsl

from dockerspawner import DockerSpawner
from traitlets import default, Unicode
from .utils import get_import_params

class ChameleonSpawner(DockerSpawner):
    work_dir = Unicode(
        "/work",
        config=True,
        help="""Working directory
        This directory will be mounted at ~/work inside the user's container
        and is intended to be a "long term" scratch directory unique to the
        user.
        """
    )

    @default('options_form')
    def _options_form(self):
        default_env = "YOURNAME=%s\n" % self.user.name
        return """
        <label for="args">Extra notebook CLI arguments</label>
        <input name="args" placeholder="e.g. --debug"></input>
        """.format(env=default_env)

    @default('options_from_form')
    def _options_from_form(self, formdata):
        """Turn html formdata (always lists of strings) into the dict we want."""
        options = {}
        # arg_s = formdata.get('args', [''])[0].strip()
        # if arg_s:
        #     options['argv'] = shlex.split(arg_s)
        return options

    @default('name_template')
    def _name_template(self):
        if self._is_import_environment():
            return '{prefix}-{username}-exp-{servername}'
        else:
            return '{prefix}-{username}'

    @default('volumes')
    def _volumes(self):
        if self._is_import_environment():
            return {
                '{prefix}-{username}-exp-{servername}': (
                    self._gen_volume_config(self.work_dir)),
            }
        else:
            return {
                '{prefix}-{username}': self._gen_volume_config(self.work_dir),
            }

    @default('remove_containers')
    def _remove_containers(self):
        return True

    @default('environment')
    def _environment(self):
        return {
            'CHOWN_EXTRA': self.work_dir,
            'CHOWN_EXTRA_OPTS': '-R',
            # Allow users to have sudo access within their container
            'GRANT_SUDO': 'yes',
            # Enable JupyterLab application
            'JUPYTER_ENABLE_LAB': 'yes',
        }

    @default('extra_host_config')
    def _extra_host_config(self):
        """Configure docker host vars.

        This is where container resource limits are set. Note the cpu_period and
        cpu_quota settings: the quota divided by the period is effectively how
        many cores a container will be allowed to have in a CPU-bound scheduling
        situation, e.g. 100/100 = 1 core.
        """
        return {
            'network_mode': self.network_name,
            'mem_limit': '1G',
            'cpu_period': 100000, # nanosecs
            'cpu_quota': 100000, # nanosecs
        }

    @default('extra_create_kwargs')
    def _extra_create_kwargs(self):
        return {
            # Need to launch the container as root in order to grant sudo access
            'user': 'root'
        }

    @default('image')
    def _image(self):
        return os.environ['DOCKER_NOTEBOOK_IMAGE']

    @default('network_name')
    def _network_name(self):
        return os.environ['DOCKER_NETWORK_NAME']

    def get_env(self):
        env = super().get_env()
        extra_env = {}

        extra_env['NB_USER'] = self.user.name,
        extra_env['OS_INTERFACE'] = 'public'
        extra_env['OS_IDENTITY_API_VERSION'] = '3'
        extra_env['OS_KEYPAIR_PRIVATE_KEY'] = f'{self.work_dir}/.ssh/id_rsa'
        extra_env['OS_KEYPAIR_PUBLIC_KEY'] = f'{self.work_dir}/.ssh/id_rsa.pub'
        extra_env['OS_PROJECT_DOMAIN_NAME'] = 'default'
        # TODO(jason): when we move to federated keystone, there will only
        # be one region, and the site will be influenced entirely by auth_url
        extra_env['OS_REGION_NAME'] = 'CHI@UC'

        auth_state = yield self.user.get_auth_state()

        if auth_state:
            extra_env['OS_AUTH_URL'] = auth_state['auth_url']
            extra_env['OS_TOKEN'] = auth_state['os_token']
            extra_env['OS_AUTH_TYPE'] = 'token'
            project_name = auth_state.get('project_name')
            if project_name:
                extra_env['OS_PROJECT_NAME'] = project_name

        env.update(extra_env)
        return env

    def _is_import_environment(self):
        return self._get_import_info() is not None

    def _get_import_info(self):
        return get_import_params(self.handler.request.query)

    def _gen_volume_config(self, target):
        return dict(
            target=target,
            driver=os.getenv('DOCKER_VOLUME_DRIVER', 'local'),
            driver_opts=self._docker_volume_opts(),
        )

    def _docker_volume_opts(self):
        opt_str = os.getenv('DOCKER_VOLUME_DRIVER_OPTS', '')
        tuples = [s.split('=') for s in opt_str.split(',') if s]
        return {t[0]: t[1] for t in tuples if len(t) == 2}
