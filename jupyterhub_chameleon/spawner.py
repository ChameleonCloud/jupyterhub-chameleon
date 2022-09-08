import os
import re

from dockerspawner import DockerSpawner
from traitlets import default, Bool, Dict, Unicode

from .utils import Artifact


class ChameleonSpawner(DockerSpawner):
    work_dir = Unicode(
        "/work",
        config=True,
        help="""Working directory
        This directory will be mounted at ~/work inside the user's container
        and is intended to be a "long term" scratch directory unique to the
        user.
        """,
    )

    share_dir = Unicode(
        "/share",
        config=True,
        help="""Shared directory
        This directory will contain the user's shared files across all of their
        Jupyter servers.
        """,
    )

    trovi_url = Unicode(
        os.getenv("TROVI_URL", "https://trovi.chameleoncloud.org"),
        config=True,
        help="""
        Base URL for Trovi experiment storage/sharing API.
        """,
    )

    # Always remove stopped containers
    remove = Bool(True, config=True)

    # Default to JupyterLab
    default_url = Unicode("/lab")

    # TODO: can enable picking different images here.
    #
    # @default('options_form')
    # def _options_form(self):
    #     default_env = "YOURNAME=%s\n" % self.user.name
    #     return """
    #     <label for="args">Extra notebook CLI arguments</label>
    #     <input name="args" placeholder="e.g. --debug"></input>
    #     """.format(env=default_env)

    # @default('options_from_form')
    # def _options_from_form(self, formdata):
    #     """Turn html formdata (always lists of strings) into the dict we want."""
    #     options = {}
    #     arg_s = formdata.get('args', [''])[0].strip()
    #     if arg_s:
    #         options['argv'] = shlex.split(arg_s)
    #     return options

    _default_name_template = "{prefix}-{username}"
    _named_name_template = "{prefix}-{username}-exp-{servername}"

    @default("name_template")
    def _name_template(self):
        if self.name:
            return self._named_name_template
        else:
            return self._default_name_template

    extra_volumes = Dict(config=True, default_value={})

    @property
    def volumes(self):
        vols = {}
        artifact = self.get_artifact()
        if not (artifact and artifact.ephemeral):
            if self.name:
                vols[self._named_name_template] = self._gen_volume_config(self.work_dir)
                # Also mount the default directory as shared dir
                # vols[self._default_name_template] = self._gen_volume_config(
                #    self.share_dir
                # )
            else:
                vols[self._default_name_template] = self._gen_volume_config(
                    self.work_dir
                )
        vols.update(self.extra_volumes)
        return vols

    @default("environment")
    def _environment(self):
        chown_extra = [self.work_dir]
        # if self.name:
        #    chown_extra.append(self.share_dir)
        return {
            "CHOWN_EXTRA": ",".join(chown_extra),
            "CHOWN_EXTRA_OPTS": "-R",
            # Allow users to have sudo access within their container
            "GRANT_SUDO": "yes",
            # Enable JupyterLab application
            "JUPYTER_ENABLE_LAB": "yes",
        }

    resource_limits = Bool(
        config=True,
        default_value=True,
        help="Whether to set default resource limits on the spawned servers.",
    )

    @default("extra_host_config")
    def _extra_host_config(self):
        """Configure docker host vars.

        This is where container resource limits are set. Note the cpu_period and
        cpu_quota settings: the quota divided by the period is effectively how
        many cores a container will be allowed to have in a CPU-bound scheduling
        situation, e.g. 100/100 = 1 core.
        """
        host_config = {"network_mode": self.network_name}

        if self.resource_limits:
            host_config.update(
                {
                    "mem_limit": "1G",
                    "cpu_period": 100000,  # nanosecs
                    "cpu_quota": 100000,  # nanosecs
                }
            )

        return host_config

    @default("extra_create_kwargs")
    def _extra_create_kwargs(self):
        return {
            # Need to launch the container as root in order to grant sudo access
            "user": "root"
        }

    @default("image")
    def _image(self):
        return os.environ["DOCKER_NOTEBOOK_IMAGE"]

    @default("network_name")
    def _network_name(self):
        return os.environ["DOCKER_NETWORK_NAME"]

    def _get_unix_user(self):
        name = self.user.name.lower()
        # Escape bad characters (just make them unix_safe)
        name = re.sub(r"[^a-z0-9_-]", "_", name)
        # Ensure we start with an proper character
        if not re.search(r"^[a-z_]", name):
            name = "_" + name
        # Usernames may only be 32 characters
        return name[:32]

    def get_env(self):
        env = super().get_env()

        extra_env = {}
        # Rename notebook user (jovyan) to Chameleon username
        extra_env["NB_USER"] = self._get_unix_user()
        # ssh_dir = self.share_dir if self.name else self.work_dir
        ssh_dir = self.work_dir
        extra_env["OS_KEYPAIR_PRIVATE_KEY"] = f"{ssh_dir}/.ssh/id_rsa"
        extra_env["OS_KEYPAIR_PUBLIC_KEY"] = f"{ssh_dir}/.ssh/id_rsa.pub"
        if self.name:
            # Experiment (named) servers will need new keypairs generated;
            # name them after the artifact hash.
            extra_env["OS_KEYPAIR_NAME"] = f"trovi-{self.name}"

        # TODO(adam): We override this manually, because we could not figure out why
        #             traitlets was not resolving this URL properly
        extra_env["TROVI_URL"] = os.getenv(
            "TROVI_URL", "https://trovi.chameleoncloud.org"
        )

        # Add parameters for experiment import
        artifact = self.get_artifact()
        if artifact:
            extra_env["ARTIFACT_CONTENTS_URL"] = artifact.contents_url
            extra_env["ARTIFACT_CONTENTS_PROTO"] = artifact.contents_proto
            extra_env["ARTIFACT_CONTENTS_URN"] = artifact.contents_urn
            extra_env["ARTIFACT_CONTENTS_ID"] = artifact.contents_id
            extra_env["ARTIFACT_CONTENTS_BACKEND"] = artifact.contents_backend
            extra_env["ARTIFACT_OWNERSHIP"] = artifact.ownership
            extra_env["ARTIFACT_DIR_NAME_FILE"] = "/tmp/experiment_dir"
            self.log.info(
                f"User {self.user.name} importing from "
                f"{artifact.contents_backend}: {artifact.contents_url}"
            )

        env.update(extra_env)

        return env

    def get_artifact(self) -> Artifact:
        if self.handler:
            return Artifact.from_query(self.handler.request.query)
        else:
            return None

    def _gen_volume_config(self, target):
        return dict(
            target=target,
            driver=os.getenv("DOCKER_VOLUME_DRIVER", "local"),
            driver_opts=self._docker_volume_opts(),
        )

    def _docker_volume_opts(self):
        opt_str = os.getenv("DOCKER_VOLUME_DRIVER_OPTS", "")
        tuples = [s.split("=") for s in opt_str.split(",") if s]
        return {t[0]: t[1] for t in tuples if len(t) == 2}
