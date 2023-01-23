import os
import re
import subprocess

from kubespawner import KubeSpawner
from traitlets import default, Bool, Dict, Unicode

from .utils import Artifact


class ChameleonSpawner(KubeSpawner):
    _default_name_template = "jupyter-{username}"
    _named_name_template = "jupyter-{username}-exp-{servername}"

    @default("pod_name_template")
    def _pod_name_template(self):
        if self.name:
            return self._named_name_template
        else:
            return self._default_name_template

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
        if self.name:
            # Experiment (named) servers will need new keypairs generated;
            # name them after the artifact hash.
            extra_env["OS_KEYPAIR_NAME"] = f"trovi-{self.name}"

        # Add parameters for experiment import
        artifact = self.get_artifact()
        if artifact:
            extra_env["ARTIFACT_UUID"] = artifact.uuid
            extra_env["ARTIFACT_VERSION_SLUG"] = artifact.version_slug
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
