import hashlib
import os
import re
import string
import subprocess

import escapism
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

    def pre_spawn_hook(self, spawner):
        # NOTE self and spawner are the same object due to how the parent class
        # calls this, so you could define this in another module.

        # The length of some kubernetes objects is limited to 63 chars
        KUBERNETES_LENGTH_LIMIT = 63
        PREFIX_NAME_LENGTH = 10 # Buffer for other prefixes (e.g. "volume-")
        SERVER_NAME_LENGTH = 6 # How long named trovi servers are
        HASH_LENGTH = 12

        short_username_length = KUBERNETES_LENGTH_LIMIT - \
                PREFIX_NAME_LENGTH - SERVER_NAME_LENGTH - HASH_LENGTH

        # the username the spawner will use. This comes from the kubespawner
        # code, but it isn't exposed as a function there, so we copy it.
        safe_chars = set(string.ascii_lowercase + string.digits)
        safe_username = escapism.escape(
            self.user.name, safe=safe_chars, escape_char='-'
        ).lower()
        short_username = safe_username[:short_username_length] + \
            hashlib.sha1(
                safe_username.encode("utf-8")).hexdigest()[:HASH_LENGTH]

        def check_template(template):
            if len(template.format(
                    username=safe_username, servername=self.name)
               ) > KUBERNETES_LENGTH_LIMIT:
                # Let kubespawner format servername later, with short username
                return template.format(
                    username=short_username, servername='{servername}')
            # Let kubespawner format the template later
            return template

        # Reformat the pod_name and volume templates using username
        # as these are subject to the short name limit
        self.pod_name = check_template(self.pod_name)
        for v in self.volumes:
            if '{username}' in v.get("name"):
                v["name"] = check_template(v.get("name"))
        for v in self.volume_mounts:
            if '{username}' in v.get("name"):
                v["name"] = check_template(v.get("name"))
