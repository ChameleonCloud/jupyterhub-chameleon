import argparse
import os
from urllib.parse import parse_qsl

from keystoneauth1 import loading
from keystoneauth1.session import Session

TROVI_URN_PREFIX = "urn:trovi:"


def parse_trovi_contents_urn(urn: str):
    backend, id = urn.replace(f"{TROVI_URN_PREFIX}contents:", "").split(":", 1)
    return backend, id


class Artifact:
    """A shared experiment/research artifact that can be spawned in JupyterHub.

    Attrs:
        uuid (str): the UUID of the artifact.
        version_slug (str): the version slug of the artifact.
        contents_urn (str): the URN of the artifact's Trovi contents.
        contents_id (str): DEPRECATED: the ID of the artifact's Trovi contents.
            This is derived from the URN.
        contents_backend (str): DEPRECATED: the name of the artifact's Trovi contents
            backend. This is derived from the URN.
        contents_url (str): the access URL for the artifact's Trovi contents.
        contents_proto (str): the protocol for accessing the artifact's Trovi contents.
        ownership (str): the requesting user's ownership status of this
            artifact. Default = "fork".
        ephemeral (bool): whether the artifact's working environment should
            be considered temporary. This can indicate that, e.g., nothing
            from the working directory should be saved when the spawned
            environment is torn down. Default = False.
    """

    def __init__(
        self,
        uuid=None,
        version_slug=None,
        contents_urn=None,
        contents_id=None,
        contents_backend=None,
        contents_url=None,
        contents_proto=None,
        ownership="fork",
        ephemeral=None,
    ):
        self.uuid = uuid
        self.version_slug = version_slug
        self.contents_urn = contents_urn
        id_from_urn, backend_from_urn = parse_trovi_contents_urn(contents_urn)
        self.contents_id = contents_id if contents_id else id_from_urn
        self.contents_backend = (
            contents_backend if contents_backend else backend_from_urn
        )
        self.contents_url = contents_url
        self.contents_proto = contents_proto
        self.ownership = ownership
        self.ephemeral = ephemeral in [True, "True", "true", "yes", "1"]

        # Only the contents information is required. Theoretically this can
        # allow importing from other sources that are not yet existing on Trovi.
        if not (contents_url and contents_proto):
            raise ValueError("Missing contents information")

    @classmethod
    def from_query(cls, query):
        if isinstance(query, str):
            query = dict(parse_qsl(query))

        try:
            return cls(**query)
        except Exception:
            return None


def keystone_session(env_overrides: dict = {}) -> Session:
    """Obtain Keystone authentication credentials for given OpenStack RC params.

    Args:
        env_overrides (dict): a dictionary of OpenStack RC parameters. These
            parameters are assumed to be as if they were pulled off of the
            environment, e.g. are like {'OS_USERNAME': '', 'OS_PASSWORD: ''}
            with uppercase and underscores.

    Returns:
        keystoneauth1.session.Session: a KSA session object, which can be used
            to authenticate any OpenStack client.
    """
    # We are abusing the KSA loading mechanism here. The arg parser will default
    # the various OpenStack auth params from the environment, which is what
    # we're after.
    fake_argv = [
        f'--{key.lower().replace("_", "-")}={value}'
        for key, value in env_overrides.items()
        # NOTE(jason): we ignore some environment variables, as they are not
        # supported as KSA command-line args.
        if key not in ["OS_IDENTITY_API_VERSION"]
    ]
    parser = argparse.ArgumentParser()
    loading.cli.register_argparse_arguments(parser, fake_argv, default="token")
    loading.session.register_argparse_arguments(parser)
    loading.adapter.register_argparse_arguments(parser)
    args = parser.parse_args(fake_argv)
    auth = loading.cli.load_from_argparse_arguments(args)
    return Session(auth=auth)


def artifact_sharing_keystone_session():
    artifact_sharing_overrides = {
        key.replace("ARTIFACT_SHARING_", ""): value
        for key, value in os.environ.items()
        if key.startswith("ARTIFACT_SHARING_OS_")
    }
    return keystone_session(env_overrides=artifact_sharing_overrides)
