import argparse
import hashlib
import hmac
import os
import requests
from time import time
from urllib.parse import parse_qsl

from keystoneauth1 import loading
from keystoneauth1.session import Session


class Artifact:
    """A shared experiment/research artifact that can be spawned in JupyterHub.

    Attrs:
        deposition_repo (str): the name of the deposition repository (e.g.,
            "zenodo" or "chameleon")
        deposition_id (str): the ID of the deposition within the repository.
        id (str): the external Trovi ID of the artifact linked to this
            deposition. Default = None.
        ownership (str): the requesting user's ownership status of this
            artifact. Default = "fork".
        ephemeral (bool): whether the artifact's working environment should
            be considered temporary. This can indicate that, e.g., nothing
            from the working directory should be saved when the spawned
            environment is torn down. Default = False.
    """
    def __init__(self, deposition_repo=None, deposition_id=None, id=None,
                 ownership='fork', ephemeral=None):
        self.id = id
        self.deposition_repo = deposition_repo
        self.deposition_id = deposition_id
        self.ownership = ownership
        self.ephemeral = ephemeral in [True, 'True', 'true', 'yes', '1']

        # Only the deposition information is required. Theoretically this can
        # allow importing arbitrary Zenodo DOIs or from other sources that are
        # not yet existing on Trovi.
        if not (deposition_repo and deposition_id):
            raise ValueError('Missing deposition information')

    def deposition_url(self):
        url_factory = getattr(self.__class__, f'{self.deposition_repo}_url_factory', None)
        if not url_factory:
            return None
        return url_factory(self.deposition_id)

    @classmethod
    def from_query(cls, query):
        if isinstance(query, str):
            query = dict(parse_qsl(query))

        try:
            return cls(**query)
        except Exception:
            return None

    @staticmethod
    def chameleon_url_factory(deposition_id: str) -> str:
        origin, path = _swift_url_parts(deposition_id)
        key = os.environ['ARTIFACT_SHARING_SWIFT_TEMP_URL_KEY']
        duration_in_seconds = 60
        expires = int(time() + duration_in_seconds)
        hmac_body = f'GET\n{expires}\n{path}'
        sig = hmac.new(
            key.encode('utf-8'), hmac_body.encode('utf-8'),
            hashlib.sha1
        ).hexdigest()

        return f'{origin}{path}?temp_url_sig={sig}&temp_url_expires={expires}'

    @staticmethod
    def http_url_factory(deposition_id: str) -> str:
        return deposition_id

    @staticmethod
    def zenodo_url_factory(deposition_id: str) -> str:
        # TODO: make this configurable
        zenodo_base = 'https://zenodo.org'
        record_id = deposition_id.split('.')[-1]
        res = requests.get(f'{zenodo_base}/api/records/{record_id}')
        res.raise_for_status()
        file_links = [
            f.get('links', {}).get('self')
            for f in res.json().get('files', [])
        ]
        file_links = [l for l in file_links if l is not None]
        if not file_links:
            raise ValueError('Found no file URLs on Zenodo deposition')
        return file_links[0]


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
        if key not in ['OS_IDENTITY_API_VERSION']
    ]
    parser = argparse.ArgumentParser()
    loading.cli.register_argparse_arguments(
        parser, fake_argv, default='token')
    loading.session.register_argparse_arguments(parser)
    loading.adapter.register_argparse_arguments(parser)
    args = parser.parse_args(fake_argv)
    auth = loading.cli.load_from_argparse_arguments(args)
    return Session(auth=auth)


def artifact_sharing_keystone_session():
    artifact_sharing_overrides = {
        key.replace('ARTIFACT_SHARING_', ''): value
        for key, value in os.environ.items()
        if key.startswith('ARTIFACT_SHARING_OS_')
    }
    return keystone_session(env_overrides=artifact_sharing_overrides)


def _swift_url_parts(deposition_id: str) -> 'tuple[str,str]':
    session = artifact_sharing_keystone_session()
    project_id = os.environ.get(
        'ARTIFACT_SHARING_SWIFT_ACCOUNT', session.get_project_id())
    endpoint = session.get_endpoint(
        service_type='object-store',
        interface=os.environ.get('ARTIFACT_SHARING_OS_INTERFACE',
            os.environ.get('OS_INTERFACE', 'public')),
        region_name=os.environ.get('ARTIFACT_SHARING_OS_REGION_NAME',
            os.environ.get('OS_REGION_NAME')))

    if not endpoint:
        raise ValueError('Could not discover object-store endpoint')

    origin = endpoint[:endpoint.index('/v1/')]
    container = os.environ.get('ARTIFACT_SHARING_SWIFT_CONTAINER', 'trovi')
    return origin, f'/v1/AUTH_{project_id}/{container}/{deposition_id}'


def upload_url(deposition_id: str) -> str:
    origin, path = _swift_url_parts(deposition_id)
    return f'{origin}{path}'
