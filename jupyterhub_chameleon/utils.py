import argparse
import hashlib
import hmac
import os
from time import time
from urllib.parse import parse_qsl

from keystoneauth1 import loading
from keystoneauth1.session import Session
from keystoneclient.v3 import client


def get_import_params(query):
    """Given an HTML query string, find the parameters relevant for import.

    :type query: Union[dict,str]
    :param query: the request query parameters (as a query string, or as a
                  parsed dictionary)
    :returns: a tuple of the import source and ID, if both were on the
              querystring, None otherwise
    """
    if isinstance(query, str):
        query = dict(parse_qsl(query))

    # NOTE(jason): fallback to legacy query keys. This can be removed when
    # Portal has been updated to have new import links like ?source,id
    repo = query.get('repo', query.get('source'))
    id = query.get('id', query.get('src_path'))

    if repo is not None and id is not None:
        return (repo, id)
    else:
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


def download_url(artifact_id: str) -> str:
    endpoint = os.environ['ARTIFACT_SHARING_SWIFT_ENDPOINT']
    container = os.environ.get('ARTIFACT_SHARING_SWIFT_CONTAINER', 'trovi')
    container_key = os.environ['ARTIFACT_SHARING_SWIFT_CONTAINER_TEMP_URL_KEY']
    duration_in_seconds = 60
    expires = int(time() + duration_in_seconds)

    path = f'{container}/{artifact_id}'
    hmac_body = f'GET\n{expires}\n{path}'
    sig = hmac.new(
        container_key.encode('utf-8'), hmac_body.encode('utf-8'),
        hashlib.sha1
    ).hexdigest()

    return f'{endpoint}/{path}?temp_url_sig={sig}&temp_url_expires={expires}'
