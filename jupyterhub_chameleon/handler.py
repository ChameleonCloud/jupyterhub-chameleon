import hashlib
import json
import os
import time
from urllib.parse import parse_qsl, urlencode
import uuid

from jupyterhub.apihandlers import APIHandler
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join
from keystoneclient.v3.client import Client as KeystoneClient
from tornado.web import HTTPError, authenticated
from tornado.httpclient import AsyncHTTPClient, HTTPRequest, HTTPError as HTTPClientError
from tornado.curl_httpclient import CurlError

from .authenticator.config import OPENSTACK_RC_AUTH_STATE_KEY
from .utils import Artifact, keystone_session, upload_url


class UserRedirectExperimentHandler(BaseHandler):
    """Redirect spawn requests to user servers.

    /import?{query vars} will spawn a new experiment server
    Server will be initialized with a given artifact/repository.
    """
    @authenticated
    def get(self):
        base_spawn_url = url_path_join(
            self.hub.base_url, 'spawn', self.current_user.name)

        if self.request.query:
            query = dict(parse_qsl(self.request.query))
            artifact = Artifact.from_query(query)

            if not artifact:
                raise HTTPError(400, (
                    'Could not understand import request'))

            sha = hashlib.sha256()
            sha.update(artifact.deposition_repo.encode('utf-8'))
            sha.update(artifact.deposition_id.encode('utf-8'))
            server_name = sha.hexdigest()[:7]

            # Auto-open file when we land in server
            if 'file_path' in query:
                file_path = query.pop('file_path')
                query['next'] = url_path_join(
                    self.hub.base_url,
                    'user', self.current_user.name, server_name,
                    'lab', 'tree', file_path)

            spawn_url = url_path_join(base_spawn_url, server_name)
            spawn_url += '?' + urlencode(query)
        else:
            spawn_url = base_spawn_url

        self.redirect(spawn_url)


class AccessTokenMixin:
    TOKEN_EXPIRY_REFRESH_THRESHOLD = 120  # seconds

    async def refresh_token(self):
        username = self.current_user.name

        auth_state = await self.current_user.get_auth_state()
        if not auth_state:
            self.log.warn((
                f'Cannot refresh token because no auth_state for {username} '
                'exists.'))
            return None, None

        refresh_token = auth_state.get('refresh_token')

        if refresh_token:
            now = time.time()

            expires_at = auth_state.get('expires_at')
            assert expires_at is not None

            if (expires_at - now) >= self.TOKEN_EXPIRY_REFRESH_THRESHOLD:
                return auth_state['access_token'], expires_at

            try:
                new_tokens = await self._fetch_new_token(refresh_token)
            # When using the curl_httpclient, CurlErrors are raised, which
            # don't have a meaningful ``code``, but does have a curl error
            # number, which can indidate what really went wrong.
            except CurlError as curl_err:
                self.log.error((
                    f'Error refreshing token for user {username}: '
                    f'curl error {curl_err.errno}: {curl_err.message}'))
                return None, None
            except HTTPClientError as http_err:
                self.log.error((
                    f'Error refreshing token for user {username}: '
                    f'HTTP error {http_err.code}: {http_err.message}'
                ))
                self.log.debug(
                    f'response={http_err.response.body.decode("utf-8")}')
                return None, None
            access_token = new_tokens.get('access_token')
            expires_at = now + int(new_tokens.get('expires_in', 0))
            if access_token:
                auth_state['access_token'] = access_token
                auth_state['refresh_token'] = new_tokens['refresh_token']
                auth_state['expires_at'] = expires_at
                auth_state[OPENSTACK_RC_AUTH_STATE_KEY].update({
                    'OS_ACCESS_TOKEN': access_token,
                })
                await self.current_user.save_auth_state(auth_state)
                self.log.info(
                    f'Refreshed access token for user {username}')
            return access_token, expires_at
        else:
            self.log.info((
                f'Cannot refresh access_token for user {username}, no '
                'refresh_token found.'))
            return None, None

    async def _fetch_new_token(self, refresh_token):
        client_id = os.environ['KEYCLOAK_CLIENT_ID']
        client_secret = os.environ['KEYCLOAK_CLIENT_SECRET']
        server_url = os.environ['KEYCLOAK_SERVER_URL']
        realm_name = os.environ['KEYCLOAK_REALM_NAME']
        token_url = os.path.join(
            server_url,
            f'auth/realms/{realm_name}/protocol/openid-connect/token')

        params = dict(
            grant_type='refresh_token',
            client_id=client_id,
            client_secret=client_secret,
            refresh_token=refresh_token,
        )
        body = urlencode(params)
        req = HTTPRequest(token_url, 'POST', body=body)
        self.log.debug(f'URL: {token_url} body: {body.replace(client_secret, "***")}')

        client = AsyncHTTPClient()
        resp = await client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        return resp_json


class AccessTokenHandler(AccessTokenMixin, APIHandler):
    async def get(self):
        if not self.current_user:
            raise HTTPError(401, 'Authentication with API token required')

        access_token, expires_at = await self.refresh_token()
        if access_token:
            response = dict(access_token=access_token, expires_at=expires_at)
        else:
            response = dict(error='Unable to retrieve access token')
        self.write(json.dumps(response))


class ArtifactPublishPrepareUploadHandler(AccessTokenMixin, APIHandler):
    async def get(self):
        if not self.current_user:
            raise HTTPError(401, 'Authentication with API token required')

        # For federated logins, Keystone authentication relies on short-lived
        # tokens from the IdP; ensure we have a fresh one stored for the user.
        await self.refresh_token()

        auth_state = await self.current_user.get_auth_state()
        openstack_rc = auth_state.get(OPENSTACK_RC_AUTH_STATE_KEY, {})
        user_session = keystone_session(env_overrides=openstack_rc)

        admin_overrides = {
            key.replace('ARTIFACT_SHARING_', ''): value
            for key, value in os.environ.items()
            if key.startswith('ARTIFACT_SHARING_OS_')
        }
        admin_session = keystone_session(env_overrides=admin_overrides)
        # NOTE(jason): we have to set interface/region_name explicitly because
        # Keystone does not read these from the session/adapter.
        admin_ks_client = KeystoneClient(session=admin_session,
            interface=os.environ.get('OS_INTERFACE'),
            region_name=os.environ.get('OS_REGION_NAME'))

        response = None
        trust_project_name = (
            os.environ.get('ARTIFACT_SHARING_TRUST_PROJECT_NAME', 'trovi'))

        try:
            trustee_user_id = user_session.get_user_id()
            trustor_user_id = admin_session.get_user_id()
            trust_project = next(iter(
                admin_ks_client.projects.list(name=trust_project_name)), None)

            if not trust_project:
                raise ValueError((
                    'Cannot create publish token because trust project '
                    f'{trust_project_name} does not exist'))

            trust = admin_ks_client.trusts.create(
                trustee_user_id, trustor_user_id, project=trust_project,
                role_names=['member'])
            self.log.info((
                f'Created trust {trust.id} for user {self.current_user} '
                f'({trustee_user_id})'))

            trust_overrides = openstack_rc.copy()
            trust_overrides['OS_TRUST_ID'] = trust.id
            # Ensure no project-scoping keys are set on the keystone session;
            # this will interfere with trust-scoping.
            project_scoping_keys = ['OS_PROJECT_NAME', 'OS_PROJECT_DOMAIN_NAME',
                                    'OS_TENANT_NAME', 'OS_TENANT_DOMAIN_NAME',
                                    'OS_PROJECT_ID', 'OS_TENANT_ID']
            for k in project_scoping_keys:
                if k in trust_overrides:
                    del trust_overrides[k]
            trust_session = keystone_session(env_overrides=trust_overrides)

            deposition_id = str(uuid.uuid4())
            response = dict(
                deposition_id=deposition_id,
                publish_endpoint=dict(
                    url=upload_url(deposition_id),
                    method='PUT',
                    headers=trust_session.get_auth_headers(),
                ),
            )
        except:
            self.log.exception(
                f'Failed to prepare upload for {self.current_user}')

        if not response:
            response = dict(error='Could not prepare upload')

        self.write(json.dumps(response))
