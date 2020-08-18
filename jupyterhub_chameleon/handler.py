import hashlib
import json
import os
from urllib.parse import parse_qsl, unquote, urlencode

from jupyterhub.apihandlers import APIHandler
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join
from keystoneauth1.session import Session
from keystoneclient.v3.client import Client as KeystoneClient
from tornado.web import HTTPError, authenticated
from tornado.httpclient import AsyncHTTPClient, HTTPRequest

from .authenticator.config import OPENSTACK_RC_AUTH_STATE_KEY
from .utils import get_import_params, keystone_session


class UserRedirectExperimentHandler(BaseHandler):
    """Redirect spawn requests to user servers.

    /import?{query vars} will spawn a new experiment server
    Server will be initialized with a git repo/zenodo zip file as specified
    If the user is not logged in, send to login URL, redirecting back here.
    """
    @authenticated
    def get(self):
        base_spawn_url = url_path_join(
            self.hub.base_url, 'spawn', self.current_user.name)

        if self.request.query:
            query = dict(parse_qsl(self.request.query))
            import_info = get_import_params(query)

            if not import_info:
                raise HTTPError(400, (
                    'Missing required arguments: source, src_path'))

            repo, id = import_info
            sha = hashlib.sha256()
            sha.update(repo.encode('utf-8'))
            sha.update(id.encode('utf-8'))
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
    async def refresh_token(self):
        auth_state = await self.current_user.get_auth_state()
        refresh_token = auth_state.get('refresh_token')

        if refresh_token:
            new_tokens = await self._fetch_new_token(refresh_token)
            access_token = new_tokens.get('access_token')
            if access_token:
                auth_state['access_token'] = access_token
                auth_state['refresh_token'] = new_tokens['refresh_token']
                auth_state[OPENSTACK_RC_AUTH_STATE_KEY].update({
                    'OS_ACCESS_TOKEN': access_token,
                })
                await self.current_user.save_auth_state(auth_state)
                self.log.info(
                    f'Refreshed access token for user {self.current_user}')
            return access_token
        else:
            self.log.info((
                f'Cannot refresh access_token for user {self.current_user}, no '
                'refresh_token found.'))
            return None

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

        access_token = await self.refresh_token()
        if access_token:
            response = dict(access_token=access_token)
        else:
            response = dict(error='Unable to retrieve access token')
        self.write(json.dumps(response))


class ArtifactPublishUploadTokenHandler(AccessTokenMixin, APIHandler):
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
            user_token = user_session.get_token()
            user_info = admin_ks_client.tokens.validate(user_token)
            trustee_user_id = user_info.user_id
            admin_token = admin_session.get_token()
            admin_info = admin_ks_client.tokens.validate(admin_token)
            trustor_user_id = admin_info.user_id
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

            # Re-scope to trust
            # NOTE(jason): it's unclear if it's actually necessary to generate
            # the token at this point. It does make a few things easier in
            # the jupyterlab-chameleon extension though, as we don't have to
            # bootstrap the user's auth creds from their environment.
            trust_overrides = openstack_rc.copy()
            trust_overrides.update(dict(OS_TRUST_ID=trust.id))
            trust_session = keystone_session(env_overrides=trust_overrides)
            response = dict(
                auth_url=trust_session.auth.auth_url,
                token=trust_session.get_token(),
                trust_id=trust.id,
            )
        except:
            self.log.exception(
                f'Failed to issue publish token for {self.current_user}')

        if not response:
            response = dict(error='Could not obtain publish token')

        self.write(json.dumps(response))
