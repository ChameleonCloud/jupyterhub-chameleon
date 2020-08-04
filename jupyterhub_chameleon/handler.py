import hashlib
import json
import os
from urllib.parse import parse_qsl, unquote, urlencode

from jupyterhub.apihandlers import APIHandler
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join
from tornado.web import HTTPError, authenticated
from tornado.httpclient import AsyncHTTPClient, HTTPRequest

from .utils import get_import_params


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

            source, path = import_info
            sha = hashlib.sha256()
            sha.update(source.encode('utf-8'))
            sha.update(path.encode('utf-8'))
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


class AccessTokenHandler(APIHandler):
    async def get(self):
        if not self.current_user:
            raise HTTPError(401, 'Authenticatino with API token required')

        auth_state = await self.current_user.get_auth_state()

        new_tokens = await self._fetch_new_token(
            auth_state.get('refresh_token'))
        self.log.debug(new_tokens)
        auth_state['access_token'] = new_tokens['access_token']
        auth_state['refresh_token'] = new_tokens['refresh_token']

        await self.current_user.save_auth_state(auth_state)

        tokens = {'access_token': auth_state.get('access_token')}
        self.write(json.dumps(tokens))

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
