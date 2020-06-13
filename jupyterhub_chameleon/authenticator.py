import base64
import json
import os
from urllib.parse import urlencode

from jupyterhub.utils import url_path_join
from keystoneauthenticator import KeystoneAuthenticator
from oauthenticator.oauth2 import OAuthenticator
from oauthenticator.generic import GenericOAuthenticator
from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from tornado.web import HTTPError
from traitlets import default, Unicode

from jupyterhub.auth import Authenticator

LOGIN_FLOW_COOKIE_NAME = 'login_flow'


class ChameleonAuthenticator(Authenticator):
    auth_url = Unicode(
        config=True,
        help="""
        Keystone server auth URL
        """
    )

    @default('auth_url')
    def _auth_url(self):
        return os.environ['OS_AUTH_URL']

    @default('enable_auth_state')
    def _enable_auth_state(self):
        # The user's Keystone token is stored in auth_state and the
        # authenticator is not very useful without it.
        return True

    @default('refresh_pre_spawn')
    def _refresh_pre_spawn(self):
        """Check state of authentication token before allowing a new spawn.

        The Keystone authenticator will fail if the user's unscoped token has
        expired, forcing them to log in, which is the right thing.
        """
        return True

    @default('auth_refresh_age')
    def _auth_refresh_age(self):
        """Automatically check the auth state this often.

        This isn't very useful for us, since we can't really do anything if
        the token has expired realistically (can we?), so we increase the poll
        interval just to reduce things the authenticator has to do.

        TODO(jason): we could potentially use the auth refresh mechanism to
        generate a refresh auth token from Keycloak (and then exchange it for
        a new Keystone token.)
        """
        return 60 * 60

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.keystone_auth = KeystoneAuthenticator(**kwargs)
        self.keystone_auth.auth_url = self.auth_url
        self.oidc_auth = ChameleonKeycloakAuthenticator(**kwargs)
        self.oidc_auth.keystone_auth_url = self.auth_url

    async def authenticate(self, handler, data):
        if self._wants_oidc_login(handler.request):
            return await self.oidc_auth.authenticate(handler, data)
        else:
            return await self.keystone_auth.authenticate(handler, data)

    def _wants_oidc_login(self, request):
        return request.cookies.get(LOGIN_FLOW_COOKIE_NAME) == '2'


class ChameleonKeycloakAuthenticator(OAuthenticator):
    """The Chameleon Keycloak OAuthenticator handles both authorization and passing
    transfer tokens to the spawner.
    """

    login_service = 'Chameleon'

    keycloak_url = Unicode(
        'https://auth.chameleoncloud.org',
        config=True,
        help="""
        Keycloak server URL
        """
    )

    keycloak_realm_name = Unicode(
        'chameleon',
        config=True,
        help="""
        Keycloak realm name
        """
    )

    keystone_auth_url = Unicode(
        config=True,
        help="""
        Something
        """
    )

    keystone_interface = Unicode(
        'public',
        config=True,
        help="""
        Something
        """
    )

    keystone_identity_api_version = Unicode(
        '3',
        config=True,
        help="""
        Something
        """
    )

    keystone_identity_provider = Unicode(
        config=True,
        help="""
        Something
        """
    )

    keystone_protocol = Unicode(
        config=True,
        help="""
        Something
        """
    )

    def _keycloak_openid_endpoint(self, name):
        return (
            f'{self.keycloak_url}/auth/realms/{self.keycloak_realm_name}'
            f'protocol/openid-connect/{name}')

    @default('userdata_url')
    def _userdata_url_default(self):
        return self._keycloak_openid_endpoint('userinfo')

    @default('authorize_url')
    def _authorize_url_default(self):
        return self._keycloak_openid_endpoint('auth')

    @default('token_url')
    def _token_url_default(self):
        return self._keycloak_openid_endpoint('token')

    @default('scope')
    def _scope_default(self):
        return [
            'openid',
            'profile',
        ]

    async def authenticate(self, handler, data=None):
        """
        Authenticate with globus.org. Usernames (and therefore Jupyterhub
        accounts) will correspond to a Globus User ID, so foouser@globusid.org
        will have the 'foouser' account in Jupyterhub.
        """
        http_client = AsyncHTTPClient()
        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=handler.get_argument('code'),
            grant_type='authorization_code',
        )
        req = HTTPRequest(self.token_url, method='POST',
            headers=self.get_client_credential_headers(),
            body=urlencode(params))
        token_response = await http_client.fetch(req)
        token_json = json.loads(token_response.body.decode('utf8', 'replace'))

        user_headers = self.get_default_headers()
        user_headers['Authorization'] = (
            'Bearer {}'.format(token_json['access_token']))
        req = HTTPRequest(self.userdata_url, method='GET', headers=user_headers)
        user_resp = await http_client.fetch(req)
        user_json = json.loads(user_resp.body.decode('utf8', 'replace'))
        username, _ = user_json.get('preferred_username').split('@', 1)
        # Can also get groups here (check for Chameleon group)

        auth_token_dict = {
            attr_name: token_json.get(attr_name)
            for attr_name in [
                'expires_in', 'scope', 'token_type', 'refresh_token',
                'access_token'
            ]
        }

        if self._has_keystone_config():
            openstack_rc = {
                'OS_AUTH_URL': self.keystone_auth_url,
                'OS_INTERFACE': self.keystone_interface,
                'OS_IDENTITY_API_VERSION': self.keystone_identity_api_version,
                'OS_ACCESS_TOKEN': auth_state['token']['access_token'],
                'OS_IDENTITY_PROVIDER': self.keystone_identity_provider,
                'OS_PROTOCOL': self.keystone_protocol,
                'OS_AUTH_TYPE': 'v3oidcaccesstoken',
            }

        return {
            'name': username,
            'admin': False,
            'auth_state': {
                'client_id': self.client_id,
                'token': auth_token_dict,
                'openstack_rc': openstack_rc,
            },
        }

    def _has_keystone_config(self):
        return (
            self.keystone_auth_url and
            self.keystone_identity_provider and
            self.keystone_protocol
        )

    def get_default_headers(self):
        return {
            'Accept': 'application/json',
            'User-Agent': 'JupyterHub',
        }

    def get_client_credential_headers(self):
        headers = self.get_default_headers()
        b64key = base64.b64encode(
            bytes('{}:{}'.format(
                self.client_id, self.client_secret), 'utf8'))
        headers['Authorization'] = 'Basic {}'.format(b64key.decode('utf8'))
        return headers
