import base64
import json
import os
from urllib.parse import urlencode

from oauthenticator.oauth2 import OAuthenticator, OAuthLoginHandler, OAuthCallbackHandler
from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from traitlets import default, Unicode


class ForceOAuthUsageMixin:
    @property
    def authenticator(self):
        """When inside an OAuth login handler, force using the OAuthenticator.

        This is necessary because the handlers reference the Authenticator
        instance configured to JupyterHub, which will be the wrapper
        authencitator, which does not have much of the API required by the
        OAuthenticator handlers.
        """
        return self.settings.get('authenticator').oidc_auth


class ChameleonOAuthCallbackHandler(ForceOAuthUsageMixin, OAuthCallbackHandler):
    pass


class ChameleonOAuthLoginHandler(ForceOAuthUsageMixin, OAuthLoginHandler):
    pass


class ChameleonKeycloakAuthenticator(OAuthenticator):
    """The Chameleon Keycloak OAuthenticator handles both authorization and passing
    transfer tokens to the spawner.
    """

    login_service = 'Chameleon'

    login_handler = ChameleonOAuthLoginHandler
    callback_handler = ChameleonOAuthCallbackHandler

    client_id_env = 'KEYCLOAK_CLIENT_ID'
    client_secret_env = 'KEYCLOAK_CLIENT_SECRET'

    keycloak_url = Unicode(
        os.getenv('KEYCLOAK_SERVER_URL', 'https://auth.chameleoncloud.org'),
        config=True,
        help="""
        Keycloak server absolue URL, protocol included
        """
    )

    keycloak_realm_name = Unicode(
        os.getenv('KEYCLOAK_REALM_NAME', 'chameleon'),
        config=True,
        help="""
        Keycloak realm name
        """
    )

    keystone_auth_url = Unicode(
        os.getenv('OS_AUTH_URL', ''),
        config=True,
        help="""
        Keystone authentication URL
        """
    )

    keystone_interface = Unicode(
        os.getenv('OS_INTERFACE', 'public'),
        config=True,
        help="""
        Keystone endpoint interface
        """
    )

    keystone_identity_api_version = Unicode(
        os.getenv('OS_IDENTITY_API_VERSION', '3'),
        config=True,
        help="""
        Keystone API version (default=v3)
        """
    )

    keystone_identity_provider = Unicode(
        os.getenv('OS_IDENTITY_PROVIDER', 'chameleon'),
        config=True,
        help="""
        Keystone identity provider name. This identity provider must have its
        client ID included as an additional audience in tokens generated for
        the client ID specified in `keycloak_client_id`. This allows the token
        generated for one client to be re-used to authenticate against another.
        """
    )

    keystone_protocol = Unicode(
        os.getenv('OS_PROTOCOL', 'openid'),
        config=True,
        help="""
        Keystone identity protocol name
        """
    )

    keystone_default_region_name = Unicode(
        os.getenv('OS_REGION_NAME', ''),
        config=True,
        help="""
        A default region to use when choosing Keystone endpoints
        """
    )

    def _keycloak_openid_endpoint(self, name):
        realm = self.keycloak_realm_name
        return os.path.join(
            self.keycloak_url,
            f'auth/realms/{realm}/protocol/openid-connect/{name}')

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
        """Authenticate with Keycloak.
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
        username = user_json.get('preferred_username').split('@', 1)[0]
        # Can also get groups here (check for Chameleon group)

        access_token = token_json['access_token']
        refresh_token = token_json['refresh_token']

        if self._has_keystone_config():
            openstack_rc = {
                'OS_AUTH_URL': self.keystone_auth_url,
                'OS_INTERFACE': self.keystone_interface,
                'OS_IDENTITY_API_VERSION': self.keystone_identity_api_version,
                'OS_ACCESS_TOKEN': access_token,
                'OS_IDENTITY_PROVIDER': self.keystone_identity_provider,
                'OS_PROTOCOL': self.keystone_protocol,
                'OS_AUTH_TYPE': 'v3oidcaccesstoken',
            }
            if self.keystone_default_region_name:
                openstack_rc['OS_REGION_NAME'] = (
                    self.keystone_default_region_name)
        else:
            openstack_rc = None

        return {
            'name': username,
            'admin': False,
            'auth_state': {
                'access_token': access_token,
                'refresh_token': refresh_token,
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
