import base64
import json
import os
from urllib.parse import urlencode

from jupyterhub.auth import LoginHandler
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join
from keystoneauthenticator import KeystoneAuthenticator
from oauthenticator.oauth2 import OAuthenticator, OAuthLoginHandler, OAuthCallbackHandler
from oauthenticator.generic import GenericOAuthenticator
from tornado import gen
from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from tornado.web import HTTPError
from traitlets import default, Bool, Int, Unicode

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

    auto_login = Bool(True)

    # The user's Keystone token is stored in auth_state and the
    # authenticator is not very useful without it.
    enable_auth_state = Bool(True)

    # Check state of authentication token before allowing a new spawn.
    # The Keystone authenticator will fail if the user's unscoped token has
    # expired, forcing them to log in, which is the right thing.
    refresh_pre_spawn = Bool(True)

    # Automatically check the auth state this often.

    # This isn't very useful for us, since we can't really do anything if
    # the token has expired realistically (can we?), so we increase the poll
    # interval just to reduce things the authenticator has to do.

    # TODO(jason): we could potentially use the auth refresh mechanism to
    # generate a refresh auth token from Keycloak (and then exchange it for
    # a new Keystone token.)
    auth_refresh_age = Int(60 * 60)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.keystone_auth = KeystoneAuthenticator(**kwargs)
        self.keystone_auth.auth_url = self.auth_url
        self.oidc_auth = ChameleonKeycloakAuthenticator(**kwargs)
        self.oidc_auth.keystone_auth_url = self.auth_url

        proxy_attrs = ['enable_auth_state']
        for attr in proxy_attrs:
            value = getattr(self, attr)
            setattr(self.keystone_auth, attr, value)
            setattr(self.oidc_auth, attr, value)

    async def authenticate(self, handler, data):
        if wants_oidc_login(handler):
            return await self.oidc_auth.authenticate(handler, data)
        else:
            return await self.keystone_auth.authenticate(handler, data)

    def get_callback_url(self, handler=None):
        """Shim the get_callback_url function required for OAuthenticator.

        This is necessary because somewhere in the request handler flow, this
        function is called via a reference to the parent authenticator instance.
        """
        return self.oidc_auth.get_callback_url(handler)

    def login_url(self, base_url):
        return url_path_join(base_url, 'login-start')

    def get_handlers(self, app):
        handlers = [
            ('/login-start', DetectLoginMethodHandler),
            ('/new-login-flow', NewLoginFlowOptInHandler),
            ('/login-form', LoginFormHandler),
        ]
        handlers.extend(self.keystone_auth.get_handlers(app))
        handlers.extend(self.oidc_auth.get_handlers(app))
        return handlers

    @gen.coroutine
    def pre_spawn_start(self, user, spawner):
        """Fill in OpenRC environment variables from user auth state.
        """
        auth_state = yield user.get_auth_state()
        if not auth_state:
            # auth_state not enabled
            self.log.warning('auth_state is not enabled! Cannot set OpenStack RC parameters')
            return
        self.log.info('auth_state = %s' % auth_state)
        for rc_key, rc_value in auth_state.get('openstack_rc', {}).items():
            spawner.environment[rc_key] = rc_value


class ForceOAuthUsageMixin:
    @property
    def authenticator(self):
        """When inside an OAuth login handler, force using the OAuthenticator.
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
        Keycloak server URL
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
        'chameleon',
        config=True,
        help="""
        Something
        """
    )

    keystone_protocol = Unicode(
        'openid',
        config=True,
        help="""
        Something
        """
    )

    def _keycloak_openid_endpoint(self, name):
        return (
            f'{self.keycloak_url}/auth/realms/{self.keycloak_realm_name}'
            f'/protocol/openid-connect/{name}')

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
        username = user_json.get('preferred_username').split('@', 1)[0]
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
                'OS_ACCESS_TOKEN': auth_token_dict['access_token'],
                'OS_IDENTITY_PROVIDER': self.keystone_identity_provider,
                'OS_PROTOCOL': self.keystone_protocol,
                'OS_AUTH_TYPE': 'v3oidcaccesstoken',
            }
        else:
            openstack_rc = None

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


def wants_oidc_login(handler):
    return handler.get_cookie(LOGIN_FLOW_COOKIE_NAME) == '2'


class DetectLoginMethodHandler(BaseHandler):
    def get(self):
        if wants_oidc_login(self):
            url = url_path_join(self.hub.base_url, 'oauth_login')
        else:
            url = url_path_join(self.hub.base_url, 'login-form')
        self.redirect(url)


class NewLoginFlowOptInHandler(BaseHandler):
    def get(self):
        self._set_cookie(LOGIN_FLOW_COOKIE_NAME, '2', encrypted=False,
                         expires_days=30)
        self.redirect(url_path_join(self.hub.base_url, 'login-start'))


class LoginFormHandler(LoginHandler):
    async def get(self):
        """Patched from the default LoginHandler to remove auto_login logic.

        We have our own auto-login handler implemented and the default
        auto_login logic bundled in the default handler, which renders a login
        page, cause an redirect loop.
        """
        username = self.get_argument('username', default='')
        self.finish(self._render(username=username))
