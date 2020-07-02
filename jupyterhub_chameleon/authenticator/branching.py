import base64
import json
import os
from urllib.parse import urlencode, parse_qsl

from jupyterhub.auth import Authenticator, LoginHandler
from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join
from keystoneauthenticator import KeystoneAuthenticator
from tornado import gen
from tornado.httputil import url_concat
from traitlets import default, Bool, Int, Unicode

from .keycloak import ChameleonKeycloakAuthenticator

LOGIN_FLOW_COOKIE_NAME = 'login_flow'


class DetectLoginMethodHandler(BaseHandler):
    def get(self):
        if wants_oidc_login(self):
            # oauth_login is included in the default handlers for OAuthenticator
            url = url_path_join(self.hub.base_url, 'oauth_login')
        else:
            url = url_path_join(self.hub.base_url, 'login-form')
        # Ensure we proxy any query parameters
        if self.request.query:
            url = url_concat(url, parse_qsl(self.request.query))
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


class ChameleonAuthenticator(Authenticator):
    """A branching authenticator that delegates to one of two login methods.

    Users can opt-in to a new login flow via the opt-in endpoint, which sets
    a cookie, saving this preference. If the user has opted in to the new flow,
    they will log in via the automatic OAuth redirect against Chameleon's
    Keycloak server. If they do not opt-in, they will log in via the legacy
    Keystone-based flow.
    """
    keystone_auth_url = Unicode(
        os.environ.get('OS_AUTH_URL', ''),
        config=True,
        help="""
        Keystone server auth URL
        """
    )

    keystone_region_name = Unicode(
        os.environ.get('OS_REGION_NAME', ''),
        config=True,
        help="""
        Keystone default region name
        """
    )

    hub_public_url = Unicode(
        os.getenv('JUPYTERHUB_PUBLIC_URL'),
        config=True,
        help="""
        The full (public) base URL of the JupyterHub
        server. JupyterHub should really provide this to
        managed services, but it doesn't, so we have to. The
        issue is that we are behind a reverse proxy, so we need
        to inform JupyterHub of this.
        """
    )

    # Force auto_login so that we don't render the default login form.
    auto_login = Bool(True)

    # The user's Keystone/Keycloak tokens are stored in auth_state and the
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
        self.keystone_auth.auth_url = self.keystone_auth_url
        self.keystone_auth.region_name = self.keystone_region_name
        self.keystone_auth.enable_auth_state = self.enable_auth_state

        self.oidc_auth = ChameleonKeycloakAuthenticator(**kwargs)
        self.oidc_auth.keystone_auth_url = self.keystone_auth_url
        self.oidc_auth.enable_auth_state = self.enable_auth_state

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
        """Override login_url with a custom handler that picks the flow.
        """
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
            self.log.error('auth_state is not enabled! Cannot set OpenStack RC parameters')
            return

        for rc_key, rc_value in auth_state.get('openstack_rc', {}).items():
            spawner.environment[rc_key] = rc_value

        if self.hub_public_url:
            spawner.environment['JUPYTERHUB_PUBLIC_URL'] = self.hub_public_url


def wants_oidc_login(handler):
    return handler.get_cookie(LOGIN_FLOW_COOKIE_NAME) == '2'
