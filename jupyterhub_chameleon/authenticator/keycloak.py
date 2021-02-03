import base64
import json
import os
import time
from urllib.parse import urlencode

from jupyterhub.handlers.login import LogoutHandler
from oauthenticator.oauth2 import OAuthenticator
from tornado.httpclient import HTTPClientError, HTTPRequest, AsyncHTTPClient
from traitlets import default, Bool, Int, Unicode

from .config import OPENSTACK_RC_AUTH_STATE_KEY


class LogoutRedirectHandler(LogoutHandler):
    """Redirect user to IdP logout page to clean upstream session.
    """
    async def render_logout_page(self):
        self.redirect(self.authenticator.logout_redirect_url, permanent=False)


class SessionRefreshHandler(LogoutHandler):
    """Redirect user back to internal page after clearing their session.

    This allows an effective "refresh" flow, where if the user is already
    logged in to the IdP, they can proceed directly back to where they were
    before, but with a refreshed session.
    """
    async def render_logout_page(self):
        next_page = self.get_argument("next", "/")
        if not next_page.startswith("/"):
            self.log.warning(
                f"Redirect to non-relative location {next_page} blocked.")
            next_page = "/"

        html = await self.render_template(
            'auth_refresh.html', next_page=next_page)
        self.finish(html)



class ChameleonKeycloakAuthenticator(OAuthenticator):
    """The Chameleon Keycloak OAuthenticator handles both authorization and passing
    transfer tokens to the spawner.
    """

    login_service = 'Chameleon'

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

    client_id_env = 'KEYCLOAK_CLIENT_ID'
    client_secret_env = 'KEYCLOAK_CLIENT_SECRET'

    keycloak_groups_claim = Unicode(
        os.getenv('KEYCLOAK_GROUPS_CLAIM', 'project_names'),
        config=True,
        help="""
        User info claim that contains the list of groups the user is in.
        """
    )

    keycloak_admin_group = Unicode(
        os.getenv('KEYCLOAK_ADMIN_GROUP', 'Chameleon'),
        config=True,
        help="""
        The group representing system admins. Any user belonging to this group
        will be granted the admin status in JupyterHub.
        """
    )

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

    keystone_project_domain_name = Unicode(
        os.getenv('OS_PROJECT_DOMAIN_NAME', 'chameleon'),
        config=True,
        help="""
        Keystone domain name for federated domain
        """
    )

    keystone_default_region_name = Unicode(
        os.getenv('OS_REGION_NAME', ''),
        config=True,
        help="""
        A default region to use when choosing Keystone endpoints
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

    @property
    def keycloak_realm_url(self):
        return f'{self.keycloak_url}/auth/realms/{self.keycloak_realm_name}'

    @property
    def logout_redirect_url(self):
        params = {
            'client_id': self.client_id,
            'redirect_uri': f'{self.keycloak_realm_url}/post-logout?client_id={self.client_id}',
        }
        return f'{self.keycloak_realm_url}/protocol/openid-connect/logout?{urlencode(params)}'

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
            headers=self._get_client_credential_headers(),
            body=urlencode(params))
        try:
            token_response = await http_client.fetch(req)
        except HTTPClientError as err:
            if err.code == 401:
                self.log.info((
                    "OIDC login failed due to invalid credentials. This could "
                    "be due to an invalid client secret_key configured."))
            else:
                self.log.error(
                    f"Unexpected HTTP error authenticating user: {err}")
            return None

        token_json = json.loads(token_response.body.decode('utf8', 'replace'))
        access_token = token_json['access_token']
        refresh_token = token_json['refresh_token']
        expires_at = time.time() + int(token_json.get('expires_in', 0))

        user_headers = self._get_default_headers()
        user_headers['Authorization'] = 'Bearer {}'.format(access_token)
        req = HTTPRequest(self.userdata_url, method='GET', headers=user_headers)
        try:
            user_resp = await http_client.fetch(req)
        except HTTPClientError as err:
            self.log.error(f"Unexpected HTTP error fetching user data: {err}")
            return None

        user_json = json.loads(user_resp.body.decode('utf8', 'replace'))
        username = user_json.get('preferred_username').split('@', 1)[0]
        is_admin = (
            self.keycloak_admin_group
            in user_json.get(self.keycloak_groups_claim, []))

        has_active_allocations = len(user_json.get('projects', [])) > 0
        if not has_active_allocations:
            self.log.info(
                f'User {username} does not have any active allocations')
            return None

        if self._has_keystone_config():
            openstack_rc = {
                'OS_AUTH_URL': self.keystone_auth_url,
                'OS_INTERFACE': self.keystone_interface,
                'OS_IDENTITY_API_VERSION': self.keystone_identity_api_version,
                'OS_ACCESS_TOKEN': access_token,
                'OS_IDENTITY_PROVIDER': self.keystone_identity_provider,
                'OS_PROTOCOL': self.keystone_protocol,
                'OS_AUTH_TYPE': 'v3oidcaccesstoken',
                'OS_PROJECT_DOMAIN_NAME': self.keystone_project_domain_name,
            }
            if self.keystone_default_region_name:
                openstack_rc['OS_REGION_NAME'] = (
                    self.keystone_default_region_name)
        else:
            self.log.warning((
                'No Keystone configuration available, cannot set OpenStack '
                'RC variables'))
            openstack_rc = None

        return {
            'name': username,
            'admin': is_admin,
            'auth_state': {
                'is_federated': True,
                'access_token': access_token,
                'refresh_token': refresh_token,
                'expires_at': expires_at,
                OPENSTACK_RC_AUTH_STATE_KEY: openstack_rc,
            },
        }

    async def pre_spawn_start(self, user, spawner):
        """Fill in OpenRC environment variables from user auth state.
        """
        auth_state = await user.get_auth_state()
        if not auth_state:
            # auth_state not enabled
            self.log.error(
                'auth_state is not enabled! Cannot set OpenStack RC parameters')
            return

        openrc_vars = auth_state.get(OPENSTACK_RC_AUTH_STATE_KEY, {})
        for rc_key, rc_value in openrc_vars.items():
            spawner.environment[rc_key] = rc_value

        if self.hub_public_url:
            spawner.environment['JUPYTERHUB_PUBLIC_URL'] = self.hub_public_url

    def get_handlers(self, app):
        """Override the default handlers to include a custom logout handler.
        """
        # Override the /logout handler; because our handlers are installed
        # first, and the first match wins, our logout handler is preferred,
        # which is good, because JupyterLab can only invoke this handler
        # when the user wants to log out, currently.
        handlers = [
            ('/logout', LogoutRedirectHandler),
            ('/auth/refresh', SessionRefreshHandler),
        ]
        handlers.extend(super().get_handlers(app))
        return handlers

    def _has_keystone_config(self):
        return (
            self.keystone_auth_url and
            self.keystone_identity_provider and
            self.keystone_protocol
        )

    def _get_default_headers(self):
        return {
            'Accept': 'application/json',
            'User-Agent': 'JupyterHub',
        }

    def _get_client_credential_headers(self):
        headers = self._get_default_headers()
        b64key = base64.b64encode(
            bytes('{}:{}'.format(
                self.client_id, self.client_secret), 'utf8'))
        headers['Authorization'] = 'Basic {}'.format(b64key.decode('utf8'))
        return headers
