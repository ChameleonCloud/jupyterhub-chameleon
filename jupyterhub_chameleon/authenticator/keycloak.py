import base64
import json
import os
import time
from urllib.parse import urlencode

from jupyterhub.handlers.login import LogoutHandler
from jupyterhub.utils import url_path_join
from oauthenticator.oauth2 import OAuthenticator
from tornado.httpclient import HTTPClientError, HTTPRequest, AsyncHTTPClient
from traitlets import default, Bool, Int, Unicode

from .config import OPENSTACK_RC_AUTH_STATE_KEY

from .openstack_oauth import OpenstackOAuthenticator

class ChameleonKeycloakAuthenticator(OpenstackOAuthenticator):
    """The Chameleon Keycloak OAuthenticator handles both authorization and passing
    transfer tokens to the spawner.
    """

    login_service = "Chameleon"

    client_id_env = "KEYCLOAK_CLIENT_ID"
    client_secret_env = "KEYCLOAK_CLIENT_SECRET"

    keycloak_url = Unicode(
        os.getenv("KEYCLOAK_SERVER_URL", "https://auth.chameleoncloud.org"),
        config=True,
        help="""
        Keycloak server absolue URL, protocol included
        """,
    )

    keycloak_realm_name = Unicode(
        os.getenv("KEYCLOAK_REALM_NAME", "chameleon"),
        config=True,
        help="""
        Keycloak realm name
        """,
    )

    keystone_auth_url = Unicode(
        os.getenv("OS_AUTH_URL", ""),
        config=True,
        help="""
        Keystone authentication URL
        """,
    )

    keystone_interface = Unicode(
        os.getenv("OS_INTERFACE", "public"),
        config=True,
        help="""
        Keystone endpoint interface
        """,
    )

    keystone_identity_api_version = Unicode(
        os.getenv("OS_IDENTITY_API_VERSION", "3"),
        config=True,
        help="""
        Keystone API version (default=v3)
        """,
    )

    keystone_identity_provider = Unicode(
        os.getenv("OS_IDENTITY_PROVIDER", "chameleon"),
        config=True,
        help="""
        Keystone identity provider name. This identity provider must have its
        client ID included as an additional audience in tokens generated for
        the client ID specified in `keycloak_client_id`. This allows the token
        generated for one client to be re-used to authenticate against another.
        """,
    )

    keystone_protocol = Unicode(
        os.getenv("OS_PROTOCOL", "openid"),
        config=True,
        help="""
        Keystone identity protocol name
        """,
    )

    keystone_project_domain_name = Unicode(
        os.getenv("OS_PROJECT_DOMAIN_NAME", "chameleon"),
        config=True,
        help="""
        Keystone domain name for federated domain
        """,
    )

    keystone_default_region_name = Unicode(
        os.getenv("OS_REGION_NAME", ""),
        config=True,
        help="""
        A default region to use when choosing Keystone endpoints
        """,
    )

    def _keycloak_openid_endpoint(self, name):
        realm = self.keycloak_realm_name
        return os.path.join(
            self.keycloak_url, f"auth/realms/{realm}/protocol/openid-connect/{name}"
        )

    @default("userdata_url")
    def _userdata_url_default(self):
        return self._keycloak_openid_endpoint("userinfo")

    @default("authorize_url")
    def _authorize_url_default(self):
        return self._keycloak_openid_endpoint("auth")

    @default("token_url")
    def _token_url_default(self):
        return self._keycloak_openid_endpoint("token")

    @default("scope")
    def _scope_default(self):
        return [
            "openid",
            "profile",
        ]

    @property
    def keycloak_realm_url(self):
        return f"{self.keycloak_url}/auth/realms/{self.keycloak_realm_name}"

    @property
    def logout_redirect_url(self):
        params = {
            "client_id": self.client_id,
        }
        return f"{self.keycloak_realm_url}/post-logout?{urlencode(params)}"

