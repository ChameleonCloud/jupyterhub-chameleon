import base64
import json
import jwt
import os
import re
import time
from urllib.parse import urlencode

from jupyterhub.handlers.login import LogoutHandler
from jupyterhub.utils import url_path_join
from oauthenticator.generic import GenericOAuthenticator
from tornado.httpclient import HTTPClientError, HTTPRequest, AsyncHTTPClient
from traitlets import default, Bool, Int, Unicode

from .config import OPENSTACK_RC_AUTH_STATE_KEY


class LogoutRedirectHandler(LogoutHandler):
    """Redirect user to IdP logout page to clean upstream session."""

    async def render_logout_page(self):
        self.redirect(self.authenticator.token_url, permanent=False)


class SessionRefreshHandler(LogoutHandler):
    """Redirect user back to internal page after clearing their session.

    This allows an effective "refresh" flow, where if the user is already
    logged in to the IdP, they can proceed directly back to where they were
    before, but with a refreshed session.
    """

    async def render_logout_page(self, next_page=None):
        if next_page is None:
            next_page = self.get_argument("next", "/")
        if not next_page.startswith("/"):
            self.log.warning(f"Redirect to non-relative location {next_page} blocked.")
            next_page = "/"

        # Redirect relative to the hub prefix. This is very important! The reason is,
        # only by redirecting to a hub-owned path will it understand that user needs
        # to be logged in again, because we explicitly killed the Hub session/login.
        # If we directly go back to a user server, the server's session is actually
        # still alive! It's not totally clear how we can tell that cookie to get cleared
        # on logout; it seems the assumption is that users always get there via some
        # other Hub handler.
        next_page = url_path_join(self.app.hub_prefix, next_page)

        html = await self.render_template("auth_refresh.html", next_page=next_page)
        self.finish(html)


class OpenstackOAuthenticator(GenericOAuthenticator):
    """
    A generic authenticator that supports getting and refreshing user tokens.
    """

    login_service = "Chameleon"

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

    @default("scope")
    def _scope_default(self):
        return [
            "openid",
            "profile",
        ]

    #hub_public_url = Unicode(
    #    os.getenv("JUPYTERHUB_PUBLIC_URL"),
    #    config=True,
    #    help="""
    #    The full (public) base URL of the JupyterHub
    #    server. JupyterHub should really provide this to
    #    managed services, but it doesn't, so we have to. The
    #    issue is that we are behind a reverse proxy, so we need
    #    to inform JupyterHub of this.
    #    """,
    #)

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

    async def authenticate(self, handler, data=None):
        # TODO fix overrides here
        """Authenticate with Keycloak."""
        auth_dict = await super().authenticate(handler, data)

        auth_state = auth_dict["auth_state"]

        access_token = auth_state["access_token"]
        decoded_access_token = jwt.decode(
            access_token, options={"verify_signature": False}
        )

        refresh_token = auth_state["refresh_token"]
        decoded_refresh_token = jwt.decode(
            refresh_token, options={"verify_signature": False}
        )

        expires_at = decoded_access_token.get("exp")
        refresh_expires_at = decoded_refresh_token.get("exp")

        user_headers = self._get_default_headers()
        user_headers["Authorization"] = "Bearer {}".format(access_token)
        req = HTTPRequest(self.userdata_url, method="GET", headers=user_headers)
        try:
            http_client = AsyncHTTPClient()
            user_resp = await http_client.fetch(req)
        except HTTPClientError as err:
            self.log.error(f"Unexpected HTTP error fetching user data: {err}")
            return None

        user_json = json.loads(user_resp.body.decode("utf8", "replace"))
        username = user_json.get("preferred_username")
        # TODO override this in keycloak
        is_admin = os.getenv("OAUTH_ADMIN_PROJECT", "Chameleon") in map(
            lambda x : x.get("id"), user_json.get("projects", [])
        )

        user_projects = user_json.get("projects", [])
        has_active_allocations = len(user_projects) > 0
        if not has_active_allocations:
            self.log.info(f"User {username} does not have any active allocations")
            return None
        if self._has_keystone_config():
            openstack_rc = {
                "OS_AUTH_URL": self.keystone_auth_url,
                "OS_INTERFACE": self.keystone_interface,
                "OS_IDENTITY_API_VERSION": self.keystone_identity_api_version,
                "OS_ACCESS_TOKEN": access_token,
                "OS_IDENTITY_PROVIDER": self.keystone_identity_provider,
                "OS_PROTOCOL": self.keystone_protocol,
                "OS_AUTH_TYPE": "v3oidcaccesstoken",
                "OS_PROJECT_DOMAIN_NAME": self.keystone_project_domain_name,
            }
            if self.keystone_default_region_name:
                openstack_rc["OS_REGION_NAME"] = self.keystone_default_region_name
            if user_projects:
                openstack_rc["OS_PROJECT_NAME"] = user_projects[0]["id"]
        else:
            self.log.warning(
                (
                    "No Keystone configuration available, cannot set OpenStack "
                    "RC variables"
                )
            )
            openstack_rc = None

        auth_state["is_federated"] = True
        auth_state["expires_at"] = expires_at
        auth_state["refresh_expires_at"] = refresh_expires_at
        auth_state[OPENSTACK_RC_AUTH_STATE_KEY] = openstack_rc
        return {
            "name": username,
            "admin": is_admin,
            "auth_state": auth_state,
        }

    async def pre_spawn_start(self, user, spawner):
        """Fill in OpenRC environment variables from user auth state."""
        auth_state = await user.get_auth_state()
        if not auth_state:
            # auth_state not enabled
            self.log.error(
                "auth_state is not enabled! Cannot set OpenStack RC parameters"
            )
            return

        openrc_vars = auth_state.get(OPENSTACK_RC_AUTH_STATE_KEY, {})
        self.log.info(openrc_vars)
        for rc_key, rc_value in openrc_vars.items():
            spawner.environment[rc_key] = rc_value

    def get_handlers(self, app):
        """Override the default handlers to include a custom logout handler."""
        # Override the /logout handler; because our handlers are installed
        # first, and the first match wins, our logout handler is preferred,
        # which is good, because JupyterLab can only invoke this handler
        # when the user wants to log out, currently.
        handlers = [
            ("/logout", LogoutRedirectHandler),
            ("/auth/refresh", SessionRefreshHandler),
        ]
        handlers.extend(super().get_handlers(app))
        return handlers

    def _has_keystone_config(self):
        return (
            self.keystone_auth_url
            and self.keystone_identity_provider
            and self.keystone_protocol
        )

    def _get_default_headers(self):
        return {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
        }

    def _get_client_credential_headers(self):
        headers = self._get_default_headers()
        b64key = base64.b64encode(
            bytes("{}:{}".format(self.client_id, self.client_secret), "utf8")
        )
        headers["Authorization"] = "Basic {}".format(b64key.decode("utf8"))
        return headers
