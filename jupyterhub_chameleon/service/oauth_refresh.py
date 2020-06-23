"""
Original copyright 2018 Tim Head
Modified copyright 2020 University of Chicago

Inspired by the [whoami][1] example.

This can be installed as a [JupyterHub managed service][2] like the following:

    {
        'name': 'oauth-refresh',
        'command': [
            sys.executable,
            '-m', 'jupyterhub_chameleon.service.oauth_refresh',
        ]
    }

[1]: https://github.com/wildtreetech/ohjh/blob/master/images/refresher/whoami.py
[2]: https://jupyterhub.readthedocs.io/en/stable/reference/services.html#hub-managed-services
"""
import json
import os
from urllib.parse import urlencode, urlparse

import requests

from tornado.log import app_log
from tornado.ioloop import IOLoop
from tornado.httpserver import HTTPServer
from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.web import HTTPError, RequestHandler, Application, authenticated
import tornado.options

from jupyterhub.services.auth import HubAuthenticated
from jupyterhub.utils import url_path_join


async def fetch_new_token(token_url, client_id, client_secret, refresh_token):
    params = dict(
        grant_type='refresh_token',
        client_id=client_id,
        client_secret=client_secret,
        refresh_token=refresh_token,
    )
    body = urlencode(params)
    req = HTTPRequest(token_url, 'POST', body=body)
    app_log.debug('URL: %s body: %s', token_url, body)

    client = AsyncHTTPClient()
    resp = await client.fetch(req)

    resp_json = json.loads(resp.body.decode('utf8', 'replace'))
    return resp_json


class TokenHandler(HubAuthenticated, RequestHandler):
    def api_request(self, method, url, **kwargs):
        """Make an API request"""
        url = url_path_join(self.hub_auth.api_url, url)
        allow_404 = kwargs.pop('allow_404', False)
        headers = kwargs.setdefault('headers', {})
        headers.setdefault('Authorization', 'token %s' % self.hub_auth.api_token)
        try:
            r = requests.request(method, url, **kwargs)
        except requests.ConnectionError as e:
            app_log.error("Error connecting to %s: %s", url, e)
            msg = "Failed to connect to Hub API at %r." % url
            if '127.0.0.1' in url:
                msg += "  Make sure to set c.JupyterHub.hub_ip to an IP accessible to" + \
                       " single-user servers if the servers are not on the same host as the Hub."
            raise HTTPError(500, msg)

        data = None
        if r.status_code == 404 and allow_404:
            pass
        elif r.status_code == 403:
            app_log.error("I don't have permission to check authorization with JupyterHub, my auth token may have expired: [%i] %s", r.status_code, r.reason)
            app_log.error(r.text)
            raise HTTPError(500, "Permission failure checking authorization, I may need a new token")
        elif r.status_code >= 500:
            app_log.error("Upstream failure verifying auth token: [%i] %s", r.status_code, r.reason)
            app_log.error(r.text)
            raise HTTPError(502, "Failed to check authorization (upstream problem)")
        elif r.status_code >= 400:
            app_log.warning("Failed to check authorization: [%i] %s", r.status_code, r.reason)
            app_log.warning(r.text)
            raise HTTPError(500, "Failed to check authorization")
        else:
            data = r.json()

        return data

    @authenticated
    async def get(self):
        client_id = os.environ['KEYCLOAK_CLIENT_ID']
        client_secret = os.environ['KEYCLOAK_CLIENT_SECRET']
        server_url = os.environ['KEYCLOAK_SERVER_URL']
        realm_name = os.environ['KEYCLOAK_REALM_NAME']
        token_url = os.path.join(
            server_url,
            'auth/realms/{realm_name}/protocol/openid-connect/token')

        user_model = self.get_current_user()
        user_path = url_path_join('users', user_model['name'])

        # Fetch current auth state
        u = self.api_request('GET', user_path)
        app_log.error("User: %s", u)
        auth_state = u['auth_state']

        new_tokens = await fetch_new_token(
            token_url, client_id, client_secret,
            auth_state.get('refresh_token'))

        # update auth state in the hub
        auth_state['access_token'] = new_tokens['access_token']
        auth_state['refresh_token'] = new_tokens['refresh_token']
        self.api_request('PATCH', user_path,
                         data=json.dumps({'auth_state': auth_state}))

        # send new token to the user
        tokens = {'access_token': auth_state.get('access_token')}
        self.set_header('content-type', 'application/json')
        self.write(json.dumps(tokens, indent=1, sort_keys=True))


def main():
    tornado.options.parse_command_line()
    app = Application([
        (os.environ['JUPYTERHUB_SERVICE_PREFIX'] + 'tokens', TokenHandler),
    ])

    url = urlparse(os.environ['JUPYTERHUB_SERVICE_URL'])
    http_server = HTTPServer(app)
    http_server.listen(url.port, address=url.hostname)

    IOLoop.current().start()


if __name__ == '__main__':
    main()
