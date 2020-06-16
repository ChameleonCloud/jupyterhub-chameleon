import hashlib
from urllib.parse import parse_qsl, unquote, urlencode

from jupyterhub.handlers import BaseHandler
from jupyterhub.utils import url_path_join
from tornado import web

from .utils import get_import_params


class UserRedirectExperimentHandler(BaseHandler):
    """Redirect spawn requests to user servers.

    /import?{query vars} will spawn a new experiment server
    Server will be initialized with a git repo/zenodo zip file as specified
    If the user is not logged in, send to login URL, redirecting back here.
    """
    @web.authenticated
    def get(self):
        base_spawn_url = url_path_join(
            self.hub.base_url, 'spawn', self.current_user.name)

        if self.request.query:
            query = dict(parse_qsl(self.request.query))
            import_info = get_import_params(query)

            if not import_info:
                raise web.HTTPError(400, (
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
