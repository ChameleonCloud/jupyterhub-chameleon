# Copyright (c) University of Chicago.
# Distributed under the terms of the Modified BSD License.
#
# Configuration file for JupyterHub
# The following environment variables affect the configuration at runtime:
#
# DATA_VOLUME_CONTAINER: (str) the directory that JupyterHub will store its
#                        runtime data in
# MYSQL_HOST: (str) the JupyterHub MySQL hostname
# MYSQL_USER: (str) the JupyterHub MySQL user (must have grants to database)
# MYSQL_PASSWORD: (str) the JupyterHub MySQL user password
# MYSQL_DATABASE: (str) the JupyterHub MySQL database used to store data
#
# See the README for the jupyterhub-chameleon module for more options.
# https://github.com/chameleoncloud/jupyterhub-chameleon
import os

import jupyterhub_chameleon

c = get_config()

##################
# Chameleon
##################

# Most configuration is handled by the jupyterhub-chameleon package
#jupyterhub_chameleon.install_extension(c)

##################
# Hub
##################

# User containers will access hub by container name on the Docker network
#c.JupyterHub.hub_ip = "jupyterhub"
#c.JupyterHub.hub_port = 8080
#c.JupyterHub.bind_url = "http://:8000"

# Persist hub data on volume mounted inside container
#data_dir = os.environ.get("DATA_VOLUME_CONTAINER", "/data")

"""
c.JupyterHub.cookie_secret_file = os.path.join(data_dir, "jupyterhub_cookie_secret")
c.JupyterHub.db_url = "mysql+mysqldb://{user}:{password}@{host}/{db}".format(
    host=os.environ["MYSQL_HOST"],
    user=os.environ["MYSQL_USER"],
    password=os.environ["MYSQL_PASSWORD"],
    db=os.environ["MYSQL_DATABASE"],
)
"""

# Whitelist admins.
#c.Authenticator.admin_users = admin = set()
# Allow admins to manage single-server instances of users.
"""
c.JupyterHub.admin_access = True
pwd = os.path.dirname(__file__)
with open(os.path.join(pwd, "adminlist")) as f:
    for line in f:
        if not line:
            continue
        admin.add(line.strip())
"""
