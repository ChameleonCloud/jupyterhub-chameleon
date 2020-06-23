=====================
jupyterhub-chameleon
=====================

**Chameleon customizations for JupyterHub, all in one module.**

This module contains several extensions and congurations relevant for Chameleon:

* A custom authenticator that handles migrating users from the legacy
  Keystone-based authenticator to a new OpenID-based authenticator (using
  Chameleon's Keycloak deployment)
* A Docker-based spawner preconfigured with volumes backed by RBD and special
  handling of user scratch directories vs. experimental (ephemeral) mounts
* An experiment import handler, which is used to craft a special spawn request
  that pulls code either from GitHub or a Zenodo deposition to create an
  ephemeral experimental environment
* A managed service that can refresh a user's access tokens

Installation
============

.. code-block:: shell

   pip install jupyterhub-chameleon

Usage
=====

The ``install_extension`` function is the easiest way to ensure everything is
configured properly, as it will make most of the adjustments to the stock
configuration for you.

.. code-block:: python

   import jupyterhub_chameleon

   c = get_config()
   jupyterhub_chameleon.install_extension(c)

   # Configure JupyterHub further as needed

Configuration options
---------------------

Environment variables are the easiest way to control the default behavior of
this module:

:DEBUG: (bool) whether to enable debug logging
:JUPYTERHUB_PUBLIC_URL: (str) the full (public) base URL of the JupyterHub
                       server. JupyterHub should really provide this to
                       managed services, but it doesn't, so we have to. The
                       issue is that we are behind a reverse proxy, so we need
                       to inform JupyterHub of this.
:DOCKER_VOLUME_DRIVER: (str) the name of the Docker volume driver to use when
                       creating user work directories
:DOCKER_VOLUME_DRIVER_OPTS: (str) options, comma-separated "key=value" pairs,
                            passed to the volume create command
:DOCKER_NOTEBOOK_IMAGE: (str) the name of the Docker image to spawn for users
:DOCKER_NETWORK_NAME: (str) the Docker network name
:KEYCLOAK_SERVER_URL: (str) the full base URL of the Keycloak server
:KEYCLOAK_REALM_NAME: (str) the Keycloak realm name to authenticate against
:KEYCLOAK_CLIENT_ID: (str) the Keycloak client ID
:KEYCLOAK_CLIENT_SECRET: (str) the Keycloak client secret
:OS_AUTH_URL: (str) the full base URL of the Keystone public endpoint
:OS_REGION_NAME: (str) an optional default Keystone region; if not set, the
                 first detected region is used when looking up services
:OS_IDENTITY_PROVIDER: (str) the Keystone identity provider to use when logging
                       in via federated authentication
:OS_PROTOCOL: (str) the Keystone federation protocol to use (openid, saml)
:CHAMELEON_SHARING_PORTAL_UPLOAD_URL: (str) the full URL for the endpoint in
                                      the Chameleon sharing portal that starts
                                      the artifact creation flow.
:CHAMELEON_SHARING_PORTAL_UPDATE_URL: (str) the full URL for the endpoint in
                                      the Chameleon sharing portal that starts
                                      the update flow.
