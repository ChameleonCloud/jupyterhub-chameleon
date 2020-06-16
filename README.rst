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
