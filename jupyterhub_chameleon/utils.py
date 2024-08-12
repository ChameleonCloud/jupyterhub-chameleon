import argparse
import os
import tempfile
import time
from urllib.parse import parse_qsl

import asyncssh
from chi import clients, lease, server
from keystoneauth1 import loading
from keystoneauth1.session import Session
from openstack.config import cloud_region
from openstack.connection import Connection

TROVI_URN_PREFIX = "urn:trovi:"


def parse_trovi_contents_urn(urn: str):
    backend, id = urn.replace(f"{TROVI_URN_PREFIX}contents:", "").split(":", 1)
    return backend, id


class Artifact:
    """A shared experiment/research artifact that can be spawned in JupyterHub.

    Attrs:
        uuid (str): the UUID of the artifact.
        version_slug (str): the version slug of the artifact.
        contents_urn (str): the URN of the artifact's Trovi contents.
        contents_id (str): DEPRECATED: the ID of the artifact's Trovi contents.
            This is derived from the URN.
        contents_backend (str): DEPRECATED: the name of the artifact's Trovi contents
            backend. This is derived from the URN.
        contents_url (str): the access URL for the artifact's Trovi contents.
        contents_proto (str): the protocol for accessing the artifact's Trovi contents.
        ownership (str): the requesting user's ownership status of this
            artifact. Default = "fork".
        ephemeral (bool): whether the artifact's working environment should
            be considered temporary. This can indicate that, e.g., nothing
            from the working directory should be saved when the spawned
            environment is torn down. Default = False.
    """

    def __init__(
        self,
        uuid=None,
        version_slug=None,
        contents_urn=None,
        contents_id=None,
        contents_backend=None,
        contents_url=None,
        contents_proto=None,
        ownership="fork",
        ephemeral=None,
    ):
        self.uuid = uuid
        self.version_slug = version_slug
        self.contents_urn = contents_urn
        id_from_urn, backend_from_urn = parse_trovi_contents_urn(contents_urn)
        self.contents_id = contents_id if contents_id else id_from_urn
        self.contents_backend = (
            contents_backend if contents_backend else backend_from_urn
        )
        self.contents_url = contents_url
        self.contents_proto = contents_proto
        self.ownership = ownership
        self.ephemeral = ephemeral in [True, "True", "true", "yes", "1"]

        # Only the contents information is required. Theoretically this can
        # allow importing from other sources that are not yet existing on Trovi.
        if not (contents_url and contents_proto):
            raise ValueError("Missing contents information")

    @classmethod
    def from_query(cls, query):
        if isinstance(query, str):
            query = dict(parse_qsl(query))

        try:
            return cls(**query)
        except Exception:
            return None


def keystone_session(env_overrides: dict = {}) -> Session:
    """Obtain Keystone authentication credentials for given OpenStack RC params.

    Args:
        env_overrides (dict): a dictionary of OpenStack RC parameters. These
            parameters are assumed to be as if they were pulled off of the
            environment, e.g. are like {'OS_USERNAME': '', 'OS_PASSWORD: ''}
            with uppercase and underscores.

    Returns:
        keystoneauth1.session.Session: a KSA session object, which can be used
            to authenticate any OpenStack client.
    """
    # We are abusing the KSA loading mechanism here. The arg parser will default
    # the various OpenStack auth params from the environment, which is what
    # we're after.
    fake_argv = [
        f'--{key.lower().replace("_", "-")}={value}'
        for key, value in env_overrides.items()
        # NOTE(jason): we ignore some environment variables, as they are not
        # supported as KSA command-line args.
        if key not in ["OS_IDENTITY_API_VERSION"]
    ]
    parser = argparse.ArgumentParser()
    loading.cli.register_argparse_arguments(parser, fake_argv, default="token")
    loading.session.register_argparse_arguments(parser)
    loading.adapter.register_argparse_arguments(parser)
    args = parser.parse_args(fake_argv)
    auth = loading.cli.load_from_argparse_arguments(args)
    return Session(auth=auth)


def artifact_sharing_keystone_session():
    artifact_sharing_overrides = {
        key.replace("ARTIFACT_SHARING_", ""): value
        for key, value in os.environ.items()
        if key.startswith("ARTIFACT_SHARING_OS_")
    }
    return artifact_sharing_overrides
    # return keystone_session(env_overrides=artifact_sharing_overrides)


class SpawnerException(ValueError):
    def __init__(self, message):
        self.jupyterhub_message = message


class ChameleonNodeProvisioner(object):
    def __init__(self, spawner, auth_state, query_args):
        # Set up ks session with user's auth
        self.query_args = query_args
        openrc = auth_state["openstack_rc"]
        self.session = keystone_session(openrc)

        def new_session():
            return self.session

        clients.session_factory = new_session
        self.blazar_client = clients.blazar()
        self.nova_client = clients.nova()
        self.neutron_client = clients.neutron()
        self.spawner = spawner

    def _find_res_id(self, my_lease, res_type):
        if not my_lease:
            my_lease = self.lease
        try:
            return next(
                r["id"] for r in my_lease["reservations"]
                if r["resource_type"] == res_type
            )
        except StopIteration:
            return None

    def add_progress_message(self, message):
        self.spawner.log.info(f"Progress: {message}")
        self.spawner.message_queue.append({
            "message": message,
        })

    def get_fip_reservation(self, my_lease=None):
        return self._find_res_id(my_lease, "virtual:floatingip")

    def get_host_reservation(self, my_lease=None):
        return self._find_res_id(my_lease, "physical:host")

    def get_or_create_lease(self):
        try:
            tmp_lease = self.blazar_client.lease.get(self.query_args["lease_id"])
            if not self.get_fip_reservation(tmp_lease):
                raise SpawnerException("Selected lease needs floating IP reservation.")
            elif not self.get_host_reservation(tmp_lease):
                raise SpawnerException("Selected lease needs a host reservation.")
            self.add_progress_message(f"Using existing lease '{tmp_lease['name']}'")
            self.lease = tmp_lease
        except Exception as e:
            self.spawner.log.info(e)
            self.add_progress_message("Creating lease.")
            reservations = []
            lease.add_node_reservation(reservations, node_type="compute_cascadelake_r", count=1)
            lease.add_fip_reservation(reservations, count=1)
            start_date, end_date = lease.lease_duration(days=0, hours=3)
            self.lease = lease.create_lease(
                f"{self.spawner._get_unix_user()}-jupyter-{start_date}",
                reservations,
                start_date='now',
                end_date=end_date
            )
            if not self.lease:
                raise SpawnerException("Could not create lease.")
            self.add_progress_message("Waiting for lease to start.")
            # TODO wait for lease to start
            time.sleep(60)

    def delete_lease(self):
        self.blazar_client.lease.delete(self.lease["id"])

    def get_or_create_instance(self):
        # server.update_keypair(
        #     key_name="jh_key", public_key="/keys/id_rsa.pub")
        server_name = f"{self.spawner._get_unix_user()}-jupyter"
        try:
            self.server = server.show_server_by_name(server_name)
            self.add_progress_message(f"Using existing node {server_name}.")
        except:
            self.add_progress_message("Provisioning node.")
            self.server = server.create_server(
                server_name,
                image_name="CC-Ubuntu22.04",
                reservation_id=self.get_host_reservation(),
                key_name="test_key",
            )
            self.add_progress_message("Waiting for node to start.")
            while True:
                try:
                    if self.nova_client.servers.get(self.nova_server.id).status == "ACTIVE":
                        break
                except:
                    pass
                time.sleep(10)

    def configure_floating_ip(self):
        self.add_progress_message("Configuring floating IP.")
        fip_res_id = self.get_fip_reservation()
        floating_ip_obj = next(
            fip for fip in self.neutron_client.list_floatingips()["floatingips"]
            if f"reservation:{fip_res_id}" in fip["tags"]
        )
        # TODO check if ip fixed is to server
        self.floating_ip = floating_ip_obj["floating_ip_address"]
        if floating_ip_obj["fixed_ip_address"]:
            self.add_progress_message("Node already has IP configured.")
            return

        NOVA_API_VERSION = "2.10"
        conn = Connection(
            config=cloud_region.from_session(self.session),
            compute_api_version=NOVA_API_VERSION,
        )
        sdk_server = conn.get_server_by_id(self.server.id)
        conn.add_ip_list(
            sdk_server,
            [self.floating_ip],
        )

        self.add_progress_message("Waiting for TCP.")
        server.wait_for_tcp(self.floating_ip, 22)

    async def _upload_file(self, conn, file_contents, remote_path):
        async with conn.start_sftp_client() as sftp:
            with tempfile.NamedTemporaryFile(delete=True) as temp_file:
                temp_file.write(file_contents.encode("utf-8"))
                temp_file.flush()
                await sftp.put(temp_file.name, remote_path)

    async def install_jupyterhub(self):
        async with asyncssh.connect(
            self.floating_ip, username="cc",
            client_keys=["/keys/id_rsa"], known_hosts=None
        ) as conn:
            self.add_progress_message("Installing Jupyter on node")
            ssh_cmd = "/usr/bin/python3 /usr/local/bin/jupyterhub-singleuser" + " ".join(self.spawner.get_args()) + " --ip 0.0.0.0 --port 8081 --allow-root"
            environment = {k: v for k, v in self.spawner.get_env().items() if k.startswith("JUPYTERHUB_")}
            environment["JUPYTERHUB_ROOT_DIR"] = "/home/cc/work"
            env_file_contents = "\n".join(f'{k}="{v}"' for k, v in environment.items())
            file_contents = f"""
[Unit]
Description=Jupyterhub

[Service]
User=root
Restart=always
StandardOutput=journal
StandardError=journal
EnvironmentFile=/etc/jupyterhub.env
ExecStart={ssh_cmd}

[Install]
WantedBy=multi-user.target
"""

            await conn.run("sudo apt update && sudo apt install -y python3-pip")
            await conn.run("sudo pip install jupyterhub jupyterlab notebook")
            await conn.run("sudo jupyter server extension enable --py jupyterlab")
            await conn.run("mkdir -p /home/cc/work")
            await self._upload_file(conn, file_contents, "jupyterhub.service")
            await self._upload_file(conn, env_file_contents, "jupyterhub.env")
            await conn.run("sudo mv jupyterhub.service /etc/systemd/system/")
            await conn.run("sudo mv jupyterhub.env /etc/")
            await conn.run("sudo systemctl daemon-reload")
            await conn.run("sudo systemctl start jupyterhub.service")
            await conn.run("sudo systemctl enable jupyterhub.service")
            await conn.run("sudo firewall-cmd --zone=public --add-port=8081/tcp")
