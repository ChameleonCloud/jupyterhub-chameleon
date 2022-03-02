import logging
import os
from urllib.parse import urljoin

import requests
from tornado.web import HTTPError

LOG = logging.getLogger(__name__)

def exchange_token(access_token):
    # Exchange the user's keystone token for a Trovi token
    token_resp = requests.post(
        urljoin(os.getenv("TROVI_URL"), "/token/"),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        json={
            "grant_type": "token_exchange",
            "subject_token": access_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "scope": "artifacts:read artifacts:write",
        },
    )
    LOG.debug(f"Trovi token exchange response: {token_resp}")

    if token_resp.status_code in (
            requests.codes.unauthorized,
            requests.codes.forbidden,
    ):
        LOG.error(f"Authentication to trovi failed: {token_resp}")
        raise HTTPError(
            requests.codes.unauthorized,
            "You are not authorized to upload artifacts to Trovi via Jupyter.",
        )
    elif token_resp.status_code != requests.codes.created:
        LOG.error(f"Authentication to trovi failed: {token_resp}")
        raise HTTPError(
            requests.codes.internal_server_error,
            requests.codes.internal_server_error,
            "Unknown error uploading artifact to Trovi.",
        )

    return token_resp.json()

def fetch_artifact(artifact_id, trovi_token):
    artifact_req = requests.PreparedRequest()
    artifact_req.prepare_url(
        urljoin(os.getenv("TROVI_URL"), f"/artifacts/{artifact_id}"),
        {"access_token": trovi_token["access_token"]},
    )
    artifact_resp = requests.get(
        artifact_req.url, headers={"accept": "application/json"}
    )

    if artifact_resp.status_code != requests.codes.ok:
        raise HTTPError(
            requests.codes.internal_server_error,
            "Error fetching artifact.",
        )

    return artifact_resp.json()

def fetch_contents_url(contents_urn, trovi_token):
    contents_req = requests.PreparedRequest()
    contents_req.prepare_url(
        urljoin(os.getenv("TROVI_URL"), f"/contents/{contents_urn}"),
        {"access_token": trovi_token},
    )
    contents_resp = requests.get(
        contents_req.url, {"accept": "application/json"}
    )
    if not contents_resp.ok:
        raise HTTPError(
            requests.codes.internal_server_error,
            "Error fetching artifact contents.",
        )
    contents_data = contents_resp.json()
    contents_protocol = contents_data["access_methods"][0]["protocol"]
    if contents_protocol == "http":
        return contents_data["url"]
    elif contents_protocol == "git":
        return contents_data["remote"]
    else:
        raise HTTPError(
            requests.codes.unsupported_media_type, "Unsupported contents type"
        )

