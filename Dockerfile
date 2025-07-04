ARG base_image=jupyterhub/k8s-hub:4.0.0

FROM $base_image AS base

USER root
RUN apt-get update \
    && apt-get remove -yq python3-pycurl \
    && apt-get install -yq --no-install-recommends \
      libmariadb-dev-compat libmariadb-dev \
      libssl-dev \
      libcurl4-openssl-dev \
      gcc \
    && rm -rf /var/lib/apt/lists/*

ENV PYCURL_SSL_LIBRARY=openssl

WORKDIR /srv/jupyterhub

FROM base AS release

## Install jupyterhub-chameleon extension
COPY ./requirements.txt /srv/jupyterhub/requirements.txt
RUN python3 -m pip install -r /srv/jupyterhub/requirements.txt

FROM base AS dev

RUN apt-get update \
    && apt-get install -yq --no-install-recommends \
    build-essential


# Install the dev extension
COPY . /ext
RUN pip install /ext
