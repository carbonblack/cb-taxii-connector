# This dockerfile creates the cb enterprise build environment
ARG OS_VERSION_CLASSIFIER
ARG ARTIFACTORY_SERVER=artifactory-pub.bit9.local
ARG BASE_IMAGE=${ARTIFACTORY_SERVER}:5000/cb/connector_env_base:${OS_VERSION_CLASSIFIER}-1.0.0

FROM ${BASE_IMAGE}

ARG ARTIFACTORY_SERVER
ENV ARTIFACTORY_SERVER=${ARTIFACTORY_SERVER}

ARG BASE_IMAGE
ENV BASE_IMAGE=${BASE_IMAGE}

RUN python3.8 -m ensurepip
RUN python3.8 -m pip install flask pyopenssl
