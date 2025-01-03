ARG AIRFLOW_VERSION="2.10.4"
ARG PYTHON_VERSION="3.11"
ARG AIRFLOW_IMAGE="apache/airflow:slim-${AIRFLOW_VERSION}-python${PYTHON_VERSION}"

FROM ${AIRFLOW_IMAGE}

USER root

RUN apt-get update \
    && ACCEPT_EULA=Y apt-get upgrade -y \
    && ACCEPT_EULA=Y apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY web /tmp/web
RUN chown -R airflow: /tmp/web

USER airflow

RUN git config --global --add safe.directory '*'

RUN mkdir -p /home/airflow/repositories

COPY scheduler/requirements.txt /

RUN python3 -m pip install --upgrade pip
RUN pip install --no-cache-dir -r /requirements.txt

RUN pip install --upgrade pip setuptools wheel
WORKDIR /tmp/web
RUN python setup.py bdist_wheel
RUN pip install dist/advancedcve-0.0.1-py3-none-any.whl