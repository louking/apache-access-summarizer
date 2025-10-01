# need default - see https://docs.docker.com/reference/build-checks/invalid-default-arg-in-from/
ARG PYTHON_VER=3.13

# For more information, please refer to https://aka.ms/vscode-docker-python
FROM python:${PYTHON_VER}-alpine

# Keeps Python from generating .pyc files in the container
ENV PYTHONDONTWRITEBYTECODE=1

# Turns off buffering for easier container logging
ENV PYTHONUNBUFFERED=1

# set the working directory in the container
WORKDIR /app

# Install pip requirements
COPY requirements.txt .
RUN python -m pip install -r requirements.txt

# we're going to want to use bash
RUN apk add bash

# use msmtp for sendmail, need volume with /etc/msmtprc defined
RUN apk add --no-cache msmtp && rm /usr/sbin/sendmail && ln -s /usr/bin/msmtp /usr/sbin/sendmail

# allow timezone setting
RUN apk add --no-cache tzdata

# set up cron jobs
COPY cronjobs /etc/crontabs/root

# copy the content of the local src directory to the working directory
# this isn't needed when developing as there's a bind under volumes: in the docker-compose.dev.yml file
COPY src /app

# # Creates a non-root user with an explicit UID and adds permission to access the /app folder
# # For more info, please refer to https://aka.ms/vscode-docker-python-configure-containers
# RUN adduser -u 5678 --disabled-password --gecos "" appuser && chown -R appuser /app
# USER appuser

# # During debugging, this entry point will be overridden. For more information, please refer to https://aka.ms/vscode-docker-python-debug
# CMD ["python", "-m", "apache_access_summarizer"]
