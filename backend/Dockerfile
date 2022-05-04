# Dockerfile
## Usage: The web app only runs in this configuration with the inclusion of AWS credentials 
##        These are passed into the build through github secrets in github actions
##        To run locally:
##            docker build -t <image tag> --build-arg ACCESS_KEY=<access key> --build-arg SECRET_KEY=<secret access key> .
##            docker run -v /var/run/docker.sock:/var/run/docker.sock --name <container name> -tdp 80:8000 <image tag>
##        Access app on localhost in web browser
##        To ssh in:
##            docker exec -it <container name> /bin/bash

## The volume flag -v makes it possible to run docker commands from inside the docker container. This is not recommended:
##       https://stackoverflow.com/questions/27879713/is-it-ok-to-run-docker-from-inside-docker
## However in this case, we are using the docker daemon of a controlled EC2 instance to build dockerfile images that are 
## managed in the ECS, so it is permissible here.

# base image
FROM alpine:3.14

# Install dependencies
## Python and Pip
RUN apk add --update python3
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools

# set work directory
WORKDIR /api

# Get build args
ARG ACCESS_KEY
ARG SECRET_KEY
ARG ACCOUNT_ID
ARG AWS_REGION
ARG AUTH_URL
# Store build args in env variables
ENV access_key $ACCESS_KEY
ENV secret_key $SECRET_KEY
ENV account_id $ACCOUNT_ID
ENV aws_region $AWS_REGION
ENV auth_url $AUTH_URL

ENV PYTHONUNBUFFERED 1

# expose port
EXPOSE 80

# copy project
COPY /api .

# copy requirements file
COPY requirements.txt .
# install dependencies
RUN pip install -r requirements.txt

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]
