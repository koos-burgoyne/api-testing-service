"""
This file launches a FastAPI API which allows a user to upload, prepare, launch,
 stop, and delete a custom container.

endpoints:
    "/": Index endpoint
    "/upload": Upload a Dockerfile
    "/prep/{name}": Prepare an image from the uploaded Dockerfile
    "/launch/{name}": Launch a container on ECS using Fargate serverless computing
    "/ip/{img_id}": Get the public IP address of a running container
    "/stop/{name}": Stop a running container
    "/start/{name}": Start a stopped container
    "/delete/{name}": Remove all resources associated with an uploaded Dockerfile
"""
# Core Imports
import os
import base64
from uuid import uuid4

# External Imports
import boto3
import docker
import requests
from fastapi import FastAPI, UploadFile


# Retrieve AWS resource credentials from environmental variables
access_key = os.getenv('access_key')
secret_key = os.getenv('secret_key')
account_id = os.getenv('aws_acc_id')
aws_region = os.getenv('aws_region')
auth_url   = os.getenv('auth_url')

# Create the FastAPI App
app = FastAPI()

# Create a S3 resource and client to access our project's buckets
s3_client = boto3.client('s3', region_name=aws_region, aws_access_key_id=access_key, aws_secret_access_key=secret_key)

# Contact the authentication API via static load balancer
auth_url = f"http://{auth_url}.{aws_region}.elb.amazonaws.com:5555/authenticate_no_form/"

# Create AWS ECR client and get credentials
ecr_client = boto3.client('ecr', region_name=aws_region, aws_access_key_id=access_key, aws_secret_access_key=secret_key)
ecr_credentials = ecr_client.get_authorization_token()['authorizationData'][0]
ecr_username = 'AWS'
ecr_password = base64.b64decode(ecr_credentials['authorizationToken']).replace(b'AWS:', b'').decode('utf-8')
ecr_url = ecr_credentials['proxyEndpoint']
ecr_repo = '{}'.format(ecr_url.replace('https://', ''), "")

# Run Docker AWS ECR login procedure
os.system(f"aws ecr get-login-password --region {aws_region} | docker login --username AWS --password-stdin {account_id}.dkr.ecr.{aws_region}.amazonaws.com")
# Create Docker client
docker_client = docker.from_env()
docker_client.login(username=ecr_username, password=ecr_password, registry=ecr_url)

# Create AWS ECS client
ecs_client = boto3.client('ecs', region_name=aws_region, aws_access_key_id=access_key, aws_secret_access_key=secret_key)


# Function to authenticate a client, requires username and password as string args
def auth(username: str, password: str):
    headers = {
        'accept': 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
    }
    params = {
        'username': username,
        'password': password,
    }
    response = requests.post(auth_url, headers=headers, params=params)
    return response.json()


@app.get("/")
async def index():
  """
  Index function to display a message when you hit our service.

  Returns:
    str: Index response message with direction to /docs
  """
  return "Welcome to your End-Point testing Web-API. Please see /docs for more information and usage."


@app.post("/upload")
async def upload_file(file: UploadFile, username: str, password: str):
  """
  Uploads a Dockerfile to S3.

  Args:
    file: Dockerfile to upload to S3

  Returns:
    str: Name of the file. Name is used to interact with instances
    :param file:
    :param password:
    :param username:
  """
  if str((auth(username, password))) == "True":
    # Generate a unique ID for the file
    img_id = uuid4().hex
    
    # Upload the Dockerfile to S3
    s3_client.upload_fileobj(file.file, "client-dockerfiles", f"{img_id}")

    return {f"Sucess! Dockerfile ID":img_id}

  else:
    return "Invalid Credentials"


@app.post("/prep/{img_id}/{img_name}")
async def prepare_instance(img_id: str, username: str, password: str):
  """
  Builds a Docker image from an uploaded Dockerfile.
  Process:
    Download Dockerfile from S3.
    Build image on local host.
    Push image to AWS ECR.

  Args:
    img_id (str): Name of the image file hosted on S3 (i.e. the .tar file).

  Returns:
    str: Job success or failure
    :param img_id:
    :param password:
    :param username:

  """
  if str((auth(username, password))) == "True":

    path = str(img_id)
    if not os.path.exists(path):
      os.makedirs(path)

    s3_client.download_file("client-dockerfiles", str(img_id), path+"/Dockerfile")

    image,logs = docker_client.images.build(path=str(img_id), tag=str(img_id))

    ecr_repo_name = '{}/{}:{}'.format(ecr_url.replace('https://', ''), "client-images", str(img_id))

    print(ecr_repo_name)
    image.tag(ecr_repo_name, tag=str(img_id))

    push_log = docker_client.images.push(ecr_repo_name, tag=str(img_id))
    
    # TODO: check push log for errors
    print(push_log)

    return {f"Image Build Successful for Instance with ID":img_id}

  else:
    return "Invalid Credentials"

import json
@app.post("/launch/{img_id}")
async def launch_instance(img_id: str, username: str, password: str):
  """
  Launches the specified Docker image on AWS ECS with Fargate. 
  Process:
    Use existing security group and IAM task execution role.
    Create new task definition.
    Create new service with single instance of task definition.

  Args:
    img_id (str): Unique ID of the image hosted on the Elastic Container Repository.

  Returns:
    str: Job success with Task Resource Number or Job failure
    
    :param img_id:
    :param password:
    :param username:
  """
  if str((auth(username, password))) == "True":
    
    task_def_response = ecs_client.register_task_definition(
        family                  = f"image-{img_id}",
        networkMode             = "awsvpc",
        requiresCompatibilities = ["FARGATE"],
        cpu                     = "256",
        memory                  = "512",
        executionRoleArn        = f"arn:aws:iam::{account_id}:role/ecsTaskExecutionRole",
        containerDefinitions    =[
          {
            "name"        : img_id,
            "image"       : f"{account_id}.dkr.ecr.{aws_region}.amazonaws.com/client-images:{img_id}",
            "portMappings": [
              {
                "hostPort"     : 80,
                "containerPort": 80,
                "protocol"     : "tcp",
              }
            ]
          }
        ],
    )
    # print(json.dumps(task_def_response, indent=4, default=str))
    if task_def_response["ResponseMetadata"]["HTTPStatusCode"] != 200:
      return {
        "Failed to create task definition": task_run_response["ResponseMetadata"]["HTTPStatusCode"],
        "Failures": task_run_response["failures"]
      }
    
    task_run_response = ecs_client.run_task(
      taskDefinition  = f"image-{img_id}",
      launchType      = 'FARGATE',
      cluster         = 'app',
      platformVersion = 'LATEST',
      count           = 1,
      networkConfiguration ={
        'awsvpcConfiguration': {
            'subnets': ["<INSERT YOUR SUBNET HERE>"],
            'assignPublicIp': 'ENABLED',
            'securityGroups': ["<INSERT YOUR SG HERE>"]
        }
      }
    )
    # print(json.dumps(task_run_response, indent=4, default=str))
    if task_run_response["ResponseMetadata"]["HTTPStatusCode"] != 200:
      return {
        "Failed to run task": task_run_response["ResponseMetadata"]["HTTPStatusCode"],
        "Failures": task_run_response["failures"]
      }
    taskArn = task_run_response["tasks"][0]["taskArn"].split("/")[2]

    # Success
    return {
      f"Started with Task Resource Number: {taskArn}",
    }

  else:
    return "Invalid Credentials"


@app.get("/ip/{task_rn}")
async def get_ip(task_rn: str, username: str, password: str):
  """
  Returns the ip address of a running container

  Args:
    task_rn (str): Unique ID of the container running on ECS - same as ID of image hosted on ECR.

  Returns:
    str: IP address of the container
    :param task_rn:
    :param password:
    :param username:
  """
  if str((auth(username, password))) == "True":
    private_ip = ecs_client.describe_tasks(
      cluster = "app", 
      tasks   = [f"arn:aws:ecs:{aws_region}:{account_id}:task/app/"+task_rn]
    )["tasks"][0]["containers"][0]["networkInterfaces"][0]["privateIpv4Address"]

    ec2 = boto3.client('ec2', region_name=aws_region, aws_access_key_id=access_key, aws_secret_access_key=secret_key)
    response = ec2.describe_network_interfaces(
        Filters=[
          {
            "Name": "private-ip-address",
            "Values": [str(private_ip)]
          }
        ]
    )
    
    ip = response["NetworkInterfaces"][0]["Association"]["PublicIp"]
    # Success
    return {f"Public IPv4 for resource number [{task_rn}]: {ip}"}

  else:
    return "Invalid Credentials"


@app.post("/stop/{task_rn}")
async def stop_instance(task_rn: str, username: str, password: str):
  """
  Stops a task that is running on the ECS.
  Update ECS service definition associated with specific container.

  Args:
    task_rn (str): Unique ID of the container running on ECS - same as ID of image hosted on ECR.

  Returns:
    str: Job success or failure
    :param task_rn:
    :param password:
    :param username:

  """
  if str((auth(username, password))) == "True":
    task_found = False
    tasks = ecs_client.list_tasks(cluster="app")["taskArns"]
    for taskARN in tasks:
      if taskARN.split("/")[2] == task_rn:
        task_found = True
        response = ecs_client.stop_task(cluster="app", task=taskARN)
        # print(json.dumps(response, indent=4, default=str))
        if response["task"]["desiredStatus"] != "STOPPED":
          return {f"Did not stop task with ID: {task_rn}"}    

    if not task_found:
      return {f"Failed to find task with ID: {task_rn}"}

    # Success
    return {f"Stopped Instance with ID: {task_rn}"}

  else:
    return "Invalid Credentials"


@app.post("/delete/{img_id}")
async def delete_instance(img_id: str, username: str, password: str):
  """
  Removes all hosted resources associated with a client's docker image.
  Process:
    Update ECS service definition associated with specific container to 0 instsances.
    Delete service.
    Delete task definition.
    Delete ECR image.
    Delete S3 Dockerfile.

  Args:
    img_id (str): Unique ID of the container running on ECS - same as ID of image hosted on ECR.

  Returns:
    str: Job success or failure
    :param img_id:
    :param username:
    :param password:

  """
  if str((auth(username, password))) == "True":
    
    # delete ecr image associated with img_id
    delete_response = ecr_client.batch_delete_image(
      repositoryName = "client-images",
      imageIds = [
        {
          "imageTag": img_id
        }
      ]
    )
    # print(json.dumps(delete_response, indent=2))
    if len(delete_response["failures"]) != 0:
      return {"Failed to delete image": delete_response["failures"]}
    
    # delete dockerfile associated with img_id in s3 bucket client-dockerfiles
    delete_response = s3_client.delete_object(Bucket="client-dockerfiles", Key=img_id)
    if len(delete_response["failures"]) != 0:
      return {"Failed to delete dockerfile": delete_response["failures"]}

    # Success
    return {f"Deleted Instance with ID: {img_id}"}

  else:
    return "Invalid Credentials"
