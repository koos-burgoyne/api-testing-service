resource "aws_iam_policy" "ec2_ecr_policy" {
  description = "Policy to give ecr permission to ec2"
  policy      = file("policies/ecr-policy.json")
}
resource "aws_iam_role" "ec2_ecr_role" {
  assume_role_policy = file("roles/ecr-role.json")
}
resource "aws_iam_role_policy_attachment" "ec2_ecr_role_policy_attachment" {
  role       = aws_iam_role.ec2_ecr_role.name
  policy_arn = aws_iam_policy.ec2_ecr_policy.arn
}
resource "aws_iam_instance_profile" "ec2_ecr_profile" {
  role = aws_iam_role.ec2_ecr_role.name
}

# --- EC2 Instance ---
resource "aws_instance" "app-server" {
  ami                    = "ami-02b05e04df16de7a9"
  instance_type          = "t2.micro"
  key_name               = var.key
  vpc_security_group_ids = [aws_security_group.http-ssh-sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_ecr_profile.name

  user_data = <<EOF
#!/bin/bash
sudo yum update -y
sudo yum install -y unzip

# install and start docker
sudo yum install -y docker
sudo service docker start
# add ec2-user to the docker group so it can run commands without using sudo
sudo usermod -a -G docker ec2-user

# Install aws cli
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# configure aws
aws configure set aws_access_key_id "${var.aws_access_key_id}" && \
aws configure set aws_secret_access_key "${var.aws_secret_access_key}"  && \
aws configure set region "${var.region}"  && \
aws configure set output "json"

# Docker login to aws ecr private repo
aws ecr get-login-password --region ${var.region} | docker login --username AWS --password-stdin ${var.account_id}.dkr.ecr.${var.region}.amazonaws.com

# Pull docker image
docker pull ${var.account_id}.dkr.ecr.${var.region}.amazonaws.com/ecr-app:latest

# Run docker image
docker run -tdp 80:80 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --name app \
  ${var.account_id}.dkr.ecr.${var.region}.amazonaws.com/ecr-app

# Cleanup
rm awscliv2.zip
  EOF
}
