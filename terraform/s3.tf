resource "aws_s3_bucket" "ecs-tf-config-files" {
  bucket = "ecs-tf-config-files"

  tags = {
    Role = "Used for the transition to ECS Fargate"
  }
}

resource "aws_s3_bucket" "client-dockerfiles" {
  bucket = "client-dockerfiles"

  tags = {
    Role = "Used to store client dockerfiles"
  }
}
