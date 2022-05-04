resource "aws_s3_bucket" "ecs_s3_terraform_state" {
  bucket = var.tf_state_bucket_name

  lifecycle {
    prevent_destroy = true
  }
  tags = {
    Role = "S3 Remote Terraform State Store for ECS-based api app"
  }
}

resource "aws_dynamodb_table" "dynamodb_terraform_state_lock" {
  name           = "ecs-tf-remote-state-lock"
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "LockID"
  lifecycle {
    prevent_destroy = true
  }
  attribute {
    name = "LockID"
    type = "S"
  }
  tags = {
    Role = "DynamoDB Table for Terraform State Lock on ECS-based api app infrastructure"
  }
}
