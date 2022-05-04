terraform {
  backend "s3" {
    bucket         = var.backend_bucket_name
    key            = "terraform.tfstate"
    region         = var.region
    dynamodb_table = aws_dynamodb_table.dynamodb_terraform_state_lock
  }
}
