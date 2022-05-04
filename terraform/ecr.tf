resource "aws_ecr_repository" "ecr-app" {
  name                 = "ecr-app"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Role = "For storing the ECS-based web app"
  }
}

resource "aws_ecr_repository" "client-images" {
  name                 = "client-images"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Role = "For storing client docker images"
  }
}