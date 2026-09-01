resource "aws_security_group" "cluster" {
  name        = "${local.name_prefix}-cluster"
  description = "EKS control plane and node security group boundary."
  vpc_id      = var.vpc_id

  egress {
    description = "Allow outbound dependency traffic."
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "data" {
  name        = "${local.name_prefix}-data"
  description = "Data tier access from EKS nodes only."
  vpc_id      = var.vpc_id

  ingress {
    description     = "PostgreSQL from EKS nodes."
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.cluster.id]
  }

  ingress {
    description     = "Redis from EKS nodes."
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.cluster.id]
  }

  egress {
    description = "Allow data tier egress for AWS-managed maintenance."
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ingress" {
  name        = "${local.name_prefix}-ingress"
  description = "Public ingress boundary for web and API load balancers."
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS ingress."
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_ingress_cidrs
  }

  egress {
    description = "Forward ingress traffic to services."
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
