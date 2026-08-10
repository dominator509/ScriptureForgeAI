data "aws_iam_policy_document" "eks_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

data "aws_iam_policy_document" "node_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

locals {
  eks_oidc_issuer_hostpath = replace(aws_eks_cluster.platform.identity[0].oidc[0].issuer, "https://", "")
}

resource "aws_iam_openid_connect_provider" "eks" {
  url             = aws_eks_cluster.platform.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = var.eks_oidc_thumbprint_list
}

data "aws_iam_policy_document" "app_secrets_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
    }

    actions = ["sts:AssumeRoleWithWebIdentity"]

    condition {
      test     = "StringEquals"
      variable = "${local.eks_oidc_issuer_hostpath}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.eks_oidc_issuer_hostpath}:sub"
      values   = ["system:serviceaccount:scriptureforge-${var.environment}:scriptureforge-workload"]
    }
  }
}

data "aws_iam_policy_document" "app_secrets_read" {
  statement {
    effect = "Allow"

    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue"
    ]

    resources = [
      data.aws_secretsmanager_secret.database_url.arn,
      data.aws_secretsmanager_secret.jwt_secret_key.arn,
      data.aws_secretsmanager_secret.journal_salt_secret.arn,
      data.aws_secretsmanager_secret.openai_api_key.arn,
      data.aws_secretsmanager_secret.zoom_credentials.arn,
      data.aws_secretsmanager_secret.grpc_engine_shared_secret.arn,
      data.aws_secretsmanager_secret.grpc_engine_tls_credentials.arn
    ]
  }
}

resource "aws_iam_role" "eks_cluster" {
  name               = "${local.name_prefix}-eks-cluster"
  assume_role_policy = data.aws_iam_policy_document.eks_assume_role.json
}

resource "aws_iam_role_policy_attachment" "eks_cluster" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role" "eks_nodes" {
  name               = "${local.name_prefix}-eks-nodes"
  assume_role_policy = data.aws_iam_policy_document.node_assume_role.json
}

resource "aws_iam_role_policy_attachment" "eks_worker_node" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_cni" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "ecr_readonly" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role" "app_secrets" {
  name               = "${local.name_prefix}-app-secrets"
  assume_role_policy = data.aws_iam_policy_document.app_secrets_assume_role.json
}

resource "aws_iam_policy" "app_secrets_read" {
  name   = "${local.name_prefix}-app-secrets-read"
  policy = data.aws_iam_policy_document.app_secrets_read.json
}

resource "aws_iam_role_policy_attachment" "app_secrets_read" {
  role       = aws_iam_role.app_secrets.name
  policy_arn = aws_iam_policy.app_secrets_read.arn
}
