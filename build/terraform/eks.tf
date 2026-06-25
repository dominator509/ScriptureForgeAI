resource "aws_eks_cluster" "platform" {
  name     = "${local.name_prefix}-cluster"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.30"

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    security_group_ids      = [aws_security_group.cluster.id]
    endpoint_private_access = true
    endpoint_public_access  = false
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster
  ]
}

resource "aws_eks_node_group" "system" {
  cluster_name    = aws_eks_cluster.platform.name
  node_group_name = "${local.name_prefix}-system"
  node_role_arn   = aws_iam_role.eks_nodes.arn
  subnet_ids      = var.private_subnet_ids

  scaling_config {
    desired_size = 2
    min_size     = 2
    max_size     = 6
  }

  update_config {
    max_unavailable = 1
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_worker_node,
    aws_iam_role_policy_attachment.eks_cni,
    aws_iam_role_policy_attachment.ecr_readonly
  ]
}

data "aws_eks_cluster_auth" "platform" {
  name = aws_eks_cluster.platform.name
}
