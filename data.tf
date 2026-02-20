# ============================================
# Data Sources
# ============================================

# Obtener VPC por tags de gobernanza
data "aws_vpc" "main" {
  tags = {
    Client      = var.client
    Project     = var.project
    Environment = var.environment
  }
}

# Obtener subnets privadas por tags
data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.main.id]
  }

  tags = {
    Client      = var.client
    Project     = var.project
    Environment = var.environment
    Type        = "Private"  # Asumiendo que el módulo de networking tagea las subnets privadas con Type=Private
  }
}
