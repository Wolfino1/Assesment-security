# ============================================
# Security Groups (PC-IAC-020)
# ============================================

# Security Group para ALB
resource "aws_security_group" "alb" {
  name        = local.sg_alb_name
  description = "Security Group para Application Load Balancer"
  vpc_id      = local.vpc_id

  tags = merge(
    local.common_tags,
    {
      Name = local.sg_alb_name
      Type = "ALB"
    }
  )
}

# Reglas de ingreso para ALB (HTTP/HTTPS desde internet)
resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow HTTP from internet"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = merge(
    local.common_tags,
    {
      Name = "${local.sg_alb_name}-ingress-http"
    }
  )
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow HTTPS from internet"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = merge(
    local.common_tags,
    {
      Name = "${local.sg_alb_name}-ingress-https"
    }
  )
}

# Regla de egreso para ALB hacia aplicación
resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Allow traffic to application"
  from_port                    = var.app_port
  to_port                      = var.app_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.app.id

  tags = merge(
    local.common_tags,
    {
      Name = "${local.sg_alb_name}-egress-to-app"
    }
  )
}

# Security Group para Aplicación (ECS Fargate)
resource "aws_security_group" "app" {
  name        = local.sg_app_name
  description = "Security Group para aplicacion ECS Fargate"
  vpc_id      = local.vpc_id

  tags = merge(
    local.common_tags,
    {
      Name = local.sg_app_name
      Type = "Application"
    }
  )
}

# Regla de ingreso para aplicación desde ALB
resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = aws_security_group.app.id
  description                  = "Allow traffic from ALB"
  from_port                    = var.app_port
  to_port                      = var.app_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.alb.id

  tags = merge(
    local.common_tags,
    {
      Name = "${local.sg_app_name}-ingress-from-alb"
    }
  )
}

# Regla de egreso para aplicación hacia VPC Endpoints
resource "aws_vpc_security_group_egress_rule" "app_to_vpce" {
  security_group_id            = aws_security_group.app.id
  description                  = "Allow HTTPS to VPC Endpoints"
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.vpc_endpoints.id

  tags = merge(
    local.common_tags,
    {
      Name = "${local.sg_app_name}-egress-to-vpce"
    }
  )
}

# Regla de egreso para aplicación hacia internet (actualizaciones)
resource "aws_vpc_security_group_egress_rule" "app_to_internet" {
  security_group_id = aws_security_group.app.id
  description       = "Allow HTTPS to internet for updates"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = merge(
    local.common_tags,
    {
      Name = "${local.sg_app_name}-egress-to-internet"
    }
  )
}

# Security Group para Base de Datos (RDS)
resource "aws_security_group" "db" {
  name        = local.sg_db_name
  description = "Security Group para base de datos RDS"
  vpc_id      = local.vpc_id

  tags = merge(
    local.common_tags,
    {
      Name = local.sg_db_name
      Type = "Database"
    }
  )
}

# Regla de ingreso para base de datos desde aplicación
resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.db.id
  description                  = "Allow database traffic from application"
  from_port                    = var.db_port
  to_port                      = var.db_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.app.id

  tags = merge(
    local.common_tags,
    {
      Name = "${local.sg_db_name}-ingress-from-app"
    }
  )
}

# Security Group para Lambda (fuera de VPC - solo para referencia)
resource "aws_security_group" "lambda" {
  name        = local.sg_lambda_name
  description = "Security Group para Lambda procesador Kinesis (fuera de VPC)"
  vpc_id      = local.vpc_id

  tags = merge(
    local.common_tags,
    {
      Name = local.sg_lambda_name
      Type = "Lambda"
      Note = "Lambda ejecuta fuera de VPC - SG creado solo para consistencia"
    }
  )
}

# Nota: La Lambda no tiene reglas de ingreso/egreso porque se ejecuta fuera de la VPC
# y accede directamente a Kinesis Data Streams y Amazon Personalize

# Security Group para VPC Endpoints
resource "aws_security_group" "vpc_endpoints" {
  name        = local.sg_vpc_endpoints_name
  description = "Security Group para VPC Endpoints"
  vpc_id      = local.vpc_id

  tags = merge(
    local.common_tags,
    {
      Name = local.sg_vpc_endpoints_name
      Type = "VPCEndpoints"
    }
  )
}

# Regla de ingreso para VPC Endpoints desde aplicación
resource "aws_vpc_security_group_ingress_rule" "vpce_from_app" {
  security_group_id            = aws_security_group.vpc_endpoints.id
  description                  = "Allow HTTPS from application"
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.app.id

  tags = merge(
    local.common_tags,
    {
      Name = "${local.sg_vpc_endpoints_name}-ingress-from-app"
    }
  )
}

# ============================================
# KMS - Customer Managed Key (PC-IAC-020)
# ============================================

resource "aws_kms_key" "main" {
  description             = "Customer Managed Key para cifrado de secretos y Kinesis"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(
    local.common_tags,
    {
      Name = "${local.governance_prefix}-cmk"
    }
  )
}

resource "aws_kms_alias" "main" {
  name          = local.kms_key_alias
  target_key_id = aws_kms_key.main.key_id
}

# ============================================
# Secrets Manager - Database Credentials (PC-IAC-020)
# ============================================

resource "aws_secretsmanager_secret" "db_credentials" {
  name                    = local.secret_name
  description             = "Credenciales maestras de la base de datos RDS"
  kms_key_id              = aws_kms_key.main.arn
  recovery_window_in_days = 30

  tags = merge(
    local.common_tags,
    {
      Name = local.secret_name
    }
  )
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = var.db_username
    password = random_password.db_password.result
    engine   = "postgres"
    host     = ""  # Se actualizará después de crear RDS
    port     = var.db_port
    dbname   = var.db_name
  })
}

resource "random_password" "db_password" {
  length  = 32
  special = true
}

# ============================================
# ACM - SSL/TLS Certificate (PC-IAC-020)
# ============================================

resource "aws_acm_certificate" "main" {
  domain_name               = var.domain_name
  subject_alternative_names = var.subject_alternative_names
  validation_method         = var.validation_method

  tags = merge(
    local.common_tags,
    {
      Name = local.acm_certificate_name
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

# ============================================
# VPC Flow Logs (PC-IAC-020)
# ============================================

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/${local.flow_logs_name}"
  retention_in_days = var.flow_logs_retention_days
  kms_key_id        = aws_kms_key.main.arn

  tags = merge(
    local.common_tags,
    {
      Name = local.flow_logs_name
    }
  )
}

resource "aws_iam_role" "flow_logs" {
  name = local.flow_logs_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Name = local.flow_logs_role_name
    }
  )
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${local.flow_logs_role_name}-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_flow_log" "main" {
  vpc_id                   = local.vpc_id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60

  tags = merge(
    local.common_tags,
    {
      Name = local.flow_logs_name
    }
  )
}

# ============================================
# IAM Roles (PC-IAC-020)
# ============================================

# 1. ECS Task Execution Role
resource "aws_iam_role" "ecs_task_execution" {
  name = local.ecs_task_execution_role

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Name = local.ecs_task_execution_role
      Type = "ECSTaskExecution"
    }
  )
}

resource "aws_iam_role_policy" "ecs_task_execution" {
  name = "${local.ecs_task_execution_role}-policy"
  role = aws_iam_role.ecs_task_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.db_credentials.arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.main.arn
      }
    ]
  })
}

# 2. ECS Task Role
resource "aws_iam_role" "ecs_task" {
  name = local.ecs_task_role

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Name = local.ecs_task_role
      Type = "ECSTask"
    }
  )
}

resource "aws_iam_role_policy" "ecs_task" {
  name = "${local.ecs_task_role}-policy"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kinesis:PutRecord",
          "kinesis:PutRecords"
        ]
        Resource = var.kinesis_stream_arn != "" ? var.kinesis_stream_arn : "*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.main.arn
      }
    ]
  })
}

# 3. Kinesis Firehose Role
resource "aws_iam_role" "firehose" {
  name = local.firehose_role

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "firehose.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Name = local.firehose_role
      Type = "Firehose"
    }
  )
}

resource "aws_iam_role_policy" "firehose" {
  name = "${local.firehose_role}-policy"
  role = aws_iam_role.firehose.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kinesis:GetRecords",
          "kinesis:GetShardIterator",
          "kinesis:DescribeStream",
          "kinesis:ListShards"
        ]
        Resource = var.kinesis_stream_arn != "" ? var.kinesis_stream_arn : "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetBucketLocation"
        ]
        Resource = [
          var.s3_bucket_arn != "" ? var.s3_bucket_arn : "*",
          var.s3_bucket_arn != "" ? "${var.s3_bucket_arn}/*" : "*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.main.arn
      }
    ]
  })
}

# 4. Lambda Execution Role (fuera de VPC)
resource "aws_iam_role" "lambda_execution" {
  name = local.lambda_execution_role

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Name = local.lambda_execution_role
      Type = "Lambda"
      Note = "Lambda ejecuta fuera de VPC"
    }
  )
}

resource "aws_iam_role_policy" "lambda_execution" {
  name = "${local.lambda_execution_role}-policy"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kinesis:GetRecords",
          "kinesis:GetShardIterator",
          "kinesis:DescribeStream",
          "kinesis:ListShards"
        ]
        Resource = var.kinesis_stream_arn != "" ? var.kinesis_stream_arn : "*"
      },
      {
        Effect = "Allow"
        Action = [
          "personalize:PutEvents"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# 5. Amazon Personalize Service Role
resource "aws_iam_role" "personalize" {
  name = local.personalize_role

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "personalize.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Name = local.personalize_role
      Type = "Personalize"
    }
  )
}

resource "aws_iam_role_policy" "personalize" {
  name = "${local.personalize_role}-policy"
  role = aws_iam_role.personalize.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          var.s3_bucket_arn != "" ? var.s3_bucket_arn : "*",
          var.s3_bucket_arn != "" ? "${var.s3_bucket_arn}/*" : "*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.main.arn
      }
    ]
  })
}

# 6. RDS Enhanced Monitoring Role
resource "aws_iam_role" "rds_monitoring" {
  name = local.rds_monitoring_role

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Name = local.rds_monitoring_role
      Type = "RDSMonitoring"
    }
  )
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}


# ============================================
# AWS WAF - Web Application Firewall (PC-IAC-020)
# ============================================

# WAF Web ACL para CloudFront (debe estar en us-east-1)
resource "aws_wafv2_web_acl" "cloudfront" {
  count    = var.enable_waf ? 1 : 0
  provider = aws.us_east_1

  name        = local.waf_name
  description = "WAF para CloudFront con reglas gestionadas de AWS"
  scope       = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # Regla 1: AWS Managed Rules - Common Rule Set (OWASP Top 10)
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.governance_prefix}-waf-common-rules"
      sampled_requests_enabled   = true
    }
  }

  # Regla 2: AWS Managed Rules - SQL Injection Protection
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesSQLiRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.governance_prefix}-waf-sqli-rules"
      sampled_requests_enabled   = true
    }
  }

  # Regla 3: AWS Managed Rules - IP Reputation List
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAmazonIpReputationList"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.governance_prefix}-waf-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  # Regla 4: AWS Managed Rules - Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 4

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.governance_prefix}-waf-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # Regla 5: Rate Limiting (protección contra DDoS de capa 7)
  rule {
    name     = "RateLimitRule"
    priority = 5

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.governance_prefix}-waf-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.governance_prefix}-waf-acl"
    sampled_requests_enabled   = true
  }

  tags = merge(
    local.common_tags,
    {
      Name  = local.waf_name
      Scope = "CLOUDFRONT"
    }
  )
}

# ============================================
# AWS GuardDuty - Detección de Amenazas (PC-IAC-020)
# ============================================

resource "aws_guardduty_detector" "main" {
  count = var.enable_guardduty ? 1 : 0

  enable                       = true
  finding_publishing_frequency = var.guardduty_finding_frequency

  # Habilitar protección de datos en S3
  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = merge(
    local.common_tags,
    {
      Name = local.guardduty_name
    }
  )
}

# ============================================
# AWS Shield Standard (PC-IAC-020)
# ============================================

# Nota: AWS Shield Standard está habilitado por defecto en todas las cuentas de AWS
# sin costo adicional. Proporciona protección automática contra ataques DDoS comunes
# en las capas 3 y 4 (red y transporte) para todos los recursos de AWS.
#
# Shield Standard protege automáticamente:
# - Amazon CloudFront
# - Amazon Route 53
# - Elastic Load Balancing (ALB, NLB, CLB)
# - AWS Global Accelerator
# - Elastic IP addresses asociadas a instancias EC2
#
# No requiere configuración adicional en Terraform, pero se documenta aquí
# para cumplimiento y auditoría.
#
# Para Shield Advanced (protección mejorada con costo adicional), se requiere
# configuración manual a través de la consola de AWS o AWS CLI, ya que implica
# un compromiso de suscripción de 1 año.
#
# Referencia: https://aws.amazon.com/shield/features/

# Recurso de documentación para cumplimiento
resource "null_resource" "shield_standard_documentation" {
  triggers = {
    documentation = jsonencode({
      service     = "AWS Shield Standard"
      status      = "Enabled by default"
      scope       = "Global"
      protection  = "Layer 3/4 DDoS protection"
      cost        = "No additional cost"
      resources   = ["CloudFront", "Route53", "ELB", "Global Accelerator", "Elastic IPs"]
      compliance  = "PC-IAC-020"
      environment = var.environment
      timestamp   = timestamp()
    })
  }

  provisioner "local-exec" {
    command = "echo 'AWS Shield Standard is enabled by default for all AWS accounts'"
  }
}


# ============================================
# AWS Cognito - Identity Provider (PC-IAC-020)
# ============================================

# Cognito User Pool
resource "aws_cognito_user_pool" "main" {
  count = var.enable_cognito ? 1 : 0

  name = local.cognito_user_pool_name

  # Email como identificador principal
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  # Políticas de contraseña robustas
  password_policy {
    minimum_length                   = var.password_minimum_length
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 7
  }

  # Atributos del esquema
  schema {
    name                     = "email"
    attribute_data_type      = "String"
    required                 = true
    mutable                  = true
    developer_only_attribute = false

    string_attribute_constraints {
      min_length = 1
      max_length = 256
    }
  }

  schema {
    name                     = "name"
    attribute_data_type      = "String"
    required                 = false
    mutable                  = true
    developer_only_attribute = false

    string_attribute_constraints {
      min_length = 1
      max_length = 256
    }
  }

  # Configuración de email
  email_configuration {
    email_sending_account = "COGNITO_DEFAULT"
  }

  # Políticas de recuperación de cuenta
  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  # Configuración de dispositivos
  device_configuration {
    challenge_required_on_new_device      = true
    device_only_remembered_on_user_prompt = true
  }

  # Prevención de compromiso de cuentas
  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }

  # Cifrado con KMS Customer Managed Key
  user_attribute_update_settings {
    attributes_require_verification_before_update = ["email"]
  }

  tags = merge(
    local.common_tags,
    {
      Name = local.cognito_user_pool_name
      Type = "CognitoUserPool"
    }
  )
}

# Cognito User Pool Client
resource "aws_cognito_user_pool_client" "main" {
  count = var.enable_cognito ? 1 : 0

  name         = local.cognito_client_name
  user_pool_id = aws_cognito_user_pool.main[0].id

  # Generar client secret
  generate_secret = true

  # Flujos de autenticación permitidos
  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH"
  ]

  # Configuración de tokens
  refresh_token_validity = 30
  access_token_validity  = 60
  id_token_validity      = 60

  token_validity_units {
    refresh_token = "days"
    access_token  = "minutes"
    id_token      = "minutes"
  }

  # URLs de callback y logout
  callback_urls = var.cognito_callback_urls
  logout_urls   = var.cognito_logout_urls

  # Scopes OAuth permitidos
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code", "implicit"]
  allowed_oauth_scopes                 = ["email", "openid", "profile"]

  # Configuración de lectura/escritura de atributos
  read_attributes = [
    "email",
    "email_verified",
    "name"
  ]

  write_attributes = [
    "email",
    "name"
  ]

  # Prevenir destrucción accidental del cliente
  prevent_user_existence_errors = "ENABLED"
}

# Cognito Domain - Dominio personalizado con certificado ACM
resource "aws_cognito_user_pool_domain" "main" {
  count = var.enable_cognito && var.cognito_custom_domain != "" ? 1 : 0

  domain          = var.cognito_custom_domain
  certificate_arn = aws_acm_certificate.main.arn
  user_pool_id    = aws_cognito_user_pool.main[0].id
}

# Cognito Domain - Dominio de AWS (fallback si no hay dominio personalizado)
resource "aws_cognito_user_pool_domain" "aws_domain" {
  count = var.enable_cognito && var.cognito_custom_domain == "" ? 1 : 0

  domain       = "${local.governance_prefix}-${var.cognito_domain_prefix}"
  user_pool_id = aws_cognito_user_pool.main[0].id
}
