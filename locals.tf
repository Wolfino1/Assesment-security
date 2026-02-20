# ============================================
# Locals - Nomenclatura y Tags (PC-IAC-003, PC-IAC-004)
# ============================================

locals {
  # Prefijo de gobernanza (PC-IAC-003)
  governance_prefix = "${var.client}-${var.project}-${var.environment}"
  
  # Valores de red: usar variables si se proporcionan, sino usar data sources
  vpc_id             = var.vpc_id != "" ? var.vpc_id : data.aws_vpc.main.id
  vpc_cidr           = var.vpc_cidr != "" ? var.vpc_cidr : data.aws_vpc.main.cidr_block
  private_subnet_ids = length(var.private_subnet_ids) > 0 ? var.private_subnet_ids : data.aws_subnets.private.ids
  
  # Tags comunes obligatorios (PC-IAC-004)
  common_tags = merge(
    {
      Client      = var.client
      Project     = var.project
      Environment = var.environment
      Region      = var.region
      ManagedBy   = "Terraform"
      Module      = "security"
    },
    var.additional_tags
  )
  
  # Nombres de recursos con prefijo de gobernanza
  sg_alb_name              = "${local.governance_prefix}-sg-alb"
  sg_app_name              = "${local.governance_prefix}-sg-app"
  sg_db_name               = "${local.governance_prefix}-sg-db"
  sg_lambda_name           = "${local.governance_prefix}-sg-lambda"
  sg_vpc_endpoints_name    = "${local.governance_prefix}-sg-vpce"
  
  kms_key_alias            = "alias/${local.governance_prefix}-cmk"
  secret_name              = "${local.governance_prefix}-db-credentials"
  
  acm_certificate_name     = "${local.governance_prefix}-cert"
  
  flow_logs_name           = "${local.governance_prefix}-vpc-flow-logs"
  flow_logs_role_name      = "${local.governance_prefix}-role-flow-logs"
  
  ecs_task_execution_role  = "${local.governance_prefix}-role-ecs-task-execution"
  ecs_task_role            = "${local.governance_prefix}-role-ecs-task"
  firehose_role            = "${local.governance_prefix}-role-firehose"
  lambda_execution_role    = "${local.governance_prefix}-role-lambda-execution"
  personalize_role         = "${local.governance_prefix}-role-personalize"
  rds_monitoring_role      = "${local.governance_prefix}-role-rds-monitoring"
  
  waf_name                 = "${local.governance_prefix}-waf-cloudfront"
  guardduty_name           = "${local.governance_prefix}-guardduty-detector"
}
