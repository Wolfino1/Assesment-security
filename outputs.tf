# ============================================
# Security Groups Outputs
# ============================================

output "vpc_id" {
  description = "ID de la VPC utilizada"
  value       = local.vpc_id
}

output "vpc_cidr" {
  description = "CIDR block de la VPC utilizada"
  value       = local.vpc_cidr
}

output "private_subnet_ids" {
  description = "IDs de las subnets privadas utilizadas"
  value       = local.private_subnet_ids
}

output "sg_alb_id" {
  description = "ID del Security Group del ALB"
  value       = aws_security_group.alb.id
}

output "sg_app_id" {
  description = "ID del Security Group de la aplicación"
  value       = aws_security_group.app.id
}

output "sg_db_id" {
  description = "ID del Security Group de la base de datos"
  value       = aws_security_group.db.id
}

output "sg_lambda_id" {
  description = "ID del Security Group de Lambda"
  value       = aws_security_group.lambda.id
}

output "sg_vpc_endpoints_id" {
  description = "ID del Security Group de VPC Endpoints"
  value       = aws_security_group.vpc_endpoints.id
}

# ============================================
# KMS Outputs
# ============================================

output "kms_key_id" {
  description = "ID de la llave KMS"
  value       = aws_kms_key.main.key_id
}

output "kms_key_arn" {
  description = "ARN de la llave KMS"
  value       = aws_kms_key.main.arn
}

output "kms_key_alias" {
  description = "Alias de la llave KMS"
  value       = aws_kms_alias.main.name
}

# ============================================
# Secrets Manager Outputs
# ============================================

output "db_secret_arn" {
  description = "ARN del secreto de credenciales de base de datos"
  value       = aws_secretsmanager_secret.db_credentials.arn
}

output "db_secret_name" {
  description = "Nombre del secreto de credenciales de base de datos"
  value       = aws_secretsmanager_secret.db_credentials.name
}

# ============================================
# ACM Outputs
# ============================================

output "acm_certificate_arn" {
  description = "ARN del certificado ACM"
  value       = aws_acm_certificate.main.arn
}

output "acm_certificate_domain" {
  description = "Dominio del certificado ACM"
  value       = aws_acm_certificate.main.domain_name
}

output "acm_certificate_status" {
  description = "Estado del certificado ACM"
  value       = aws_acm_certificate.main.status
}

# ============================================
# VPC Flow Logs Outputs
# ============================================

output "flow_logs_id" {
  description = "ID de VPC Flow Logs"
  value       = aws_flow_log.main.id
}

output "flow_logs_log_group_name" {
  description = "Nombre del CloudWatch Log Group para Flow Logs"
  value       = aws_cloudwatch_log_group.flow_logs.name
}

output "flow_logs_role_arn" {
  description = "ARN del rol IAM para Flow Logs"
  value       = aws_iam_role.flow_logs.arn
}

# ============================================
# IAM Roles Outputs
# ============================================

output "ecs_task_execution_role_arn" {
  description = "ARN del rol de ejecución de tareas ECS"
  value       = aws_iam_role.ecs_task_execution.arn
}

output "ecs_task_execution_role_name" {
  description = "Nombre del rol de ejecución de tareas ECS"
  value       = aws_iam_role.ecs_task_execution.name
}

output "ecs_task_role_arn" {
  description = "ARN del rol de tareas ECS"
  value       = aws_iam_role.ecs_task.arn
}

output "ecs_task_role_name" {
  description = "Nombre del rol de tareas ECS"
  value       = aws_iam_role.ecs_task.name
}

output "firehose_role_arn" {
  description = "ARN del rol de Kinesis Firehose"
  value       = aws_iam_role.firehose.arn
}

output "firehose_role_name" {
  description = "Nombre del rol de Kinesis Firehose"
  value       = aws_iam_role.firehose.name
}

output "lambda_execution_role_arn" {
  description = "ARN del rol de ejecución de Lambda"
  value       = aws_iam_role.lambda_execution.arn
}

output "lambda_execution_role_name" {
  description = "Nombre del rol de ejecución de Lambda"
  value       = aws_iam_role.lambda_execution.name
}

output "personalize_role_arn" {
  description = "ARN del rol de Amazon Personalize"
  value       = aws_iam_role.personalize.arn
}

output "personalize_role_name" {
  description = "Nombre del rol de Amazon Personalize"
  value       = aws_iam_role.personalize.name
}

output "rds_monitoring_role_arn" {
  description = "ARN del rol de monitoreo de RDS"
  value       = aws_iam_role.rds_monitoring.arn
}

output "rds_monitoring_role_name" {
  description = "Nombre del rol de monitoreo de RDS"
  value       = aws_iam_role.rds_monitoring.name
}

# ============================================
# Summary Output
# ============================================

output "security_summary" {
  description = "Resumen de la infraestructura de seguridad creada"
  value = {
    security_groups = {
      alb            = aws_security_group.alb.id
      app            = aws_security_group.app.id
      db             = aws_security_group.db.id
      lambda         = aws_security_group.lambda.id
      vpc_endpoints  = aws_security_group.vpc_endpoints.id
    }
    encryption = {
      kms_key_id    = aws_kms_key.main.key_id
      kms_key_arn   = aws_kms_key.main.arn
      kms_alias     = aws_kms_alias.main.name
    }
    secrets = {
      db_secret_arn  = aws_secretsmanager_secret.db_credentials.arn
      db_secret_name = aws_secretsmanager_secret.db_credentials.name
    }
    certificates = {
      acm_arn    = aws_acm_certificate.main.arn
      domain     = aws_acm_certificate.main.domain_name
      status     = aws_acm_certificate.main.status
    }
    observability = {
      flow_logs_id        = aws_flow_log.main.id
      log_group_name      = aws_cloudwatch_log_group.flow_logs.name
    }
    iam_roles = {
      ecs_task_execution = aws_iam_role.ecs_task_execution.arn
      ecs_task           = aws_iam_role.ecs_task.arn
      firehose           = aws_iam_role.firehose.arn
      lambda_execution   = aws_iam_role.lambda_execution.arn
      personalize        = aws_iam_role.personalize.arn
      rds_monitoring     = aws_iam_role.rds_monitoring.arn
    }
  }
}
