# ============================================
# Variables de Gobernanza (PC-IAC-002)
# ============================================

client      = "pragma"
project     = "Assesment"
environment = "dev"
region      = "us-east-1"

# ============================================
# Variables de Red (OPCIONALES - se obtienen automáticamente por tags)
# ============================================

# Si no se proporcionan, el módulo buscará automáticamente la VPC y subnets
# que coincidan con los tags de gobernanza (client, project, environment)

# vpc_id             = "vpc-xxxxxxxxxxxxxxxxx"
# vpc_cidr           = "10.0.0.0/16"
# private_subnet_ids = [
#   "subnet-xxxxxxxxxxxxxxxxx",
#   "subnet-yyyyyyyyyyyyyyyyy"
# ]

# Nota: Si prefieres especificar manualmente los valores, descomenta las líneas anteriores
# y proporciona los IDs correctos del módulo de networking

# ============================================
# Configuración de Security Groups
# ============================================

alb_port = 80
app_port = 8080
db_port  = 5432

# ============================================
# Configuración de Secrets Manager
# ============================================

db_username = "dbadmin"
db_name     = "myappdb"

# ============================================
# Configuración de ACM
# ============================================

domain_name               = "myapp.example.com"
subject_alternative_names = ["*.myapp.example.com", "www.myapp.example.com"]
validation_method         = "DNS"

# ============================================
# Configuración de VPC Flow Logs
# ============================================

flow_logs_retention_days = 7

# ============================================
# ARNs de Recursos Externos (Opcionales)
# ============================================

# Descomentar y configurar cuando estén disponibles
# ecr_repository_arns = [
#   "arn:aws:ecr:us-east-1:123456789012:repository/myapp"
# ]

kinesis_stream_arn = ""
s3_bucket_arn      = ""
# personalize_dataset_group_arn = ""
# lambda_function_name = ""

# ============================================
# Configuración de WAF
# ============================================

enable_waf      = true
waf_rate_limit  = 2000  # Requests por IP en 5 minutos

# ============================================
# Configuración de GuardDuty
# ============================================

enable_guardduty            = true
guardduty_finding_frequency = "FIFTEEN_MINUTES"  # FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS

# ============================================
# Tags Adicionales (PC-IAC-004)
# ============================================

additional_tags = {
  Owner      = "santiago.guerrero"
  CostCenter = "00000"
  Purpose    = "Security Infrastructure"
}
