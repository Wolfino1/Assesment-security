# ============================================
# Variables de Gobernanza (PC-IAC-002)
# ============================================

variable "client" {
  description = "Nombre del cliente (máx 10 caracteres)"
  type        = string
  validation {
    condition     = length(var.client) <= 10
    error_message = "El nombre del cliente no puede exceder 10 caracteres."
  }
}

variable "project" {
  description = "Nombre del proyecto (máx 15 caracteres)"
  type        = string
  validation {
    condition     = length(var.project) <= 15
    error_message = "El nombre del proyecto no puede exceder 15 caracteres."
  }
}

variable "environment" {
  description = "Ambiente de despliegue (dev, qa, pdn)"
  type        = string
  validation {
    condition     = contains(["dev", "qa", "pdn"], var.environment)
    error_message = "El ambiente debe ser dev, qa o pdn."
  }
}

variable "region" {
  description = "Región de AWS"
  type        = string
  default     = "us-east-1"
}

# ============================================
# Variables de Red (desde módulo networking)
# ============================================

variable "vpc_id" {
  description = "ID de la VPC donde se desplegarán los recursos. Si no se proporciona, se buscará automáticamente por tags de gobernanza"
  type        = string
  default     = ""
}

variable "vpc_cidr" {
  description = "CIDR block de la VPC. Si no se proporciona, se obtendrá automáticamente del data source"
  type        = string
  default     = ""
}

variable "private_subnet_ids" {
  description = "IDs de las subnets privadas. Si no se proporciona, se buscarán automáticamente por tags de gobernanza"
  type        = list(string)
  default     = []
}

# ============================================
# Variables de Security Groups
# ============================================

variable "alb_port" {
  description = "Puerto del Application Load Balancer"
  type        = number
  default     = 80
}

variable "app_port" {
  description = "Puerto de la aplicación (contenedor)"
  type        = number
  default     = 8080
}

variable "db_port" {
  description = "Puerto de la base de datos"
  type        = number
  default     = 5432
}

# ============================================
# Variables de Secrets Manager
# ============================================

variable "db_username" {
  description = "Usuario maestro de la base de datos"
  type        = string
  sensitive   = true
}

variable "db_name" {
  description = "Nombre de la base de datos"
  type        = string
}

# ============================================
# Variables de ACM
# ============================================

variable "domain_name" {
  description = "Nombre del dominio para el certificado SSL/TLS"
  type        = string
}

variable "subject_alternative_names" {
  description = "Nombres alternativos del dominio"
  type        = list(string)
  default     = []
}

variable "validation_method" {
  description = "Método de validación del certificado (DNS o EMAIL)"
  type        = string
  default     = "DNS"
  validation {
    condition     = contains(["DNS", "EMAIL"], var.validation_method)
    error_message = "El método de validación debe ser DNS o EMAIL."
  }
}

# ============================================
# Variables de VPC Flow Logs
# ============================================

variable "flow_logs_retention_days" {
  description = "Días de retención para VPC Flow Logs"
  type        = number
  default     = 7
}

# ============================================
# Variables de IAM
# ============================================

variable "ecr_repository_arns" {
  description = "ARNs de los repositorios ECR"
  type        = list(string)
  default     = []
}

variable "kinesis_stream_arn" {
  description = "ARN del Kinesis Data Stream"
  type        = string
  default     = ""
}

variable "s3_bucket_arn" {
  description = "ARN del bucket S3 para Firehose"
  type        = string
  default     = ""
}

variable "personalize_dataset_group_arn" {
  description = "ARN del Dataset Group de Amazon Personalize"
  type        = string
  default     = ""
}

variable "lambda_function_name" {
  description = "Nombre de la función Lambda para procesamiento Kinesis"
  type        = string
  default     = ""
}

# ============================================
# Tags Adicionales (PC-IAC-004)
# ============================================

variable "additional_tags" {
  description = "Tags adicionales para aplicar a todos los recursos"
  type        = map(string)
  default     = {}
}
