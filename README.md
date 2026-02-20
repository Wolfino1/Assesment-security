# Security & Connectivity Infrastructure - Terraform Module

Este módulo de Terraform implementa la capa de seguridad lógica, cifrado de datos, gestión de secretos y certificados de identidad siguiendo las mejores prácticas de seguridad y las reglas PC-IAC de Pragma CloudOps.

## Descripción

El módulo despliega una arquitectura de seguridad completa que incluye:

### Security Groups (Modelo n-tier)
- 1 Security Group para ALB (HTTP/HTTPS desde internet)
- 1 Security Group para Aplicación ECS Fargate (tráfico desde ALB)
- 1 Security Group para Base de Datos RDS (tráfico desde aplicación)
- 1 Security Group para Lambda (procesador Kinesis a Personalize - fuera de VPC)
- 1 Security Group para VPC Endpoints (tráfico desde app)

### Cifrado y Gestión de Secretos
- 1 Customer Managed Key (KMS) con rotación automática
- 1 Secret en Secrets Manager para credenciales de base de datos
- Generación automática de contraseña segura (32 caracteres)

### Certificados SSL/TLS
- 1 Certificado ACM para el dominio del proyecto
- Soporte para nombres alternativos (SANs)
- Validación por DNS o EMAIL

### Observabilidad de Red
- VPC Flow Logs capturando todo el tráfico de la VPC
- CloudWatch Log Group con retención configurable
- Logs cifrados con KMS

### Roles IAM
- ECS Task Execution Role (para iniciar contenedores)
- ECS Task Role (para la aplicación en ejecución)
- Kinesis Firehose Role (para mover datos a S3)
- Lambda Execution Role (para procesar eventos de Kinesis)
- Amazon Personalize Role (para entrenar modelos)
- RDS Enhanced Monitoring Role (para métricas detalladas)

## Arquitectura de Seguridad

### Flujo de Tráfico (n-tier)

```
Internet (0.0.0.0/0)
    ↓ (HTTP/HTTPS - 80/443)
ALB Security Group
    ↓ (App Port - ej. 8080)
Application Security Group (ECS Fargate)
    ↓ (DB Port - ej. 5432)
Database Security Group (RDS)
```

### Flujo de Datos con Kinesis

```
ECS Fargate
    ↓ (usa VPC Endpoint kinesis-streams)
Kinesis Data Streams
    ↓ (Firehose consume)
Kinesis Firehose
    ↓ (escribe a S3)
S3 Bucket
    ↓ (Personalize lee)
Amazon Personalize
```

### Lambda para Procesamiento

```
Kinesis Data Streams
    ↓ (trigger)
Lambda (fuera de VPC)
    ↓ (acceso directo)
Amazon Personalize API
```

**Nota:** La Lambda se ejecuta fuera de la VPC para acceder directamente a Kinesis Data Streams y Amazon Personalize sin necesidad de VPC Endpoints ni NAT Gateway, simplificando la arquitectura y reduciendo costos.

## Características de Seguridad (PC-IAC-020)

### Cifrado en Reposo y en Tránsito
- KMS Customer Managed Key con rotación automática habilitada
- Secretos cifrados en Secrets Manager
- Logs de Flow Logs cifrados con KMS
- Certificados TLS gestionados por ACM

### Principio de Mínimo Privilegio
- Security Groups con reglas específicas por origen/destino
- Prohibición de 0.0.0.0/0 en puertos no públicos
- Roles IAM con permisos mínimos necesarios
- Políticas IAM específicas por recurso cuando es posible

### Control de Acceso a Metadatos
- Roles IAM para servicios (no credenciales hardcoded)
- Secrets Manager para credenciales de base de datos
- KMS para control de acceso a datos cifrados

### Privacidad de Red
- Tráfico interno a través de VPC Endpoints
- Lambda fuera de VPC para acceso directo a servicios AWS gestionados
- Egreso a internet controlado mediante NAT Gateway para aplicaciones en VPC

### Observabilidad
- VPC Flow Logs capturando todo el tráfico
- Retención configurable de logs
- Centralización en CloudWatch Logs

## Uso

### Opción 1: Detección Automática (Recomendado)

El módulo puede detectar automáticamente la VPC y subnets privadas usando los tags de gobernanza:

```hcl
module "security" {
  source = "./security"

  # Variables de gobernanza (requeridas)
  client      = "pragma"
  project     = "myproject"
  environment = "dev"
  region      = "us-east-1"

  # Variables de red: NO es necesario especificarlas
  # El módulo las buscará automáticamente por tags

  # Configuración de Security Groups
  alb_port = 80
  app_port = 8080
  db_port  = 5432

  # Configuración de Secrets Manager
  db_username = "dbadmin"
  db_name     = "myapp"

  # Configuración de ACM
  domain_name               = "myapp.example.com"
  subject_alternative_names = ["*.myapp.example.com"]
  validation_method         = "DNS"

  # Configuración de VPC Flow Logs
  flow_logs_retention_days = 7

  # Tags adicionales
  additional_tags = {
    Owner      = "CloudOps Team"
    CostCenter = "Engineering"
  }
}
```

### Opción 2: Especificación Manual

Si prefieres especificar manualmente los valores de red:

```hcl
module "security" {
  source = "./security"

  # Variables de gobernanza
  client      = "pragma"
  project     = "myproject"
  environment = "dev"
  region      = "us-east-1"

  # Variables de red (especificadas manualmente)
  vpc_id             = module.networking.vpc_id
  vpc_cidr           = module.networking.vpc_cidr
  private_subnet_ids = module.networking.private_subnet_ids

  # Resto de configuración...
}
```

## Inputs

| Nombre | Descripción | Tipo | Default | Requerido |
|--------|-------------|------|---------|-----------|
| client | Nombre del cliente (máx 10 caracteres) | string | - | Sí |
| project | Nombre del proyecto (máx 15 caracteres) | string | - | Sí |
| environment | Ambiente de despliegue (dev, qa, pdn) | string | - | Sí |
| region | Región de AWS | string | "us-east-1" | No |
| vpc_id | ID de la VPC. Si no se proporciona, se busca automáticamente por tags de gobernanza | string | "" | No |
| vpc_cidr | CIDR block de la VPC. Si no se proporciona, se obtiene automáticamente | string | "" | No |
| private_subnet_ids | IDs de las subnets privadas. Si no se proporciona, se buscan automáticamente por tags | list(string) | [] | No |
| alb_port | Puerto del ALB | number | 80 | No |
| app_port | Puerto de la aplicación | number | 8080 | No |
| db_port | Puerto de la base de datos | number | 5432 | No |
| db_username | Usuario maestro de la base de datos | string | - | Sí |
| db_name | Nombre de la base de datos | string | - | Sí |
| domain_name | Nombre del dominio para certificado SSL/TLS | string | - | Sí |
| subject_alternative_names | Nombres alternativos del dominio | list(string) | [] | No |
| validation_method | Método de validación del certificado (DNS o EMAIL) | string | "DNS" | No |
| flow_logs_retention_days | Días de retención para VPC Flow Logs | number | 7 | No |
| ecr_repository_arns | ARNs de los repositorios ECR | list(string) | [] | No |
| kinesis_stream_arn | ARN del Kinesis Data Stream | string | "" | No |
| s3_bucket_arn | ARN del bucket S3 para Firehose | string | "" | No |
| personalize_dataset_group_arn | ARN del Dataset Group de Amazon Personalize | string | "" | No |
| lambda_function_name | Nombre de la función Lambda | string | "" | No |
| additional_tags | Tags adicionales | map(string) | {} | No |

## Outputs

| Nombre | Descripción |
|--------|-------------|
| vpc_id | ID de la VPC utilizada (detectada automáticamente o especificada) |
| vpc_cidr | CIDR block de la VPC utilizada |
| private_subnet_ids | IDs de las subnets privadas utilizadas |
| sg_alb_id | ID del Security Group del ALB |
| sg_app_id | ID del Security Group de la aplicación |
| sg_db_id | ID del Security Group de la base de datos |
| sg_lambda_id | ID del Security Group de Lambda |
| sg_vpc_endpoints_id | ID del Security Group de VPC Endpoints |
| kms_key_id | ID de la llave KMS |
| kms_key_arn | ARN de la llave KMS |
| kms_key_alias | Alias de la llave KMS |
| db_secret_arn | ARN del secreto de credenciales de base de datos |
| db_secret_name | Nombre del secreto de credenciales de base de datos |
| acm_certificate_arn | ARN del certificado ACM |
| acm_certificate_domain | Dominio del certificado ACM |
| acm_certificate_status | Estado del certificado ACM |
| flow_logs_id | ID de VPC Flow Logs |
| flow_logs_log_group_name | Nombre del CloudWatch Log Group para Flow Logs |
| flow_logs_role_arn | ARN del rol IAM para Flow Logs |
| ecs_task_execution_role_arn | ARN del rol de ejecución de tareas ECS |
| ecs_task_execution_role_name | Nombre del rol de ejecución de tareas ECS |
| ecs_task_role_arn | ARN del rol de tareas ECS |
| ecs_task_role_name | Nombre del rol de tareas ECS |
| firehose_role_arn | ARN del rol de Kinesis Firehose |
| firehose_role_name | Nombre del rol de Kinesis Firehose |
| lambda_execution_role_arn | ARN del rol de ejecución de Lambda |
| lambda_execution_role_name | Nombre del rol de ejecución de Lambda |
| personalize_role_arn | ARN del rol de Amazon Personalize |
| personalize_role_name | Nombre del rol de Amazon Personalize |
| rds_monitoring_role_arn | ARN del rol de monitoreo de RDS |
| rds_monitoring_role_name | Nombre del rol de monitoreo de RDS |
| security_summary | Resumen de la infraestructura de seguridad creada |

## Requisitos

- Terraform >= 1.5.0
- AWS Provider ~> 5.0
- Random Provider ~> 3.6
- Credenciales de AWS configuradas
- Módulo de networking desplegado previamente (con tags de gobernanza correctos)

### Requisitos para Detección Automática

Para que el módulo pueda detectar automáticamente la VPC y subnets, el módulo de networking debe haber creado los recursos con los siguientes tags:

**VPC:**
- `Client` = valor de var.client
- `Project` = valor de var.project
- `Environment` = valor de var.environment

**Subnets Privadas:**
- `Client` = valor de var.client
- `Project` = valor de var.project
- `Environment` = valor de var.environment
- `Type` = "Private"

Si estos tags no están presentes, deberás especificar manualmente los valores de `vpc_id`, `vpc_cidr` y `private_subnet_ids`.

## Cumplimiento de Reglas PC-IAC

| Regla | Descripción | Implementación |
|-------|-------------|----------------|
| PC-IAC-002 | Variables de Gobernanza | Variables client, project, environment con validaciones |
| PC-IAC-003 | Nomenclatura Estándar | Prefijo de gobernanza en todos los recursos |
| PC-IAC-004 | Etiquetas Obligatorias | Tags comunes aplicados mediante merge |
| PC-IAC-010 | For_Each y Control | Uso de for_each para recursos múltiples |
| PC-IAC-020 | Seguridad (Hardenizado) | Cifrado, mínimo privilegio, VPC Endpoints, Flow Logs |

## Decisiones de Diseño

### Detección Automática de Recursos de Red
El módulo utiliza data sources para buscar automáticamente la VPC y subnets privadas basándose en los tags de gobernanza (client, project, environment). Esto elimina la necesidad de hardcodear IDs de recursos y permite que el módulo funcione inmediatamente después de desplegar el módulo de networking, siempre que los tags estén correctamente configurados.

**Ventajas:**
- No es necesario copiar/pegar IDs manualmente
- Reduce errores de configuración
- Facilita la automatización y CI/CD
- Mantiene consistencia entre módulos

**Alternativa:** Si prefieres control explícito, puedes especificar manualmente los valores de `vpc_id`, `vpc_cidr` y `private_subnet_ids`.

### Security Groups por Capa
Se implementa un modelo n-tier donde cada capa solo acepta tráfico de su predecesor inmediato, minimizando la superficie de ataque.

### Lambda fuera de VPC
La Lambda se ejecuta fuera de la VPC para simplificar la arquitectura y reducir costos. Al estar fuera de la VPC:
- Accede directamente a Kinesis Data Streams sin necesidad de VPC Endpoint
- Se comunica con Amazon Personalize sin pasar por NAT Gateway
- No requiere configuración de red adicional (ENIs, subnets)
- Reduce latencia al eliminar saltos de red innecesarios

### KMS Customer Managed Key
Se utiliza una llave gestionada por el cliente (no AWS managed) para tener control total sobre las políticas de acceso y rotación.

### Secrets Manager vs Parameter Store
Se elige Secrets Manager por su capacidad de rotación automática de secretos y mejor integración con RDS.

### VPC Flow Logs
Se captura todo el tráfico (ALL) para tener visibilidad completa, con retención configurable para balance entre costo y auditoría.

### Roles IAM Específicos
Cada servicio tiene su propio rol con permisos mínimos necesarios, evitando roles compartidos que podrían escalar privilegios.

## Seguridad Adicional

### Rotación de Secretos
El secreto de base de datos debe configurarse con rotación automática después del despliegue inicial de RDS.

### Validación de Certificado ACM
El certificado ACM requiere validación manual (DNS o EMAIL) antes de poder usarse en el ALB.

### Monitoreo de Flow Logs
Se recomienda configurar alarmas de CloudWatch para detectar patrones anómalos en el tráfico de red.

### Políticas de KMS
Se recomienda agregar políticas de KMS específicas para limitar qué roles pueden usar la llave para cifrado/descifrado.

## Autor

Pragma CloudOps Team

## Licencia

Proprietary - Pragma
