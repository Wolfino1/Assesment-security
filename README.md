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

### Protección contra Amenazas
- 1 AWS WAF Web ACL para CloudFront con 5 reglas:
  - AWS Managed Rules Common Rule Set (OWASP Top 10)
  - AWS Managed Rules SQL Injection Protection
  - AWS Managed Rules IP Reputation List
  - AWS Managed Rules Known Bad Inputs
  - Rate Limiting personalizable
- 1 AWS GuardDuty Detector para detección de amenazas
- AWS Shield Standard (habilitado por defecto)

### Gestión de Identidad y Acceso
- 1 AWS Cognito User Pool como proveedor de identidad
  - Email como identificador principal con auto-verificación
  - Políticas de contraseña robustas (mín. 12 caracteres)
  - Cifrado de datos en reposo con KMS
  - Advanced Security Mode habilitado
- 1 Cognito User Pool Client para la aplicación
  - Client secret generado automáticamente
  - Flujos de autenticación: USER_PASSWORD, REFRESH_TOKEN, USER_SRP
  - OAuth 2.0 con scopes: email, openid, profile
- 1 Cognito Domain personalizado con certificado ACM

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

### Protección de Perímetro
- WAF con reglas gestionadas de AWS para protección contra OWASP Top 10
- Rate limiting para prevenir ataques de denegación de servicio
- Métricas de CloudWatch habilitadas para todas las reglas WAF

### Detección de Amenazas
- GuardDuty habilitado con frecuencia de hallazgos de 15 minutos
- Protección de datos en S3, Kubernetes y EC2
- Escaneo de malware en volúmenes EBS

### Protección Anti-DDoS
- Shield Standard habilitado por defecto (sin costo adicional)
- Protección automática en capas 3 y 4 para CloudFront, Route53, ELB y Elastic IPs

### Gestión de Identidad con Cognito
- User Pool configurado con email como identificador principal
- Políticas de contraseña robustas (mínimo 12 caracteres, requiere números, símbolos, mayúsculas y minúsculas)
- Advanced Security Mode habilitado para prevención de compromiso de cuentas
- Cifrado de datos en reposo con KMS Customer Managed Key
- Dominio personalizado con certificado ACM para URLs branded (ej: auth.assesment.pragma.com.co)
- OAuth 2.0 con flujos de autenticación seguros
- Client secret generado automáticamente para la aplicación

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

  # Configuración de WAF
  enable_waf     = true
  waf_rate_limit = 2000

  # Configuración de GuardDuty
  enable_guardduty            = true
  guardduty_finding_frequency = "FIFTEEN_MINUTES"

  # Configuración de Cognito
  enable_cognito         = true
  cognito_custom_domain  = "auth.assesment.pragma.com.co"
  password_minimum_length = 12
  cognito_callback_urls  = ["https://myapp.example.com/callback"]
  cognito_logout_urls    = ["https://myapp.example.com/logout"]

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
| enable_waf | Habilitar AWS WAF para CloudFront | bool | true | No |
| waf_rate_limit | Límite de requests por IP en 5 minutos | number | 2000 | No |
| enable_guardduty | Habilitar AWS GuardDuty para detección de amenazas | bool | true | No |
| guardduty_finding_frequency | Frecuencia de publicación de hallazgos (FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS) | string | "FIFTEEN_MINUTES" | No |
| enable_cognito | Habilitar AWS Cognito User Pool como proveedor de identidad | bool | true | No |
| cognito_custom_domain | Dominio personalizado completo para Cognito (ej: auth.assesment.pragma.com.co) | string | "" | No |
| cognito_domain_prefix | Prefijo del dominio de Cognito si no se usa dominio personalizado | string | "auth" | No |
| password_minimum_length | Longitud mínima de la contraseña | number | 12 | No |
| cognito_callback_urls | URLs de callback permitidas para el cliente de Cognito | list(string) | ["https://localhost:3000/callback"] | No |
| cognito_logout_urls | URLs de logout permitidas para el cliente de Cognito | list(string) | ["https://localhost:3000/logout"] | No |
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
| waf_web_acl_id | ID del WAF Web ACL para CloudFront |
| waf_web_acl_arn | ARN del WAF Web ACL para CloudFront |
| waf_web_acl_capacity | Capacidad utilizada por el WAF Web ACL |
| guardduty_detector_id | ID del detector de GuardDuty |
| guardduty_detector_arn | ARN del detector de GuardDuty |
| guardduty_account_id | ID de la cuenta de AWS con GuardDuty habilitado |
| shield_standard_status | Estado de AWS Shield Standard |
| cognito_user_pool_id | ID del Cognito User Pool |
| cognito_user_pool_arn | ARN del Cognito User Pool |
| cognito_user_pool_endpoint | Endpoint del Cognito User Pool |
| cognito_client_id | ID del cliente de aplicación de Cognito |
| cognito_client_secret | Secret del cliente de aplicación de Cognito (sensible) |
| cognito_domain_url | URL del dominio de Cognito |
| cognito_hosted_ui_url | URL de la interfaz de usuario hospedada de Cognito |
| security_summary | Resumen de la infraestructura de seguridad creada |

## Requisitos

- Terraform >= 1.5.0
- AWS Provider ~> 5.0 (con alias us_east_1 para WAF)
- Random Provider ~> 3.6
- Credenciales de AWS configuradas
- Módulo de networking desplegado previamente (con tags de gobernanza correctos)

### Nota sobre WAF y CloudFront
El WAF para CloudFront debe crearse en la región us-east-1 independientemente de la región donde se desplieguen los demás recursos. El módulo incluye un provider alias configurado automáticamente para esto.

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

### AWS WAF para CloudFront
Se implementa WAF con reglas gestionadas de AWS que cubren las amenazas más comunes (OWASP Top 10, SQL Injection, IPs maliciosas). El rate limiting protege contra ataques de denegación de servicio a nivel de aplicación.

### GuardDuty para Detección de Amenazas
GuardDuty analiza continuamente los logs de VPC Flow, CloudTrail y DNS para detectar comportamientos anómalos y amenazas. La frecuencia de 15 minutos permite respuesta rápida a incidentes.

### Shield Standard
AWS Shield Standard está habilitado por defecto sin costo adicional y proporciona protección automática contra ataques DDoS comunes en las capas 3 y 4. Para protección avanzada (Shield Advanced), se requiere suscripción manual.

### AWS Cognito como Identity Provider
Se implementa Cognito User Pool como proveedor de identidad centralizado para la aplicación ECS. 

**Características clave:**
- Email como identificador único simplifica la experiencia del usuario
- Políticas de contraseña robustas cumplen con estándares de seguridad empresarial
- Advanced Security Mode detecta y previene intentos de compromiso de cuentas
- Dominio personalizado con certificado ACM proporciona URLs branded y profesionales
- OAuth 2.0 permite integración con aplicaciones web y móviles
- Client secret protege la comunicación entre la aplicación y Cognito

**Integración con otros recursos:**
- Usa el certificado ACM del módulo para el dominio personalizado
- Cifra datos en reposo con la KMS Customer Managed Key del módulo
- Se integra con el ALB para autenticación de usuarios antes de acceder a la aplicación

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
