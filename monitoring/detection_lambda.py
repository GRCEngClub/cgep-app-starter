import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Analiza logs de AWS CloudTrail distribuidos en tiempo real y genera
    alertas de cumplimiento para los controles de SOC 2 e HIPAA.
    """
    logger.info(f"Evento de auditoria recibido: {json.dumps(event)}")
    
    detail = event.get('detail', {})
    event_name = detail.get('eventName', '')
    user_identity = detail.get('userIdentity', {}).get('arn', 'Usuario-Desconocido')
    timestamp = detail.get('eventTime', 'Sin-Timestamp')
    
    # CONTROL CRÍTICO: SOC 2 CC6.1 - Detección de desactivación de cifrado en reposo
    if event_name in ["PutBucketEncryption", "DeleteBucketEncryption"]:
        request_parameters = detail.get('requestParameters', {})
        bucket_name = request_parameters.get('bucketName', 'desconocido')
        
        msg = f"🚨 ALERT [SOC 2 CC6.1 VIOLATION] - Timestamp: {timestamp} | Origen: CloudTrail | Control ID: CC6.1 | Mensaje: El usuario {user_identity} intento alterar o remover el cifrado SSE-KMS en el S3 Bucket: {bucket_name}."
        logger.error(msg)
        return {"status": "VIOLATION_DETECTED", "control_id": "CC6.1", "message": msg}
        
    # CONTROL CRÍTICO: SOC 2 CC6.3 - Detección de modificaciones manuales de privilegios en caliente
    if event_name in ["PutRolePolicy", "CreatePolicyVersion", "DeleteRolePolicy", "AttachRolePolicy"]:
        msg = f"🚨 ALERT [SOC 2 CC6.3 DRIFT] - Timestamp: {timestamp} | Origen: CloudTrail | Control ID: CC6.3 | Mensaje: Modificacion manual de permisos detectada por {user_identity}. Riesgo alto de violar el principio de menor privilegio."
        logger.warning(msg)
        return {"status": "IAM_DRIFT_DETECTED", "control_id": "CC6.3", "message": msg}

    return {"status": "COMPLIANT", "message": "Evento verificado. No se detectaron violaciones en esta operacion."}
