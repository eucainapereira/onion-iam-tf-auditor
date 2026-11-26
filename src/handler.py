"""
AWS Lambda entrypoint and HTTP API adapter for Onion Auditor.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict

try:
    from .auditor import audit_iam, audit_terraform
except ImportError:
    from auditor import audit_iam, audit_terraform  # type: ignore


CORS_HEADERS: Dict[str, str] = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


def _response(status_code: int, body_data: Any) -> Dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": CORS_HEADERS,
        "body": json.dumps(body_data, ensure_ascii=False),
    }


def lambda_handler(event: Any, context: Any = None) -> Dict[str, Any]:
    """
    AWS Lambda entrypoint handling API Gateway HTTP API v2 and direct calls.
    """
    # 1. Handle OPTIONS (pre-flight)
    if isinstance(event, dict):
        method = ""
        if "requestContext" in event and "http" in event["requestContext"]:
            method = event["requestContext"]["http"].get("method", "").upper()
        elif "httpMethod" in event:
            method = event.get("httpMethod", "").upper()
        elif "routeKey" in event and event["routeKey"].startswith("OPTIONS"):
            method = "OPTIONS"

        if method == "OPTIONS":
            return _response(200, {"status": "ok"})

    # 2. Extract payload
    payload: Any = None
    if isinstance(event, str):
        try:
            payload = json.loads(event)
        except Exception:
            return _response(400, {"error": "Corpo da requisição não é um JSON válido."})
    elif isinstance(event, dict):
        if "body" in event and event["body"] is not None:
            raw_body = event["body"]
            if event.get("isBase64Encoded", False):
                try:
                    raw_body = base64.b64decode(raw_body).decode("utf-8")
                except Exception as exc:
                    return _response(400, {"error": f"Erro na decodificação Base64: {str(exc)}"})

            if isinstance(raw_body, dict):
                payload = raw_body
            elif isinstance(raw_body, str):
                try:
                    payload = json.loads(raw_body)
                except Exception as exc:
                    return _response(400, {"error": f"JSON inválido no corpo da requisição: {str(exc)}"})
            else:
                return _response(400, {"error": "Formato de payload inválido."})
        elif "type" in event and "content" in event:
            payload = event
        else:
            return _response(400, {"error": "Campos 'type' e 'content' são obrigatórios."})
    else:
        return _response(400, {"error": "Evento de requisição inválido."})

    if not isinstance(payload, dict):
        return _response(400, {"error": "O corpo da requisição deve ser um objeto JSON."})

    # 3. Validate fields
    audit_type = payload.get("type")
    content = payload.get("content")

    if not audit_type or not isinstance(audit_type, str):
        return _response(400, {"error": "O campo 'type' é obrigatório e deve ser uma string ('iam' ou 'terraform')."})

    audit_type = audit_type.strip().lower()
    if audit_type not in ["iam", "terraform"]:
        return _response(400, {"error": f"Tipo de auditoria inválido: '{audit_type}'. Utilize 'iam' ou 'terraform'."})

    if content is None or not isinstance(content, str) or not content.strip():
        return _response(400, {"error": "O campo 'content' é obrigatório e deve conter uma string não vazia."})

    # 4. Execute audit
    try:
        if audit_type == "iam":
            result = audit_iam(content)
        else:
            result = audit_terraform(content)
        return _response(200, result)
    except ValueError as val_err:
        return _response(400, {"error": str(val_err)})
    except Exception as exc:
        return _response(500, {"error": f"Erro interno durante a execução da auditoria: {str(exc)}"})
