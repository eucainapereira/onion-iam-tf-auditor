"""
AWS Lambda entrypoint and HTTP API adapter for Onion Auditor.
Hardened against giant payloads, recursion DoS, and sensitive information leaks.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
from typing import Any, Dict

try:
    from .auditor import audit_iam, audit_terraform
except ImportError:
    from auditor import audit_iam, audit_terraform  # type: ignore

logger = logging.getLogger("onion_auditor.handler")

# Maximum payload size in bytes (default 512 KB)
MAX_PAYLOAD_BYTES: int = int(os.environ.get("MAX_PAYLOAD_BYTES", 512 * 1024))

# Configurable CORS origin (QA-015)
ALLOWED_ORIGIN: str = os.environ.get("ALLOWED_ORIGIN", "*")

CORS_HEADERS: Dict[str, str] = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}

# Regex for non-printable ASCII control characters (excluding \t (0x09), \n (0x0a), \r (0x0d))
# Strips \x00-\x08, \x0b, \x0c, \x0e-\x1f, and \x7f
CONTROL_CHARS_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _response(status_code: int, body_data: Any) -> Dict[str, Any]:
    """
    Constructs an API Gateway HTTP API v2 response with standardized CORS headers.
    """
    return {
        "statusCode": status_code,
        "headers": dict(CORS_HEADERS),
        "body": json.dumps(body_data, ensure_ascii=False),
    }


def _check_payload_size(data: Any) -> bool:
    """
    Checks if data exceeds MAX_PAYLOAD_BYTES (512 KB).
    Returns True if exceeded, False otherwise.
    """
    if isinstance(data, (bytes, bytearray)):
        return len(data) > MAX_PAYLOAD_BYTES
    if isinstance(data, str):
        if len(data) > MAX_PAYLOAD_BYTES:
            return True
        return len(data.encode("utf-8")) > MAX_PAYLOAD_BYTES
    return False


def _sanitize_content(content: str, audit_type: str) -> str:
    """
    Sanitizes invalid control characters.
    For Terraform HCL, strips non-printable control characters that could corrupt regex/parsing.
    For IAM JSON, preserves raw content so strict JSON parser rejects malformed control characters.
    """
    if audit_type == "terraform":
        return CONTROL_CHARS_PATTERN.sub("", content)
    return content


def _check_nesting_depth(obj: Any, max_depth: int = 800) -> None:
    """
    Validates nesting depth of parsed JSON structures to defend against
    deeply nested JSON DoS / RecursionError across all Python runtime versions (including Python 3.12+).
    """
    stack = [(obj, 1)]
    while stack:
        curr, depth = stack.pop()
        if depth > max_depth:
            raise RecursionError(f"Profundidade de aninhamento excessiva ({depth} > {max_depth}).")
        if isinstance(curr, dict):
            for v in curr.values():
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
        elif isinstance(curr, list):
            for item in curr:
                if isinstance(item, (dict, list)):
                    stack.append((item, depth + 1))


def lambda_handler(event: Any, context: Any = None) -> Dict[str, Any]:
    """
    AWS Lambda entrypoint handling API Gateway HTTP API v2 and direct calls.
    Protected with rigid payload size limits (512 KB), safe JSON/Base64 decoding,
    recursion handling, contract validation, and a strict global exception boundary.
    """
    try:
        return _handle_event(event, context)
    except Exception as global_exc:
        logger.error("Unhandled global exception in lambda_handler: %s", global_exc, exc_info=True)
        return _response(500, {"error": "Erro interno do servidor durante o processamento da requisição."})


def _handle_event(event: Any, context: Any = None) -> Dict[str, Any]:
    # 1. Handle OPTIONS (pre-flight)
    if isinstance(event, dict):
        method = ""
        if "requestContext" in event and isinstance(event["requestContext"], dict):
            http_ctx = event["requestContext"].get("http")
            if isinstance(http_ctx, dict):
                method = http_ctx.get("method", "").upper()
        if not method and "httpMethod" in event:
            method = str(event.get("httpMethod", "")).upper()
        if not method and "routeKey" in event and str(event["routeKey"]).startswith("OPTIONS"):
            method = "OPTIONS"

        if method == "OPTIONS":
            return _response(200, {"status": "ok"})

    # 2. Extract and validate raw payload
    payload: Any = None

    if isinstance(event, str):
        if _check_payload_size(event):
            return _response(413, {"error": "Corpo da requisição excede o limite máximo permitido de 512 KB."})
        try:
            payload = json.loads(event)
            _check_nesting_depth(payload)
        except RecursionError:
            return _response(
                400,
                {"error": "Limite de recursão excedido devido a aninhamento excessivo no JSON (RecursionError)."},
            )
        except Exception:
            return _response(400, {"error": "Corpo da requisição não é um JSON válido."})

    elif isinstance(event, dict):
        if "body" in event:
            raw_body = event["body"]
            if raw_body is None:
                return _response(400, {"error": "O corpo da requisição não pode ser nulo."})

            is_b64 = bool(event.get("isBase64Encoded", False))

            if isinstance(raw_body, str):
                if _check_payload_size(raw_body):
                    return _response(413, {"error": "Corpo da requisição excede o limite máximo permitido de 512 KB."})

                if is_b64:
                    try:
                        decoded_bytes = base64.b64decode(raw_body, validate=True)
                    except (binascii.Error, ValueError) as b64_err:
                        return _response(400, {"error": f"Erro na decodificação Base64: {str(b64_err)}"})
                    except Exception as b64_err:
                        return _response(400, {"error": f"Erro na decodificação Base64: {str(b64_err)}"})

                    if _check_payload_size(decoded_bytes):
                        return _response(413, {"error": "Corpo da requisição excede o limite máximo permitido de 512 KB."})

                    try:
                        raw_body = decoded_bytes.decode("utf-8")
                    except UnicodeDecodeError as dec_err:
                        return _response(400, {"error": f"Erro de decodificação UTF-8 no payload Base64: {str(dec_err)}"})

                try:
                    payload = json.loads(raw_body)
                    _check_nesting_depth(payload)
                except RecursionError:
                    return _response(
                        400,
                        {"error": "Limite de recursão excedido devido a aninhamento excessivo no JSON (RecursionError)."},
                    )
                except (json.JSONDecodeError, UnicodeDecodeError) as json_err:
                    return _response(400, {"error": f"JSON inválido no corpo da requisição: {str(json_err)}"})
                except Exception as json_err:
                    return _response(400, {"error": f"JSON inválido no corpo da requisição: {str(json_err)}"})

            elif isinstance(raw_body, dict):
                try:
                    _check_nesting_depth(raw_body)
                except RecursionError:
                    return _response(
                        400,
                        {"error": "Limite de recursão excedido devido a aninhamento excessivo no JSON (RecursionError)."},
                    )
                payload = raw_body
            else:
                return _response(400, {"error": "Formato de payload inválido."})

        elif "type" in event and "content" in event:
            try:
                _check_nesting_depth(event)
            except RecursionError:
                return _response(
                    400,
                    {"error": "Limite de recursão excedido devido a aninhamento excessivo no JSON (RecursionError)."},
                )
            payload = event
        else:
            return _response(400, {"error": "Campos 'type' e 'content' são obrigatórios."})
    else:
        return _response(400, {"error": "Evento de requisição inválido."})

    if not isinstance(payload, dict):
        return _response(400, {"error": "O corpo da requisição deve ser um objeto JSON."})

    # 3. Validate contract
    audit_type = payload.get("type")
    content = payload.get("content")

    if audit_type is None or not isinstance(audit_type, str):
        return _response(
            400,
            {"error": "O campo 'type' é obrigatório e deve ser uma string ('iam' ou 'terraform')."},
        )

    audit_type_clean = audit_type.strip().lower()
    if audit_type_clean not in ["iam", "terraform"]:
        return _response(
            400,
            {"error": f"Tipo de auditoria inválido: '{audit_type}'. Utilize 'iam' ou 'terraform'."},
        )

    if content is None or not isinstance(content, str) or not content.strip():
        return _response(
            400,
            {"error": "O campo 'content' é obrigatório e deve conter uma string não vazia."},
        )

    # 4. Check content size before deep processing
    if _check_payload_size(content):
        return _response(
            413,
            {"error": "Corpo da requisição excede o limite máximo permitido de 512 KB."},
        )

    # 5. Sanitize content
    content = _sanitize_content(content, audit_type_clean)

    # 6. Execute audit safely
    try:
        if audit_type_clean == "iam":
            result = audit_iam(content)
        else:
            result = audit_terraform(content)
        return _response(200, result)
    except RecursionError as rec_err:
        return _response(
            400,
            {"error": f"Limite de recursão excedido devido a aninhamento excessivo no JSON (RecursionError): {str(rec_err)}"},
        )
    except ValueError as val_err:
        err_msg = str(val_err)
        if "recursion" in err_msg.lower():
            return _response(
                400,
                {"error": f"Limite de recursão excedido devido a aninhamento excessivo no JSON (RecursionError): {err_msg}"},
            )
        return _response(400, {"error": err_msg})
    except Exception as exc:
        logger.error("Audit execution error: %s", exc, exc_info=True)
        return _response(500, {"error": "Erro interno durante a execução da auditoria."})
