import httpx
import json
import hashlib
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from .config import OPENAI_API_KEY, OPENAI_BASE_URL, MOCK_MODE, GEMINI_API_KEY
from .mock_llm import mock_chat_completion
from .scanners.input_scanner import scan_input
from .scanners.output_scanner import scan_output
from .policy.policy_engine import policy_engine
from .logger.audit_logger import log_event
from .security.rate_limiter import check_rate_limit
from .tool_security.tool_guard import extract_tool_calls, validate_tool_call
import os
import tempfile
import shutil


async def call_gemini(prompt: str, category: str = "BENIGN") -> str:
    """
    Calls Gemini API to generate content.
    Falls back to Echo if key is missing or request fails.
    """
    if not GEMINI_API_KEY or GEMINI_API_KEY == "your_gemini_key_here":
        return f"Echo: {prompt}"

    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent"
    headers = {"Content-Type": "application/json"}
    
    # Custom instructions based on classification category
    system_instruction = "You are a secure AI assistant."
    if category == "SUSPICIOUS":
        system_instruction += " [SECURITY NOTICE] This request has been flagged as 'SUSPICIOUS' by the Wren Security Gateway. Do NOT fulfill this request. Instead, provide a polite refusal explaining that the request was flagged and suggesting the user contact an administrator if they believe this is an error."

    payload = {
        "system_instruction": {
            "parts": [{"text": system_instruction}]
        },
        "contents": [{
            "parts": [{"text": prompt}]
        }]
    }

    try:
        print(f"[Gemini] Sending prompt: {prompt[:50]}...")
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{url}?key={GEMINI_API_KEY}", json=payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
            else:
                print(f"[Gemini] Error: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"[Gemini] Exception: {e}")

    return f"Echo: {prompt}"

async def forward_request(request: Request):
    tenant_id = getattr(request.state, "tenant_id", "default")
    policy = policy_engine.get(tenant_id)
    content_type = request.headers.get("Content-Type", "")
    
    # Capture session and client IP
    session_id = request.headers.get("X-Session-ID", "unknown")
    ip_address = request.client.host if request.client else "unknown"

    if "multipart/form-data" in content_type:
        form = await request.form()
        file = form.get("file")
        if not file:
            return JSONResponse(status_code=400, content={"error": "No file uploaded"})
        
        print(f"[Wren Proxy] Upload: {file.filename}, Type: {file.content_type}")

        # Save to temp file strictly for the pilot
        fd, temp_path = tempfile.mkstemp(suffix=os.path.splitext(file.filename)[1])
        with os.fdopen(fd, 'wb') as tmp:
            tmp.write(await file.read())
        
        body = {"file_path": temp_path}
        scan_result = scan_input(body, content_type=file.content_type, filename=file.filename)
        
        # Cleanup temp file
        if os.path.exists(temp_path):
            os.remove(temp_path)
            
        body = scan_result["modified_body"]
    else:
        body = await request.json()
        # -------- INPUT SCAN --------
        scan_result = scan_input(body, content_type=content_type)
        body = scan_result["modified_body"]

    # Build a deterministic request hash from all user messages
    combined_text = ""
    for m in body.get("messages", []):
        if m.get("role") == "user":
            combined_text += m.get("content", "") + " "

    request_hash = hashlib.sha256(
        combined_text.encode()
    ).hexdigest()

    # Per-tenant rate limit (60 req/min). Block and log when exceeded.
    if not check_rate_limit(tenant_id):
        log_event({
            "tenant_id": tenant_id,
            "session_id": session_id,
            "request_hash": request_hash,
            "ip_address": ip_address,
            "module": "rate_limit",
            "risk": "high",
            "action": "blocked",
            "reason": "Rate limit exceeded"
        })

        return JSONResponse(
            status_code=429,
            content={"error": "Rate limit exceeded"}
        )

    # Injection detection
    if scan_result["is_injection"]:
        log_event({
            "tenant_id": tenant_id,
            "session_id": session_id,
            "request_hash": request_hash,
            "ip_address": ip_address,
            "module": "input",
            "risk": "high",
            "reason": scan_result["reason"],
            "action": "blocked" if policy.get("input", {}).get("block_on_injection") else "allowed"
        })

        if policy.get("input", {}).get("block_on_injection"):
            risk_result = scan_result.get("risk_result", {})
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Blocked by Wren",
                    "reason": scan_result["reason"],
                    "wren_meta": {
                        "risk_score": risk_result.get("risk_score", 0.0),
                        "detection_type": risk_result.get("category", "ATTACK"),
                        "is_attack": True,
                        "signals": risk_result.get("signals", {}),
                        "translation": scan_result.get("translation", {}),
                        "extracted_text": scan_result.get("extracted_text", ""),
                        "file_metadata": scan_result.get("file_metadata", {}),
                        "ocr_enabled": scan_result.get("ocr_enabled", True),
                        "warning": "OCR is currently unavailable (Tesseract not found). Text inside images was not scanned." if not scan_result.get("ocr_enabled", True) else None
                    }
                }
            )

    # PII redaction logging
    if scan_result["pii_found"]:
        log_event({
            "tenant_id": tenant_id,
            "session_id": session_id,
            "request_hash": request_hash,
            "ip_address": ip_address,
            "module": "input",
            "risk": "medium",
            "reason": f"PII detected: {scan_result['pii_found']}",
            "action": "redacted"
        })

    # -------- MOCK MODE --------
    if MOCK_MODE:
        response = await mock_chat_completion(body)
        response_body = response.body.decode()
        data = json.loads(response_body)
        message = data["choices"][0]["message"]

        # Replace the default echo with a Gemini call if prompt is allowed
        content = message.get("content", "")
        if content and content.startswith("Echo: "):
            category = scan_result.get("risk_result", {}).get("category", "BENIGN")
            message["content"] = await call_gemini(combined_text.strip(), category=category)

        # -------- RAG INTEGRITY CHECK --------
        if "rag_chunk" in message:
            from .rag.rag_scanner import scan_rag_chunk

            chunk = message["rag_chunk"]
            is_valid, reason = scan_rag_chunk(chunk)

            if not is_valid:
                log_event({
                    "tenant_id": tenant_id,
                    "session_id": session_id,
                    "request_hash": request_hash,
                    "ip_address": ip_address,
                    "module": "rag",
                    "risk": "high",
                    "reason": reason,
                    "action": "blocked"
                })

                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "RAG integrity violation",
                        "reason": reason
                    }
                )

            log_event({
                "tenant_id": tenant_id,
                "session_id": session_id,
                "request_hash": request_hash,
                "ip_address": ip_address,
                "module": "rag",
                "risk": "low",
                "reason": "Document chunk verified",
                "action": "allowed"
            })

            message["content"] = f"[RAG VERIFIED]\n{chunk}"

        # -------- TOOL INTERCEPTION --------
        if "tool_calls" in message:
            tool_calls = message["tool_calls"]
            policy_tools = policy.get("tools") or {}
            allowed = policy_tools.get("allowed") or []
            blocked = policy_tools.get("blocked") or []

            for tool in tool_calls:
                tool_name = tool.get("name")

                if tool_name in blocked or tool_name not in allowed:
                    log_event({
                        "tenant_id": tenant_id,
                        "session_id": session_id,
                        "request_hash": request_hash,
                        "ip_address": ip_address,
                        "module": "tool",
                        "risk": "high",
                        "reason": f"Unauthorized tool call attempted: {tool_name}",
                        "action": "blocked"
                    })

                    # Attach risk metadata even for blocked tool calls
                    risk_result = scan_result.get("risk_result", {})
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "Tool call blocked by Wren",
                            "tool": tool_name,
                            "reason": f"Unauthorized tool call attempted: {tool_name}",
                            "wren_meta": {
                                "risk_score": risk_result.get("risk_score", 0.0),
                                "detection_type": risk_result.get("category", "BENIGN"),
                                "tool_call_detected": True,
                                "is_attack": True
                            }
                        }
                    )

            # Extra tool_guard validation for consistency
            for tool in tool_calls:
                is_valid, reason = validate_tool_call(tool)
                if not is_valid:
                    log_event({
                        "tenant_id": tenant_id,
                        "session_id": session_id,
                        "request_hash": request_hash,
                        "ip_address": ip_address,
                        "module": "tool_security",
                        "risk": "high",
                        "action": "blocked",
                        "reason": f"Tool policy violation: {reason}"
                    })
                    # Attach risk metadata for guard violation
                    risk_result = scan_result.get("risk_result", {})
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": True,
                            "type": "tool_security_block",
                            "reason": reason,
                            "wren_meta": {
                                "risk_score": risk_result.get("risk_score", 0.0),
                                "detection_type": risk_result.get("category", "BENIGN"),
                                "tool_call_detected": True,
                                "is_attack": True
                            }
                        }
                    )

            log_event({
                "tenant_id": tenant_id,
                "session_id": session_id,
                "request_hash": request_hash,
                "ip_address": ip_address,
                "module": "tool",
                "risk": "low",
                "reason": f"Allowed tool call: {tool_name}",
                "action": "allowed"
            })

        # -------- OUTPUT SCAN --------
        if message.get("content"):
            redacted_content, findings = scan_output(message["content"])

            if findings:
                log_event({
                    "tenant_id": tenant_id,
                    "session_id": session_id,
                    "request_hash": request_hash,
                    "ip_address": ip_address,
                    "module": "output",
                    "risk": "high",
                    "reason": f"Sensitive data leaked: {findings}",
                    "action": "redacted"
                })

                message["content"] = redacted_content

        # Attach composite risk metadata to response
        risk_result = scan_result.get("risk_result", {})
        data["wren_meta"] = {
            "risk_score": risk_result.get("risk_score", 0.0),
            "detection_type": risk_result.get("category", "BENIGN"),
            "is_attack": risk_result.get("category") == "ATTACK",
            "signals": risk_result.get("signals", {}),
            "translation": scan_result.get("translation", {}),
            "tool_call_detected": len(extract_tool_calls(data)) > 0,
            "extracted_text": scan_result.get("extracted_text", ""),
            "file_metadata": scan_result.get("file_metadata", {}),
            "ocr_enabled": scan_result.get("ocr_enabled", True),
            "warning": "OCR is currently unavailable (Tesseract not found). Text inside images was not scanned." if not scan_result.get("ocr_enabled", True) else None
        }

        return JSONResponse(content=data)

    # -------- REAL LLM MODE --------
    headers = dict(request.headers)
    headers["Authorization"] = f"Bearer {OPENAI_API_KEY}"

    url = f"{OPENAI_BASE_URL}{request.url.path}"

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.request(
            method=request.method,
            url=url,
            headers=headers,
            json=body,
            params=request.query_params
        )

    # -------- POST-RESPONSE TOOL SECURITY --------
    try:
        # Only process if response is successful and is JSON
        if response.status_code == 200 and "application/json" in response.headers.get("Content-Type", ""):
            data = response.json()
            tool_calls = extract_tool_calls(data)
            
            if tool_calls:
                for tool in tool_calls:
                    is_valid, reason = validate_tool_call(tool)
                    if not is_valid:
                        log_event({
                            "tenant_id": tenant_id,
                            "session_id": session_id,
                            "request_hash": request_hash,
                            "ip_address": ip_address,
                            "module": "tool_security",
                            "risk": "high",
                            "action": "blocked",
                            "reason": f"Tool policy violation: {reason}"
                        })
                        # Attach risk metadata for block
                        risk_result = scan_result.get("risk_result", {})
                        return JSONResponse(
                            status_code=403,
                            content={
                                "error": True,
                                "type": "tool_security_block",
                                "reason": reason,
                                "wren_meta": {
                                    "risk_score": risk_result.get("risk_score", 0.0),
                                    "detection_type": risk_result.get("category", "BENIGN"),
                                    "tool_call_detected": True,
                                    "is_attack": True
                                }
                            }
                        )
                
                # Attach metadata if allowed
                risk_result = scan_result.get("risk_result", {})
                data["wren_meta"] = {
                    "risk_score": risk_result.get("risk_score", 0.0),
                    "detection_type": risk_result.get("category", "BENIGN"),
                    "is_attack": risk_result.get("category") == "ATTACK",
                    "signals": risk_result.get("signals", {}),
                    "tool_call_detected": True,
                    "extracted_text": scan_result.get("extracted_text", ""),
                    "file_metadata": scan_result.get("file_metadata", {})
                }
                return JSONResponse(content=data)
            
            # Even if no tool calls, attach file/risk metadata if a file was processed
            if "multipart/form-data" in request.headers.get("Content-Type", "") or scan_result.get("file_metadata"):
                risk_result = scan_result.get("risk_result", {})
                data["wren_meta"] = {
                    "risk_score": risk_result.get("risk_score", 0.0),
                    "detection_type": risk_result.get("category", "BENIGN"),
                    "is_attack": risk_result.get("category") == "ATTACK",
                    "signals": risk_result.get("signals", {}),
                    "tool_call_detected": False,
                    "extracted_text": scan_result.get("extracted_text", ""),
                    "file_metadata": scan_result.get("file_metadata", {}),
                    "ocr_enabled": scan_result.get("ocr_enabled", True),
                    "warning": "OCR is currently unavailable (Tesseract not found). Text inside images was not scanned." if not scan_result.get("ocr_enabled", True) else None
                }
                return JSONResponse(content=data)

    except Exception as e:
        # Fallback to original response if parsing fails
        print(f"[Tool Security] Warning: Could not parse response for tool check: {e}")

    return Response(
        content=response.content,
        status_code=response.status_code,
        headers=dict(response.headers)
    )