from typing import Tuple
from .injection_rules import COMPILED_PATTERNS
from .pii_rules import EMAIL_REGEX, PHONE_REGEX, API_KEY_REGEX, CREDIT_CARD_REGEX
from .risk_scorer import compute_risk_score
from app.semantic.ml_detector import analyze_prompt
from app.logger.audit_logger import log_event
from app.file_processor import process_file
import os
from langdetect import detect, DetectorFactory
from deep_translator import GoogleTranslator

# Ensure deterministic language detection
DetectorFactory.seed = 0


def detect_injection(text: str) -> Tuple[bool, str, int]:
    """
    Fast rule-based detection using pre-compiled regex.
    Returns (matched, reason, match_count).
    """
    match_count = 0
    for pattern in COMPILED_PATTERNS:
        if pattern.search(text):
            match_count += 1

    if match_count > 0:
        return True, "Blocked: Identified high-risk pattern match", match_count

    return False, "No injection detected", 0


def redact_pii(text: str):
    redacted = text
    findings = []

    if EMAIL_REGEX.search(redacted):
        redacted = EMAIL_REGEX.sub("[REDACTED_EMAIL]", redacted)
        findings.append("email")

    if PHONE_REGEX.search(redacted):
        redacted = PHONE_REGEX.sub("[REDACTED_PHONE]", redacted)
        findings.append("phone")

    if API_KEY_REGEX.search(redacted):
        redacted = API_KEY_REGEX.sub("[REDACTED_API_KEY]", redacted)
        findings.append("api_key")

    if CREDIT_CARD_REGEX.search(redacted):
        redacted = CREDIT_CARD_REGEX.sub("[REDACTED_CARD]", redacted)
        findings.append("credit_card")

    return redacted, findings


def detect_input_type(content_type: str, filename: str = "") -> str:
    """Categorizes MIME types and filenames into text, pdf, or image."""
    ct = (content_type or "").lower()
    fn = (filename or "").lower()

    if ct == "application/pdf" or fn.endswith(".pdf"):
        return "pdf"
    elif ct.startswith("image/") or any(fn.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".webp"]):
        return "image"
    else:
        return "text"


def translate_prompt(text: str) -> dict:
    """
    Detects language and translates to English if necessary.
    Returns { "translated_text": str, "source_lang": str, "applied": bool }
    """
    if not text.strip() or len(text.strip()) < 3:
        return {"translated_text": text, "source_lang": "en", "applied": False}

    try:
        source_lang = detect(text)
        print(f"[Wren Translation] Detected Language: {source_lang}")
        if source_lang == "en":
            return {"translated_text": text, "source_lang": "en", "applied": False}

        translated = GoogleTranslator(source="auto", target="en").translate(text)
        print(f"[Wren Translation] Translated to: {translated}")
        return {
            "translated_text": translated,
            "source_lang": source_lang,
            "applied": True
        }
    except Exception as e:
        print(f"[Wren Translation] Error: {e}")
        return {"translated_text": text, "source_lang": "unknown", "applied": False}


def scan_input(body: dict, content_type: str = "text/plain", filename: str = ""):
    input_type = detect_input_type(content_type, filename)

    # --- Router: Redirect Files to Processor ---
    if input_type != "text":
        file_path = body.get("file_path")
        if file_path and os.path.exists(file_path):
            file_data = process_file(file_path, content_type, filename)
            extracted_text = file_data.get("text", "")
            metadata = file_data.get("metadata", {})
            ocr_enabled = file_data.get("ocr_enabled", True)
            
            # Combine text and metadata for security scanning
            eval_text = extracted_text
            if metadata:
                metadata_str = " ".join([str(v) for v in metadata.values() if isinstance(v, (str, int, float))])
                eval_text += "\n[METADATA]\n" + metadata_str

            # Create a new body with the combined text to reuse the evaluation logic
            new_body = {
                "messages": [{"role": "user", "content": eval_text}]
            }
            # RE-ENTRANT CALL: Evaluate the combined content as a normal prompt
            result = scan_input(new_body, "text/plain")
            
            # UNCONDITIONAL LOGGING: Ensure all file uploads appear in the monitor
            log_event({
                "module": "file_scanner",
                "risk": "low" if not result["is_injection"] else "high",
                "action": "allowed" if not result["is_injection"] else "blocked",
                "reason": f"File '{filename}' processed. OCR Enabled: {ocr_enabled}. Result: {result['reason']}"
            })

            # Ensure the original body, extracted text, and metadata are returned
            result["modified_body"] = body 
            result["extracted_text"] = extracted_text
            result["file_metadata"] = metadata
            result["ocr_enabled"] = ocr_enabled
            return result
        else:
            return {
                "is_injection": False,
                "reason": "File processing skipped: No valid file_path provided",
                "pii_found": [],
                "modified_body": body
            }

    messages = body.get("messages", [])
    combined_text = ""

    if not isinstance(messages, list):
        return {
            "is_injection": False,
            "reason": "Invalid messages format",
            "pii_found": [],
            "modified_body": body
        }

    for m in messages:
        if isinstance(m, dict) and m.get("role") == "user":
            combined_text += m.get("content", "") + " "

    # --- Translation Layer ---
    # Convert to English before analysis to catch hidden injections
    translation_info = translate_prompt(combined_text)
    eval_text = translation_info["translated_text"] if translation_info["applied"] else combined_text

    # --- ML-based detection (always runs for scoring) ---
    ml_result = analyze_prompt(eval_text)
    ml_score = ml_result.get("scores", {}).get("attack", 0.0)

    # --- Rule-based detection (returns match count) ---
    rule_matched, rule_reason, match_count = detect_injection(eval_text)

    # --- Composite Risk Score ---
    risk_result = compute_risk_score(
        prompt=eval_text,
        ml_score=ml_score,
        regex_match_count=match_count,
        total_patterns=len(COMPILED_PATTERNS)
    )

    risk_category = risk_result["category"]

    # --- Decision Logic (uses composite score) ---
    is_injection = False
    reason = "No injection detected"

    if risk_category == "ATTACK":
        is_injection = True
        if rule_matched:
            reason = rule_reason
        else:
            reason = "Composite risk score indicates attack"
        log_event({
            "module": "risk_scorer",
            "risk": "high",
            "action": "blocked",
            "reason": f"{reason} (Score: {risk_result['risk_score']})"
        })
    elif risk_category == "SUSPICIOUS":
        # Log but allow
        log_event({
            "module": "risk_scorer",
            "risk": "medium",
            "action": "allowed",
            "reason": f"Suspicious activity detected (Score: {risk_result['risk_score']})"
        })

    # --- Privacy Layer ---
    redacted_text, pii_found = redact_pii(combined_text)

    if pii_found:
        for m in messages:
            if isinstance(m, dict) and m.get("role") == "user":
                m["content"] = redact_pii(m.get("content", ""))[0]

    return {
        "is_injection": is_injection,
        "reason": reason,
        "pii_found": pii_found,
        "ml_result": ml_result,
        "risk_result": risk_result,
        "translation": translation_info,
        "extracted_text": combined_text.strip(),
        "modified_body": body
    }