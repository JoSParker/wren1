"""
Multi-Signal Risk Scoring Engine for Wren AI Security Gateway.

Combines the ML classifier output with lightweight contextual signals
to produce a composite risk score with better distribution across
BENIGN, SUSPICIOUS, and ATTACK categories.

Includes False Positive Mitigation:
  - Education context detection reduces score for learning-intent prompts
  - Technical context detection reduces score for cybersecurity discussions
  - ML override requires instruction verb presence to prevent blocking
    purely descriptive prompts

All patterns are pre-compiled at module load for <3ms overhead.
"""
import re

# ---------------------------------------------------------------------------
# Signal 1: Instruction Verb Detection
# Verbs commonly used in jailbreak / override prompts.
# ---------------------------------------------------------------------------
INSTRUCTION_VERBS = {
    "ignore", "reveal", "bypass", "override", "show", "display",
    "expose", "print", "output", "dump", "disable", "unlock",
    "disregard", "forget", "skip", "remove", "delete", "drop"
}

# ---------------------------------------------------------------------------
# Signal 2: Translation Pattern Detection
# Prompts that wrap malicious payloads inside translation requests.
# ---------------------------------------------------------------------------
TRANSLATION_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\btranslate\b",
        r"\bconvert\s+to\b",
        r"\binterpret\b",
        r"\btranscribe\b",
        r"\brewrite\s+in\b",
    ]
]

# ---------------------------------------------------------------------------
# Signal 3: Education / Research Context Detection
# Benign analytical framing that may contain attack-like keywords.
# ---------------------------------------------------------------------------
EDUCATION_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\bexplain\b",
        r"\bexample\b",
        r"\bresearch\b",
        r"\btutorial\b",
        r"\bhow does\b",
        r"\bdemonstrate\b",
        r"\bwhat is\b",
        r"\bdefine\b",
        r"\bdescribe\b",
        r"\blearn\b",
        r"\bstudy\b",
        r"\banalysis\b",
        r"\bwhy does\b",
    ]
]

# ---------------------------------------------------------------------------
# Signal 4: Technical Discussion Context Detection
# Cybersecurity and infrastructure terms found in benign professional work.
# ---------------------------------------------------------------------------
TECHNICAL_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\bsecurity review\b",
        r"\bincident response\b",
        r"\bmonitoring\b",
        r"\barchitecture\b",
        r"\btelemetry\b",
        r"\bauthentication\b",
        r"\binfrastructure\b",
        r"\bdetection\b",
        r"\bprotocol\b",
        r"\breview\b",
        r"\baudit\b",
        r"\bvulnerability\b",
        r"\bcompliance\b",
    ]
]

# ---------------------------------------------------------------------------
# Weights (tuned for false-positive mitigation)
# ---------------------------------------------------------------------------
W_ML          =  0.60
W_REGEX       =  0.20
W_INSTRUCTION =  0.10
W_TRANSLATION =  0.10
W_EDUCATION   = -0.20
W_TECHNICAL   = -0.10

# ---------------------------------------------------------------------------
# Thresholds (widened SUSPICIOUS band for better distribution)
# ---------------------------------------------------------------------------
ATTACK_THRESHOLD     = 0.65
SUSPICIOUS_THRESHOLD = 0.30
ML_OVERRIDE          = 0.90   # Force ATTACK only if instruction verbs present


def compute_risk_score(prompt: str, ml_score: float, regex_match_count: int,
                       total_patterns: int) -> dict:
    """
    Compute a composite risk score from multiple lightweight signals.

    Args:
        prompt:             The raw user prompt text.
        ml_score:           Attack probability from DistilBERT (0.0-1.0).
        regex_match_count:  Number of regex injection patterns that matched.
        total_patterns:     Total number of regex patterns checked.

    Returns:
        dict with keys: risk_score, category, signals
    """
    lower_prompt = prompt.lower()
    words = lower_prompt.split()
    word_count = max(len(words), 1)  # avoid division by zero

    # --- Signal: Regex Match Density ---
    regex_density = regex_match_count / max(total_patterns, 1)

    # --- Signal: Instruction Verb Density ---
    instruction_count = sum(1 for w in words if w in INSTRUCTION_VERBS)
    instruction_density = instruction_count / word_count

    # --- Signal: Translation Flag ---
    translation_flag = 1.0 if any(p.search(lower_prompt) for p in TRANSLATION_PATTERNS) else 0.0

    # --- Signal: Education Context Flag ---
    education_flag = 1.0 if any(p.search(lower_prompt) for p in EDUCATION_PATTERNS) else 0.0

    # --- Signal: Technical Discussion Context Flag ---
    technical_flag = 1.0 if any(p.search(lower_prompt) for p in TECHNICAL_PATTERNS) else 0.0

    # --- Weighted Aggregation ---
    # If education context coexists with instruction verbs,
    # halve the education discount (the prompt discusses attacks in context)
    effective_edu_weight = W_EDUCATION
    if education_flag and instruction_density > 0:
        effective_edu_weight = W_EDUCATION * 0.5

    raw_score = (
        W_ML          * ml_score
      + W_REGEX       * regex_density
      + W_INSTRUCTION * instruction_density
      + W_TRANSLATION * translation_flag
      + effective_edu_weight * education_flag
      + W_TECHNICAL   * technical_flag
    )

    # Clamp to [0.0, 1.0]
    risk_score = round(max(0.0, min(1.0, raw_score)), 4)

    # --- Classification ---
    # ML override: only force ATTACK if there are actual instruction verbs
    if ml_score > ML_OVERRIDE and instruction_density > 0:
        category = "ATTACK"
    elif risk_score >= ATTACK_THRESHOLD:
        category = "ATTACK"
    elif risk_score >= SUSPICIOUS_THRESHOLD:
        category = "SUSPICIOUS"
    else:
        category = "BENIGN"

    return {
        "risk_score": risk_score,
        "category": category,
        "signals": {
            "ml_score": round(ml_score, 4),
            "regex_density": round(regex_density, 4),
            "instruction_density": round(instruction_density, 4),
            "translation_flag": int(translation_flag),
            "education_context_flag": int(education_flag),
            "technical_context_flag": int(technical_flag),
        }
    }
